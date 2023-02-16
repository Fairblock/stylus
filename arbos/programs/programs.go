// Copyright 2022-2023, Offchain Labs, Inc.
// For license information, see https://github.com/nitro/blob/master/LICENSE

package programs

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/offchainlabs/nitro/arbcompress"
	"github.com/offchainlabs/nitro/arbos/storage"
	"github.com/offchainlabs/nitro/util/arbmath"
)

const MaxWasmSize = 64 * 1024

type Programs struct {
	backingStorage  *storage.Storage
	machineVersions *storage.Storage
	wasmGasPrice    storage.StorageBackedUBips
	wasmMaxDepth    storage.StorageBackedUint32
	wasmHostioCost  storage.StorageBackedUint64
	version         storage.StorageBackedUint32
}

var machineVersionsKey = []byte{0}

const (
	versionOffset uint64 = iota
	wasmGasPriceOffset
	wasmMaxDepthOffset
	wasmHostioCostOffset
)

func Initialize(sto *storage.Storage) {
	wasmGasPrice := sto.OpenStorageBackedBips(wasmGasPriceOffset)
	wasmMaxDepth := sto.OpenStorageBackedUint32(wasmMaxDepthOffset)
	wasmHostioCost := sto.OpenStorageBackedUint32(wasmHostioCostOffset)
	version := sto.OpenStorageBackedUint64(versionOffset)
	_ = wasmGasPrice.Set(0)
	_ = wasmMaxDepth.Set(math.MaxUint32)
	_ = wasmHostioCost.Set(0)
	_ = version.Set(1)
}

func Open(sto *storage.Storage) *Programs {
	return &Programs{
		backingStorage:  sto,
		machineVersions: sto.OpenSubStorage(machineVersionsKey),
		wasmGasPrice:    sto.OpenStorageBackedUBips(wasmGasPriceOffset),
		wasmMaxDepth:    sto.OpenStorageBackedUint32(wasmMaxDepthOffset),
		wasmHostioCost:  sto.OpenStorageBackedUint64(wasmHostioCostOffset),
		version:         sto.OpenStorageBackedUint32(versionOffset),
	}
}

func (p Programs) StylusVersion() (uint32, error) {
	return p.version.Get()
}

func (p Programs) WasmGasPrice() (arbmath.UBips, error) {
	return p.wasmGasPrice.Get()
}

func (p Programs) SetWasmGasPrice(price arbmath.UBips) error {
	return p.wasmGasPrice.Set(price)
}

func (p Programs) WasmMaxDepth() (uint32, error) {
	return p.wasmMaxDepth.Get()
}

func (p Programs) SetWasmMaxDepth(depth uint32) error {
	return p.wasmMaxDepth.Set(depth)
}

func (p Programs) WasmHostioCost() (uint64, error) {
	return p.wasmHostioCost.Get()
}

func (p Programs) SetWasmHostioCost(cost uint64) error {
	return p.wasmHostioCost.Set(cost)
}

func (p Programs) CompileProgram(statedb vm.StateDB, program common.Address) (uint32, error) {
	version, err := p.StylusVersion()
	if err != nil {
		return 0, err
	}
	latest, err := p.machineVersions.GetUint32(program.Hash())
	if err != nil {
		return 0, err
	}
	if latest >= version {
		return 0, errors.New("program is current")
	}

	wasm, err := getWasm(statedb, program)
	if err != nil {
		return 0, err
	}
	if err := compileUserWasm(statedb, program, wasm, version); err != nil {
		return 0, err
	}
	return version, p.machineVersions.SetUint32(program.Hash(), version)
}

func (p Programs) CallProgram(
	statedb vm.StateDB,
	program common.Address,
	calldata []byte,
	gas *uint64,
	readOnly bool,
	txContext vm.TxContext,
	blockContext vm.BlockContext,
) ([]byte, error) {
	stylusVersion, err := p.StylusVersion()
	if err != nil {
		return nil, err
	}
	programVersion, err := p.machineVersions.GetUint32(program.Hash())
	if err != nil {
		return nil, err
	}
	if programVersion == 0 {
		return nil, errors.New("program not compiled")
	}
	if programVersion != stylusVersion {
		return nil, errors.New("program out of date, please recompile")
	}
	params, err := p.goParams(programVersion)
	if err != nil {
		return nil, err
	}
	evmContext := p.goEvmContext(readOnly, txContext, blockContext)
	return callUserWasm(statedb, program, calldata, gas, params, evmContext)
}

func getWasm(statedb vm.StateDB, program common.Address) ([]byte, error) {
	prefixedWasm := statedb.GetCode(program)
	if prefixedWasm == nil {
		return nil, fmt.Errorf("missing wasm at address %v", program)
	}
	wasm, err := state.StripStylusPrefix(prefixedWasm)
	if err != nil {
		return nil, err
	}
	return arbcompress.Decompress(wasm, MaxWasmSize)
}

type goParams struct {
	version      uint32
	maxDepth     uint32
	wasmGasPrice uint64
	hostioCost   uint64
}

func (p Programs) goParams(version uint32) (*goParams, error) {
	maxDepth, err := p.WasmMaxDepth()
	if err != nil {
		return nil, err
	}
	wasmGasPrice, err := p.WasmGasPrice()
	if err != nil {
		return nil, err
	}
	hostioCost, err := p.WasmHostioCost()
	if err != nil {
		return nil, err
	}
	config := &goParams{
		version:      version,
		maxDepth:     maxDepth,
		wasmGasPrice: wasmGasPrice.Uint64(),
		hostioCost:   hostioCost,
	}
	return config, nil
}

type userStatus uint8

type goEvmContext struct {
	readOnly   bool
	origin     common.Address
	gasPrice   *big.Int
	coinbase   common.Address
	gasLimit   uint64
	time       *big.Int
	difficulty *big.Int
	baseFee    *big.Int
	random     *common.Hash
}

func (p Programs) goEvmContext(readOnly bool, txContext vm.TxContext, blockContext vm.BlockContext) *goEvmContext {
	return &goEvmContext{
		readOnly:   readOnly,
		origin:     txContext.Origin,
		gasPrice:   txContext.GasPrice,
		coinbase:   blockContext.Coinbase,
		gasLimit:   blockContext.GasLimit,
		time:       blockContext.Time,
		difficulty: blockContext.Difficulty,
		baseFee:    blockContext.BaseFee,
		random:     blockContext.Random,
	}
}

const (
	userSuccess userStatus = iota
	userRevert
	userFailure
	userOutOfGas
	userOutOfStack
)

func (status userStatus) output(data []byte) ([]byte, error) {
	switch status {
	case userSuccess:
		return data, nil
	case userRevert:
		return data, errors.New("program reverted")
	case userFailure:
		return nil, errors.New(string(data))
	case userOutOfGas:
		return nil, vm.ErrOutOfGas
	case userOutOfStack:
		return nil, vm.ErrDepth
	default:
		return nil, errors.New("unknown status kind")
	}
}
