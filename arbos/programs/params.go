// Copyright 2022-2024, Offchain Labs, Inc.
// For license information, see https://github.com/OffchainLabs/nitro/blob/master/LICENSE

package programs

import (
	"errors"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/offchainlabs/nitro/arbos/storage"
	am "github.com/offchainlabs/nitro/util/arbmath"
)

const MaxWasmSize = 128 * 1024      // max decompressed wasm size (programs are also bounded by compressed size)
const initialStackDepth = 4 * 65536 // 4 page stack.
const InitialFreePages = 2          // 2 pages come free (per tx).
const InitialPageGas = 1000         // linear cost per allocation.
const initialPageRamp = 620674314   // targets 8MB costing 32 million gas, minus the linear term.
const initialPageLimit = 128        // reject wasms with memories larger than 8MB.
const initialInkPrice = 10000       // 1 evm gas buys 10k ink.
const initialMinInitGas = 0         // assume pricer is correct (update in case of emergency)
const initialExpiryDays = 365       // deactivate after 1 year.
const initialKeepaliveDays = 31     // wait a month before allowing reactivation
const initialInitTableBits = 7      // cache the last 128 programs
const initialTrieTableBits = 11     // cache the hottest 1024 slots

// This struct exists to collect the many Stylus configuration parameters into a single word.
// The items here must only be modified in ArbOwner precompile methods (or in ArbOS upgrades).
type StylusParams struct {
	backingStorage *storage.Storage
	Version        uint16 // must only be changed during ArbOS upgrades
	InkPrice       uint24
	MaxStackDepth  uint32
	FreePages      uint16
	PageGas        uint16
	PageRamp       uint64
	PageLimit      uint16
	MinInitGas     uint16
	ExpiryDays     uint16
	KeepaliveDays  uint16
	InitTableBits  uint8
	TrieTableBits  uint8
}

// Provides a view of the Stylus parameters. Call Save() to persist.
// Note: this method never returns nil.
func (p Programs) Params() (*StylusParams, error) {
	sto := p.backingStorage.OpenSubStorage(paramsKey)

	// assume read is warm due to the frequency of access
	if err := sto.Burner().Burn(params.WarmStorageReadCostEIP2929); err != nil {
		return &StylusParams{}, err
	}

	// paid for the read above
	word := sto.GetFree(common.Hash{})
	data := word[:]
	take := func(count int) []byte {
		value := data[:count]
		data = data[count:]
		return value
	}

	return &StylusParams{
		backingStorage: sto,
		Version:        am.BytesToUint16(take(2)),
		InkPrice:       am.BytesToUint24(take(3)),
		MaxStackDepth:  am.BytesToUint32(take(4)),
		FreePages:      am.BytesToUint16(take(2)),
		PageGas:        am.BytesToUint16(take(2)),
		PageRamp:       am.BytesToUint(take(8)),
		PageLimit:      am.BytesToUint16(take(2)),
		MinInitGas:     am.BytesToUint16(take(2)),
		ExpiryDays:     am.BytesToUint16(take(2)),
		KeepaliveDays:  am.BytesToUint16(take(2)),
		InitTableBits:  am.BytesToUint8(take(1)),
		TrieTableBits:  am.BytesToUint8(take(1)),
	}, nil
}

// Writes the params to permanent storage.
func (p *StylusParams) Save() error {
	if p.backingStorage == nil {
		log.Error("tried to Save invalid StylusParams")
		return errors.New("invalid StylusParams")
	}

	data := am.ConcatByteSlices(
		am.Uint16ToBytes(p.Version),
		am.Uint24ToBytes(p.InkPrice),
		am.Uint32ToBytes(p.MaxStackDepth),
		am.Uint16ToBytes(p.FreePages),
		am.Uint16ToBytes(p.PageGas),
		am.UintToBytes(p.PageRamp),
		am.Uint16ToBytes(p.PageLimit),
		am.Uint16ToBytes(p.MinInitGas),
		am.Uint16ToBytes(p.ExpiryDays),
		am.Uint16ToBytes(p.KeepaliveDays),
		am.Uint8ToBytes(p.InitTableBits),
		am.Uint8ToBytes(p.TrieTableBits),
	)
	word := common.Hash{}
	copy(word[:], data) // right-pad with zeros
	return p.backingStorage.SetByUint64(0, word)
}

func initStylusParams(sto *storage.Storage) {
	params := &StylusParams{
		backingStorage: sto,
		Version:        1,
		InkPrice:       initialInkPrice,
		MaxStackDepth:  initialStackDepth,
		FreePages:      InitialFreePages,
		PageGas:        InitialPageGas,
		PageRamp:       initialPageRamp,
		PageLimit:      initialPageLimit,
		MinInitGas:     initialMinInitGas,
		ExpiryDays:     initialExpiryDays,
		KeepaliveDays:  initialKeepaliveDays,
		InitTableBits:  initialInitTableBits,
		TrieTableBits:  initialTrieTableBits,
	}
	_ = params.Save()
}
