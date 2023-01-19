// Copyright 2022-2023, Offchain Labs, Inc.
// For license information, see https://github.com/nitro/blob/master/LICENSE

package precompiles

type ArbWasm struct {
	Address addr // 0x71
}

// Compile a wasm program with the latest instrumentation
func (con ArbWasm) CompileProgram(c ctx, evm mech, program addr) (uint32, error) {
	// TODO: pay for gas by some compilation pricing formula
	return c.State.Programs().CompileProgram(evm.StateDB, program)
}

// Calls a wasm program
// TODO: move into geth
func (con ArbWasm) CallProgram(c ctx, evm mech, program addr, calldata []byte) ([]byte, error) {
	// TODO: require some intrinsic amount of gas
	programs := c.State.Programs()

	// give all gas to the program
	return programs.CallProgram(evm.StateDB, program, calldata, &c.gasLeft)
}

// Gets the latest stylus version
func (con ArbWasm) StylusVersion(c ctx, evm mech) (uint32, error) {
	return c.State.Programs().StylusVersion()
}

// Gets the price (in evm gas basis points) of wasm gas
func (con ArbWasm) WasmGasPrice(c ctx, evm mech) (uint64, error) {
	bips, err := c.State.Programs().WasmGasPrice()
	return bips.Uint64(), err
}

// Gets the wasm stack size limit
func (con ArbWasm) WasmMaxDepth(c ctx, evm mech) (uint32, error) {
	return c.State.Programs().WasmMaxDepth()
}

// Gets the cost (in wasm gas) of starting a stylus hostio call
func (con ArbWasm) WasmHostioCost(c ctx, evm mech) (uint64, error) {
	return c.State.Programs().WasmHostioCost()
}
