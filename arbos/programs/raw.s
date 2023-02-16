// Copyright 2022-2023, Offchain Labs, Inc.
// For license information, see https://github.com/nitro/blob/master/LICENSE

//go:build js
// +build js

#include "textflag.h"

TEXT ·compileUserWasmRustImpl(SB), NOSPLIT, $0
  CallImport
  RET

TEXT ·callUserWasmRustImpl(SB), NOSPLIT, $0
  CallImport
  RET

TEXT ·readRustVecLenImpl(SB), NOSPLIT, $0
  CallImport
  RET

TEXT ·rustVecIntoSliceImpl(SB), NOSPLIT, $0
  CallImport
  RET

TEXT ·rustConfigImpl(SB), NOSPLIT, $0
  CallImport
  RET

TEXT ·boolToRustIntImpl(SB), NOSPLIT, $0
  CallImport
  RET

TEXT ·addressToRustBytes20Imp(SB), NOSPLIT, $0
  CallImport
  RET

TEXT ·hashToRustBytes32Impl(SB), NOSPLIT, $0
  CallImport
  RET

TEXT ·rustEvmContextImpl(SB), NOSPLIT, $0
  CallImport
  RET
