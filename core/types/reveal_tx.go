// Copyright 2021 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package types

import (
	"bytes"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
)

const RevealTxType = 0x50

type RevealTx struct {
	Key []byte
}

// copy creates a deep copy of the transaction data and initializes all fields.
func (tx *RevealTx) copy() TxData {
	cpy := &RevealTx{
		Key: common.CopyBytes(tx.Key),
	}
	return cpy
}

// accessors for innerTx.
func (tx *RevealTx) txType() byte           { return RevealTxType }
func (tx *RevealTx) chainID() *big.Int      { return common.Big0 }
func (tx *RevealTx) accessList() AccessList { return nil }
func (tx *RevealTx) data() []byte           { return tx.Key }
func (tx *RevealTx) gas() uint64            { return 0 }
func (tx *RevealTx) gasFeeCap() *big.Int    { return new(big.Int) }
func (tx *RevealTx) gasTipCap() *big.Int    { return new(big.Int) }
func (tx *RevealTx) gasPrice() *big.Int     { return new(big.Int) }
func (tx *RevealTx) value() *big.Int        { return new(big.Int) }
func (tx *RevealTx) nonce() uint64          { return 0 }
func (tx *RevealTx) to() *common.Address    { return &common.Address{} }
func (tx *RevealTx) isSystemTx() bool       { return true }

func (tx *RevealTx) effectiveGasPrice(dst *big.Int, baseFee *big.Int) *big.Int {
	return dst.Set(new(big.Int))
}

func (tx *RevealTx) effectiveNonce() *uint64 { return nil }

func (tx *RevealTx) rawSignatureValues() (v, r, s *big.Int) {
	return common.Big0, common.Big0, common.Big0
}

func (tx *RevealTx) setSignatureValues(chainID, v, r, s *big.Int) {
	// this is a noop for reveal transactions
}

func (tx *RevealTx) encode(b *bytes.Buffer) error {
	return rlp.Encode(b, tx)
}

func (tx *RevealTx) decode(input []byte) error {
	return rlp.DecodeBytes(input, tx)
}
