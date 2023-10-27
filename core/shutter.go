package core

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/shutter"
	"github.com/ethereum/go-ethereum/core/vm"
)

var ShutterSystemAddress = common.HexToAddress("0x8000000000000000000000000000000000000001")

var ErrNoActiveKeyperSet = errors.New("no active keyper set at current block number")

// AreShutterContractsDeployed checks if the system contracts required for
// Shutter to operate are deployed.
func AreShutterContractsDeployed(evm *vm.EVM) bool {
	addresses := []common.Address{
		evm.ChainConfig().Shutter.KeyperSetManagerAddress,
		evm.ChainConfig().Shutter.KeyBroadcastContractAddress,
	}
	for _, address := range addresses {
		code := evm.StateDB.GetCode(address)
		if len(code) == 0 {
			return false
		}
	}
	return true
}

// GetCurrentEon returns the eon at the current block number.
func GetCurrentEon(evm *vm.EVM) (uint64, error) {
	block := evm.Context.BlockNumber.Uint64()
	data, err := shutter.KeyperSetManagerABI.Pack("getKeyperSetIndexByBlock", block)
	if err != nil {
		return 0, err
	}
	sender := vm.AccountRef(common.Address{})
	ret, _, err := evm.Call(
		sender,
		evm.ChainConfig().Shutter.KeyperSetManagerAddress,
		data,
		100_000_000,
		new(big.Int),
	)
	if err == vm.ErrExecutionReverted {
		// The only reason this call may revert if there is no keyper set
		// configured for the given block.
		return 0, ErrNoActiveKeyperSet
	}
	if err != nil {
		return 0, err
	}

	unpacked, err := shutter.KeyperSetManagerABI.Unpack("getKeyperSetIndexByBlock", ret)
	if err != nil {
		return 0, err
	}
	if len(unpacked) != 1 {
		return 0, fmt.Errorf("getKeyperSetIndexByBlock did not return single value")
	}
	eon, ok := unpacked[0].(uint64)
	if !ok {
		return 0, fmt.Errorf("getKeyperSetIndexByBlock returned value of unexpected type")
	}
	return eon, nil
}

// GetCurrentEonKey returns the current eon key or an empty byte slice if it has not been
// broadcasted yet.
func GetCurrentEonKey(evm *vm.EVM) ([]byte, error) {
	eon, err := GetCurrentEon(evm)
	if err != nil {
		return []byte{}, err
	}

	data, err := shutter.KeyBroadcastContractABI.Pack("getEonKey", eon)
	if err != nil {
		return []byte{}, err
	}
	sender := vm.AccountRef(common.Address{})
	ret, _, err := evm.Call(
		sender,
		evm.ChainConfig().Shutter.KeyBroadcastContractAddress,
		data,
		100_000_000,
		new(big.Int),
	)
	if err == vm.ErrExecutionReverted {
		return []byte{}, nil
	}
	if err != nil {
		return []byte{}, err
	}

	unpacked, err := shutter.KeyBroadcastContractABI.Unpack("getEonKey", ret)
	if err != nil {
		return []byte{}, err
	}
	if len(unpacked) != 1 {
		return []byte{}, fmt.Errorf("key broadcast contract returned unexpected number of values")
	}
	key, ok := unpacked[0].([]byte)
	if !ok {
		return []byte{}, fmt.Errorf("key broadcast contract returned unexpected type")
	}
	return key, nil
}

func IsShutterKeyperSetManagerPaused(evm *vm.EVM) (bool, error) {
	data, err := shutter.KeyperSetManagerABI.Pack("paused")
	if err != nil {
		return false, err
	}
	sender := vm.AccountRef(common.Address{})
	ret, _, err := evm.Call(
		sender,
		evm.ChainConfig().Shutter.KeyperSetManagerAddress,
		data,
		100_000_000,
		new(big.Int),
	)
	if err != nil {
		return false, err
	}

	unpacked, err := shutter.KeyperSetManagerABI.Unpack("paused", ret)
	if err != nil {
		return false, err
	}
	if len(unpacked) != 1 {
		return false, fmt.Errorf("keyper set manager returned unexpected number of values")
	}
	paused, ok := unpacked[0].(bool)
	if !ok {
		return false, fmt.Errorf("keyper set manager returned unexpected type")
	}
	return paused, nil
}

// IsShutterEnabled checks if Shutter is enabled at the given block number.
// Shutter is enabled iff
// - Shutter is enabled in the chain config,
// - the required contracts have been deployed,
// - a keyper set has been configured and is active, and
// - an eon key has been broadcast for the current eon.
// We don't check if the key is valid because this is in general not possible (an invalid key is
// functionally equivalent to a valid one without a corresponding private key).
func IsShutterEnabled(evm *vm.EVM) (bool, error) {
	rules := evm.ChainConfig().Rules(evm.Context.BlockNumber, true, evm.Context.Time)
	if !rules.IsShutter {
		return false, nil
	}

	deployed := AreShutterContractsDeployed(evm)
	if !deployed {
		return false, nil
	}

	eonKey, err := GetCurrentEonKey(evm)
	if err == ErrNoActiveKeyperSet {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if len(eonKey) == 0 {
		return false, nil
	}

	return true, nil
}

func ApplyRevealMessage(evm *vm.EVM, msg *Message, gp *GasPool) (*ExecutionResult, error) {
	key := msg.Data
	if len(key) == 0 {
		return ApplyPauseMessage(evm, gp)
	}

	return &ExecutionResult{}, nil
}

func ApplyPauseMessage(evm *vm.EVM, gp *GasPool) (*ExecutionResult, error) {
	data, err := shutter.KeyperSetManagerABI.Pack("pause")
	if err != nil {
		return nil, err
	}
	sender := vm.AccountRef(ShutterSystemAddress)
	gasLimit := uint64(100_000_000)
	ret, leftOverGas, err := evm.Call(
		sender,
		evm.ChainConfig().Shutter.KeyperSetManagerAddress,
		data,
		gasLimit,
		new(big.Int),
	)
	if err != nil {
		return nil, err
	}

	return &ExecutionResult{
		UsedGas:    gasLimit - leftOverGas,
		Err:        nil,
		ReturnData: ret,
	}, nil
}
