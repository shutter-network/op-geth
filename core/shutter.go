package core

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/shutter"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/shutter-network/shutter/shlib/shcrypto"
)

var ShutterSystemAddress = common.HexToAddress("0x8000000000000000000000000000000000000001")

var (
	ErrNoActiveKeyperSet        = errors.New("no active keyper set at current block number")
	ErrInvalidDecryptionKey     = errors.New("the decryption key in the reveal message is invalid")
	ErrInvalidEonKey            = errors.New("the eon key in the key broadcast contract is invalid")
	ErrUndecryptableTransaction = errors.New("could not decrypt transaction")
)

type EncryptedTransaction struct {
	EncryptedTransaction []byte
	Sender               common.Address
	GasLimit             uint64
	CumulativeGasLimit   uint64
}

type DecryptedTransaction struct {
	To    common.Address
	Data  []byte
	Value *big.Int
}

func (tx *EncryptedTransaction) GetDecryptedTransaction(decryptionKey *shcrypto.EpochSecretKey) (*DecryptedTransaction, error) {
	msg := new(shcrypto.EncryptedMessage)
	err := msg.Unmarshal(tx.EncryptedTransaction)
	if err != nil {
		return nil, err
	}

	decryptedBytes, err := msg.Decrypt(decryptionKey)
	if err != nil {
		return nil, err
	}

	if len(decryptedBytes) == 0 {
		return nil, fmt.Errorf("decrypted tx is empty")
	}
	if decryptedBytes[0] != 0 {
		return nil, fmt.Errorf("decrypted tx has invalid version prefix %d", decryptedBytes[0])
	}

	decryptedTx := new(DecryptedTransaction)
	err = rlp.DecodeBytes(decryptedBytes[1:], decryptedTx)
	if err != nil {
		return nil, err
	}
	return decryptedTx, nil
}

type RevealRecord struct {
	DecryptionKey      []byte
	TransactionRecords []RevealedTransactionRecord
}

type RevealedTransactionRecord struct {
	Status            uint64
	CumulativeGasUsed uint64
	CumulativeLogs    uint64
}

const (
	RevealedTransactionRecordStatusSuccess          = 100
	RevealedTransactionRecordStatusDecryptionFailed = 101
	RevealedTransactionRecordStatusExecutionFailed  = 102
)

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
// - the keyper set manager is not paused
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

	paused, err := IsShutterKeyperSetManagerPaused(evm)
	if err != nil {
		return false, err
	}
	if paused {
		return false, nil
	}

	return true, nil
}

func GetSubmittedEncryptedTransactions(evm *vm.EVM, blockNumber uint64) ([]EncryptedTransaction, error) {
	data, err := shutter.InboxABI.Pack("getTransactions", blockNumber)
	if err != nil {
		return []EncryptedTransaction{}, err
	}
	sender := vm.AccountRef(common.Address{})
	ret, _, err := evm.Call(
		sender,
		evm.ChainConfig().Shutter.InboxAddress,
		data,
		100_000_000,
		new(big.Int),
	)
	if err != nil {
		return []EncryptedTransaction{}, err
	}

	unpacked, err := shutter.InboxABI.Unpack("getTransactions", ret)
	if err != nil {
		return []EncryptedTransaction{}, err
	}
	if len(unpacked) != 1 {
		return []EncryptedTransaction{}, fmt.Errorf("inbox returned unexpected number of values")
	}

	anonTxs, ok := unpacked[0].([]struct {
		EncryptedTransaction []uint8        "json:\"encryptedTransaction\""
		Sender               common.Address "json:\"sender\""
		GasLimit             uint64         "json:\"gasLimit\""
		CumulativeGasLimit   uint64         "json:\"cumulativeGasLimit\""
	})
	if !ok {
		return []EncryptedTransaction{}, fmt.Errorf("inbox returned unexpected type")
	}

	txs := []EncryptedTransaction{}
	for _, anonTx := range anonTxs {
		tx := EncryptedTransaction{
			EncryptedTransaction: anonTx.EncryptedTransaction,
			Sender:               anonTx.Sender,
			GasLimit:             anonTx.GasLimit,
			CumulativeGasLimit:   anonTx.CumulativeGasLimit,
		}
		txs = append(txs, tx)
	}
	return txs, nil
}

func ClearSubmittedEncryptedTransactions(evm *vm.EVM) error {
	data, err := shutter.InboxABI.Pack("clear")
	if err != nil {
		return err
	}
	sender := vm.AccountRef(ShutterSystemAddress)
	ret, _, err := evm.Call(
		sender,
		evm.ChainConfig().Shutter.InboxAddress,
		data,
		100_000_000,
		new(big.Int),
	)
	if err != nil {
		return err
	}
	if len(ret) > 0 {
		return fmt.Errorf("inbox returned value unexpectedly")
	}
	return nil
}

func Uint64ToIdentityPreimage(n uint64) []byte {
	b := new(big.Int).SetUint64(n)
	return b.Bytes()
}

// verifyDecryptionKey checks that the given key is correct for the given block number and eon
// key. It does so by encrypting a test message pseudo-randomly derived from the previous block
// hash.
func verifyDecryptionKey(
	decryptionKey *shcrypto.EpochSecretKey,
	eonKey *shcrypto.EonPublicKey,
	blockNumber uint64,
	prevBlockHash common.Hash,
) (bool, error) {
	identity := Uint64ToIdentityPreimage(blockNumber)

	sigmaPreimage := append(prevBlockHash[:], []byte("sigma")...)
	sigmaBytes := crypto.Keccak256(sigmaPreimage)
	var sigma shcrypto.Block
	copy(sigma[:], sigmaBytes)

	messagePreimage := append(prevBlockHash[:], []byte("message")...)
	message := crypto.Keccak256(messagePreimage)
	return shcrypto.VerifyEpochSecretKeyDeterministic(
		decryptionKey,
		eonKey,
		identity,
		sigma,
		message,
	)
}

func ApplyRevealMessage(evm *vm.EVM, statedb *state.StateDB, msg *Message, tx *types.Transaction, gp *GasPool) (*ExecutionResult, error) {
	var (
		err    error
		result *ExecutionResult
	)

	decryptionKeyBytes := msg.Data
	revealRecord := RevealRecord{
		DecryptionKey:      decryptionKeyBytes,
		TransactionRecords: []RevealedTransactionRecord{},
	}
	if len(decryptionKeyBytes) == 0 {
		result, err = ApplyPauseMessage(evm, gp)
		if err != nil {
			return nil, err
		}
	} else {
		decryptionKey := new(shcrypto.EpochSecretKey)
		err = decryptionKey.Unmarshal(decryptionKeyBytes)
		if err != nil {
			return nil, ErrInvalidDecryptionKey
		}

		eonKeyBytes, err := GetCurrentEonKey(evm)
		if err != nil {
			return nil, err
		}
		eonKey := new(shcrypto.EonPublicKey)
		err = eonKey.Unmarshal(eonKeyBytes)
		if err != nil {
			// The sequencer is not responsible for an invalid eon key, but they are
			// supposed to sidestep this error by pausing Shutter.
			return nil, ErrInvalidEonKey
		}

		blockNumber := evm.Context.BlockNumber.Uint64()
		prevBlockHash := evm.Context.GetHash(blockNumber - 1)
		ok, err := verifyDecryptionKey(decryptionKey, eonKey, blockNumber, prevBlockHash)
		if err != nil {
			return nil, err
		}
		// FIXME: we fail here
		if !ok {
			return nil, ErrInvalidDecryptionKey
		}

		encryptedTxs, err := GetSubmittedEncryptedTransactions(evm, blockNumber)
		if err != nil {
			return nil, err
		}
		cumulativeGasUsed := uint64(0)
		for _, encryptedTx := range encryptedTxs {
			result, err := ApplyEncryptedTransaction(evm, gp, &encryptedTx, decryptionKey)
			if result != nil {
				cumulativeGasUsed += result.UsedGas
			}
			logs := statedb.GetLogs(tx.Hash(), 0, common.Hash{})
			cumulativeLogs := uint64(len(logs))
			record := RevealedTransactionRecord{
				CumulativeGasUsed: cumulativeGasUsed,
				CumulativeLogs:    cumulativeLogs,
			}
			if err != nil {
				if err == ErrUndecryptableTransaction {
					record.Status = RevealedTransactionRecordStatusDecryptionFailed
				} else {
					record.Status = RevealedTransactionRecordStatusExecutionFailed
				}
			} else {
				record.Status = RevealedTransactionRecordStatusSuccess
			}
			revealRecord.TransactionRecords = append(revealRecord.TransactionRecords, record)
		}

		result = &ExecutionResult{
			UsedGas:    cumulativeGasUsed,
			Err:        nil,
			ReturnData: []byte{},
		}
	}

	revealLogData, err := rlp.EncodeToBytes(revealRecord)
	if err != nil {
		return nil, err
	}
	revealLog := &types.Log{
		Address: ShutterSystemAddress,
		Topics:  []common.Hash{},
		Data:    revealLogData,
	}
	statedb.AddLog(revealLog)

	isShutterEnabled, err := IsShutterEnabled(evm)
	if err != nil {
		return nil, err
	}
	if isShutterEnabled {
		if err := ClearSubmittedEncryptedTransactions(evm); err != nil {
			return nil, err
		}
	}

	return result, nil
}

func ApplyEncryptedTransaction(
	evm *vm.EVM,
	gp *GasPool,
	encryptedTx *EncryptedTransaction,
	decryptionKey *shcrypto.EpochSecretKey,
) (*ExecutionResult, error) {
	decryptedTx, err := encryptedTx.GetDecryptedTransaction(decryptionKey)
	if err != nil {
		return nil, ErrUndecryptableTransaction
	}

	nonce := evm.StateDB.GetNonce(encryptedTx.Sender)
	baseFee := evm.Context.BaseFee
	msg := Message{
		To:                &decryptedTx.To,
		From:              encryptedTx.Sender,
		Nonce:             nonce,
		Value:             decryptedTx.Value,
		GasLimit:          encryptedTx.GasLimit,
		GasPrice:          baseFee,
		GasFeeCap:         baseFee,
		GasTipCap:         common.Big0,
		Data:              decryptedTx.Data,
		AccessList:        types.AccessList{},
		BlobGasFeeCap:     common.Big0,
		BlobHashes:        nil,
		SkipAccountChecks: false,
		IsSystemTx:        false,
		IsDepositTx:       false,
		Mint:              nil,
		RollupDataGas:     types.RollupGasData{},
	}

	// The fee has already been paid when the transaction was submitted to the inbox contract.
	// However, the EVM requires at least the base fee to be paid during transaction
	// execution. Therefore, we have to mint them some ETH for free. Anything that is not used
	// will be burned later. Note that the account will be unable to spend it because all will
	// be used to pre-pay for gas.
	feeAllocation := new(big.Int).Mul(
		new(big.Int).SetUint64(msg.GasLimit),
		msg.GasPrice,
	)
	evm.StateDB.AddBalance(encryptedTx.Sender, feeAllocation)

	result, err := ApplyMessage(evm, &msg, gp)

	var usedGas uint64
	if result != nil {
		usedGas = result.UsedGas
	} else {
		usedGas = 0
	}
	unusedGas := msg.GasLimit - usedGas
	unusedFeeAllocation := new(big.Int).Mul(
		new(big.Int).SetUint64(unusedGas),
		msg.GasPrice,
	)
	evm.StateDB.SubBalance(encryptedTx.Sender, unusedFeeAllocation)

	return result, err
}

func ApplyPauseMessage(evm *vm.EVM, gp *GasPool) (*ExecutionResult, error) {
	data, err := shutter.KeyperSetManagerABI.Pack("pause")
	if err != nil {
		return nil, err
	}
	sender := vm.AccountRef(ShutterSystemAddress)
	gasLimit := uint64(100_000_000)
	ret, _, err := evm.Call(
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
		UsedGas:    0,
		Err:        nil,
		ReturnData: ret,
	}, nil
}

func ShutterBlockPostProcess(evm *vm.EVM) error {
	isShutterEnabled, err := IsShutterEnabled(evm)
	if err != nil {
		return err
	}
	if isShutterEnabled {
		if err := ClearSubmittedEncryptedTransactions(evm); err != nil {
			return err
		}
	}
	return nil
}
