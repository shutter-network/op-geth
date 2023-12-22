package core

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/shutter"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/shutter-network/shutter/shlib/shcrypto"
)

var (
	deployKey     *ecdsa.PrivateKey
	deployAddress common.Address
	deploySigner  types.Signer

	testKeyGen *shcrypto.TestKeyGen
)

func init() {
	deployKeyHex := "9c647b8b7c4e7c3490668fb6c11473619db80c93704c70893d3813af4090c39c"
	deployKey, _ = crypto.HexToECDSA(deployKeyHex)
	deployAddress = crypto.PubkeyToAddress(deployKey.PublicKey) // 658bdf435d810c91414ec09147daa6db62406379
}

func makeTestChainConfig() *params.ChainConfig {
	conf := *params.AllCliqueProtocolChanges
	conf.Clique = nil
	conf.TerminalTotalDifficultyPassed = true
	conf.BedrockBlock = big.NewInt(0)
	conf.Optimism = &params.OptimismConfig{EIP1559Elasticity: 50, EIP1559Denominator: 10}
	conf.Shutter = &params.ShutterConfig{
		KeyperSetManagerAddress:     common.HexToAddress("0x99466ED2E37B892A2Ee3E9CD55a98b68f5735db2"),
		KeyBroadcastContractAddress: common.HexToAddress("0x946755051097d22a9383B896Fe4817bAFC867a89"),
		InboxAddress:                common.HexToAddress("0xDCdf1e30e221CeB2ED862994FDF18b52588094Da"),
	}
	return &conf
}

type testEnv struct {
	DB    ethdb.Database
	Chain *BlockChain

	TestKeyGen *shcrypto.TestKeyGen

	t *testing.T
}

func newPreDeployTestEnv(t *testing.T) *testEnv {
	db := rawdb.NewMemoryDatabase()
	engine := ethash.NewFaker()
	vmConfig := vm.Config{}
	chainConfig := makeTestChainConfig()

	alloc := make(GenesisAlloc)
	tenEth, ok := new(big.Int).SetString("10000000000000000000", 10)
	if !ok {
		t.Fatalf("invalid genesis allocation amount")
	}
	alloc[deployAddress] = GenesisAccount{Balance: tenEth}
	genesis := &Genesis{
		Config:   chainConfig,
		GasLimit: 100000000,
		Alloc:    alloc,
	}
	triedb := trie.NewDatabase(db, trie.HashDefaults)
	_, err := genesis.Commit(db, triedb)
	if err != nil {
		t.Fatalf("failed to commit genesis state: %v", err)
	}

	chain, err := NewBlockChain(db, nil, genesis, nil, engine, vmConfig, nil, nil)
	if err != nil {
		t.Fatalf("failed to create blockchain: %v", err)
	}

	testKeyGen, err := shcrypto.NewTestKeyGen()
	if err != nil {
		t.Fatalf("failed to create testkeygen: %v", err)
	}

	return &testEnv{
		DB:         db,
		Chain:      chain,
		TestKeyGen: testKeyGen,
		t:          t,
	}
}

func newPreKeyperConfigTestEnv(t *testing.T) *testEnv {
	env := newPreDeployTestEnv(t)
	env.DeployContracts()
	return env
}

func newPreKeyBroadcastTestEnv(t *testing.T) *testEnv {
	env := newPreKeyperConfigTestEnv(t)
	env.ScheduleKeyperSet()
	env.ExtendChain(10, nil)
	return env
}

func newTestEnv(t *testing.T) *testEnv {
	env := newPreKeyBroadcastTestEnv(t)
	env.BroadcastEonKey()
	return env
}

func (env *testEnv) GetStateDB() *state.StateDB {
	statedb, err := state.New(env.Chain.CurrentHeader().Root, state.NewDatabase(env.DB), nil)
	if err != nil {
		env.t.Fatalf("failed to create statedb: %v", err)
	}
	return statedb
}

func (env *testEnv) GetEVM() *vm.EVM {
	author := &common.Address{}
	blockCtx := NewEVMBlockContext(env.Chain.CurrentHeader(), env.Chain, author, env.Chain.chainConfig, env.GetStateDB())
	vmenv := vm.NewEVM(blockCtx, vm.TxContext{}, env.GetStateDB(), env.Chain.Config(), vm.Config{})
	return vmenv
}

func (env *testEnv) GetSigner() types.Signer {
	return types.MakeSigner(
		env.Chain.Config(),
		env.Chain.CurrentBlock().Number,
		env.Chain.CurrentBlock().Time,
	)
}

func (env *testEnv) ComputeDecryptionKey(blockNumber uint64) *shcrypto.EpochSecretKey {
	identityPreimage := ComputeIdentityPreimage(blockNumber)
	epochID := shcrypto.ComputeEpochID(identityPreimage)
	key, err := env.TestKeyGen.ComputeEpochSecretKey(epochID)
	if err != nil {
		env.t.Fatalf("failed to compute decryption key: %v", err)
	}
	return key
}

func (env *testEnv) ExtendChain(n int, gen func(int, *BlockGen)) ([]*types.Block, []types.Receipts) {
	head := env.Chain.GetBlockByHash(env.Chain.CurrentBlock().Hash())
	if gen == nil {
		gen = func(i int, g *BlockGen) {
			evm := env.GetEVM()
			shutterEnabled, err := IsShutterEnabled(evm)
			if err != nil {
				env.t.Fatalf("failed to check if shutter is enabled: %v", err)
			}
			if shutterEnabled {
				key := env.ComputeDecryptionKey(g.header.Number.Uint64())
				g.AddTx(types.NewTx(&types.RevealTx{Key: key.Marshal()}))
			}
		}
	}
	blocks, receipts := GenerateChain(env.Chain.Config(), head, env.Chain.Engine(), env.DB, n, gen)
	_, err := env.Chain.InsertChain(blocks)
	if err != nil {
		env.t.Fatalf("failed to insert blocks into chain: %v", err)
	}
	return blocks, receipts
}

// SendTransaction signs and sends the given transaction. All fields but data and to are
// automatically populated with reasonable values.
func (env *testEnv) SendTransaction(unsignedTx *types.DynamicFeeTx, key *ecdsa.PrivateKey, shutterEnabled bool) *types.Receipt {
	signer := env.GetSigner()
	statedb := env.GetStateDB()

	if unsignedTx.ChainID == nil {
		unsignedTx.ChainID = env.Chain.Config().ChainID
	}
	if unsignedTx.Nonce == 0 {
		unsignedTx.Nonce = statedb.GetNonce(deployAddress)
	}
	if unsignedTx.GasTipCap == nil {
		unsignedTx.GasTipCap = new(big.Int)
	}
	if unsignedTx.GasFeeCap == nil {
		unsignedTx.GasFeeCap = big.NewInt(1_000_000_000)
	}
	if unsignedTx.Gas == 0 {
		unsignedTx.Gas = 10_000_000
	}
	if unsignedTx.Value == nil {
		unsignedTx.Value = new(big.Int)
	}

	tx, err := types.SignTx(types.NewTx(unsignedTx), signer, deployKey)
	if err != nil {
		env.t.Fatalf("failed to sign tx: %v", err)
	}
	_, receipts := env.ExtendChain(1, func(n int, g *BlockGen) {
		if shutterEnabled {
			key := env.ComputeDecryptionKey(g.header.Number.Uint64())
			g.AddTx(types.NewTx(&types.RevealTx{Key: key.Marshal()}))
		}
		g.AddTx(tx)
	})
	if len(receipts) != 1 {
		env.t.Fatalf("expected one set of receipts, got %d", len(receipts))
	}
	numExpectedReceipts := 1
	if shutterEnabled {
		numExpectedReceipts += 1
	}
	if len(receipts[0]) != numExpectedReceipts {
		env.t.Fatalf("expected %d receipts, got %d", numExpectedReceipts, len(receipts[0]))
	}

	receipt := receipts[0][numExpectedReceipts-1]
	if receipt.Status == types.ReceiptStatusFailed {
		env.t.Fatalf("transaction failed: %+v", receipt)
	}
	return receipt
}

func (env *testEnv) DeployContract(data []byte) *types.Receipt {
	signer := env.GetSigner()
	statedb := env.GetStateDB()
	unsignedTx := &types.DynamicFeeTx{
		ChainID:   env.Chain.Config().ChainID,
		Nonce:     statedb.GetNonce(deployAddress),
		GasTipCap: new(big.Int),
		GasFeeCap: big.NewInt(1_000_000_000),
		Gas:       1_000_000,
		To:        nil,
		Value:     new(big.Int),
		Data:      data,
	}
	tx, err := types.SignTx(types.NewTx(unsignedTx), signer, deployKey)
	if err != nil {
		env.t.Fatalf("failed to sign deploy transaction: %v", err)
	}
	_, receipts := env.ExtendChain(1, func(n int, g *BlockGen) {
		g.AddTx(tx)
	})
	if len(receipts) != 1 {
		env.t.Fatalf("expected one set of receipts, got %d", len(receipts))
	}
	if len(receipts[0]) != 1 {
		env.t.Fatalf("expected single receipt, got %d", len(receipts[0]))
	}
	receipt := receipts[0][0]
	if receipt.Status == types.ReceiptStatusFailed {
		env.t.Fatalf("deployment transaction failed")
	}
	return receipt
}

func (env *testEnv) DeployContracts() {
	deployKeyperSetManagerTx := &types.DynamicFeeTx{
		To:   nil,
		Data: shutter.GetKeyperSetManagerDeployData(&deployAddress, &deployAddress),
	}
	keyperSetManagerReceipt := env.SendTransaction(deployKeyperSetManagerTx, deployKey, false)

	deployKeyBroadcastContractTx := &types.DynamicFeeTx{
		To:   nil,
		Data: shutter.GetKeyBroadcastContractDeployData(&keyperSetManagerReceipt.ContractAddress),
	}
	keyBroadcastContractReceipt := env.SendTransaction(deployKeyBroadcastContractTx, deployKey, false)

	deployInboxTx := &types.DynamicFeeTx{
		To:   nil,
		Data: shutter.GetInboxDeployData(10_000_000, &deployAddress, &deployAddress),
	}
	inboxReceipt := env.SendTransaction(deployInboxTx, deployKey, false)

	if keyperSetManagerReceipt.ContractAddress != env.Chain.Config().Shutter.KeyperSetManagerAddress {
		env.t.Fatalf("keyper set manager deployed at unexpected address")
	}
	if keyBroadcastContractReceipt.ContractAddress != env.Chain.Config().Shutter.KeyBroadcastContractAddress {
		env.t.Fatalf("key broadcast contract deployed at unexpected address")
	}
	if inboxReceipt.ContractAddress != env.Chain.Config().Shutter.InboxAddress {
		env.t.Fatalf("inbox deployed at unexpected address")
	}

	env.GrantRole(&shutter.KeyperSetManagerABI, env.Chain.Config().Shutter.KeyperSetManagerAddress, "PAUSER_ROLE", ShutterSystemAddress)
	env.GrantRole(&shutter.InboxABI, env.Chain.Config().Shutter.InboxAddress, "SEQUENCER_ROLE", ShutterSystemAddress)
}

func (env *testEnv) ScheduleKeyperSet() {
	deployTx := &types.DynamicFeeTx{
		To:   nil,
		Data: shutter.GetKeyperSetDeployData(),
	}
	keyperSetReceipt := env.SendTransaction(deployTx, deployKey, false)

	setBroadcasterData, err := shutter.KeyperSetABI.Pack("setKeyBroadcaster", deployAddress)
	if err != nil {
		env.t.Fatalf("failed to encode setKeyBroadcaster data: %v", err)
	}
	setBroadcasterTx := &types.DynamicFeeTx{
		To:   &keyperSetReceipt.ContractAddress,
		Data: setBroadcasterData,
	}
	env.SendTransaction(setBroadcasterTx, deployKey, false)

	finalizeData, err := shutter.KeyperSetABI.Pack("setFinalized")
	if err != nil {
		env.t.Fatalf("failed to encode setFinalized data: %v", err)
	}
	finalizeTx := &types.DynamicFeeTx{
		To:   &keyperSetReceipt.ContractAddress,
		Data: finalizeData,
	}
	env.SendTransaction(finalizeTx, deployKey, false)

	activationBlockNumber := env.Chain.CurrentBlock().Number.Uint64() + 10
	addKeyperSetData, err := shutter.KeyperSetManagerABI.Pack(
		"addKeyperSet",
		activationBlockNumber,
		keyperSetReceipt.ContractAddress,
	)
	if err != nil {
		env.t.Fatalf("failed to encode addKeyperSet data: %v", err)
	}
	addKeyperSetTx := &types.DynamicFeeTx{
		To:   &env.Chain.Config().Shutter.KeyperSetManagerAddress,
		Data: addKeyperSetData,
	}
	env.SendTransaction(addKeyperSetTx, deployKey, false)
}

func (env *testEnv) BroadcastEonKey() {
	data, err := shutter.KeyBroadcastContractABI.Pack("broadcastEonKey", uint64(0), env.TestKeyGen.EonPublicKey.Marshal())
	if err != nil {
		env.t.Fatalf("failed to encode broadcastEonKey data: %v", err)
	}
	tx := &types.DynamicFeeTx{
		To:   &env.Chain.chainConfig.Shutter.KeyBroadcastContractAddress,
		Data: data,
	}
	env.SendTransaction(tx, deployKey, false)
}

func (env *testEnv) PauseShutter() {
	env.ExtendChain(1, func(n int, g *BlockGen) {
		g.AddTx(types.NewTx(&types.RevealTx{}))
	})
}

func (env *testEnv) SubmitEncryptedTransaction(block uint64, encryptedTransaction []byte, gasLimit uint64, excessFeeRecipient common.Address) {
	data, err := shutter.InboxABI.Pack("submitEncryptedTransaction", block, encryptedTransaction, gasLimit, deployAddress)
	if err != nil {
		env.t.Fatalf("failed to submit encrypted tx: %v", err)
	}
	pointOneEth, ok := new(big.Int).SetString("100000000000000000", 10)
	if !ok {
		env.t.Fatalf("invalid decimal integer")
	}
	tx := &types.DynamicFeeTx{
		To:    &env.Chain.chainConfig.Shutter.InboxAddress,
		Data:  data,
		Value: pointOneEth,
	}
	env.SendTransaction(tx, deployKey, true)
}

func (env *testEnv) GrantRole(contractABI *abi.ABI, contractAddress common.Address, role string, address common.Address) {
	roleHash, err := getRole(env.GetEVM(), contractABI, contractAddress, role)
	if err != nil {
		env.t.Fatalf("failed to get role hash: %v", err)
	}
	grantRoleData, err := contractABI.Pack("grantRole", roleHash, address)
	if err != nil {
		env.t.Fatalf("failed to encode grantRole data: %v", err)
	}
	grantRoleTx := &types.DynamicFeeTx{
		To:   &contractAddress,
		Data: grantRoleData,
	}
	env.SendTransaction(grantRoleTx, deployKey, false)
}

func getRole(evm *vm.EVM, contractABI *abi.ABI, contractAddress common.Address, role string) (common.Hash, error) {
	data, err := contractABI.Pack(role)
	if err != nil {
		return common.Hash{}, err
	}
	sender := vm.AccountRef(common.Address{})
	ret, _, err := evm.Call(
		sender,
		contractAddress,
		data,
		100_000_000,
		new(big.Int),
	)
	if err != nil {
		return common.Hash{}, err
	}

	unpacked, err := contractABI.Unpack(role, ret)
	if err != nil {
		return common.Hash{}, err
	}
	if len(unpacked) != 1 {
		return common.Hash{}, fmt.Errorf("contract returned unexpected number of values")
	}
	roleHash, ok := unpacked[0].([32]byte)
	if !ok {
		return common.Hash{}, fmt.Errorf("contract returned unexpected type")
	}
	return common.BytesToHash(roleHash[:]), nil
}

func TestAreShutterContractsDeployed(t *testing.T) {
	env := newPreDeployTestEnv(t)
	deployed := AreShutterContractsDeployed(env.GetEVM())
	if deployed {
		t.Fail()
	}

	env.DeployContracts()
	deployed = AreShutterContractsDeployed(env.GetEVM())
	if !deployed {
		t.Fail()
	}
}

func TestGetCurrentEon(t *testing.T) {
	env := newPreKeyperConfigTestEnv(t)
	_, err := GetCurrentEon(env.GetEVM())
	if err == nil {
		t.Errorf("no error before keyper config")
	}

	env.ScheduleKeyperSet()
	_, err = GetCurrentEon(env.GetEVM())
	if err == nil {
		t.Errorf("no error before keyper set is activated")
	}

	env.ExtendChain(10, nil)
	eon, err := GetCurrentEon(env.GetEVM())
	if err != nil {
		t.Errorf("failed to get eon")
	}
	if eon != 0 {
		t.Errorf("unexpected eon index")
	}

	env.ScheduleKeyperSet()
	env.ExtendChain(5, nil)
	env.ScheduleKeyperSet()
	env.ExtendChain(5, nil)

	eon, err = GetCurrentEon(env.GetEVM())
	if err != nil {
		t.Errorf("failed to get eon")
	}
	if eon != 1 {
		t.Errorf("unexpected eon index")
	}
}

func TestGetCurrentEonKey(t *testing.T) {
	env := newPreKeyBroadcastTestEnv(t)
	key, err := GetCurrentEonKey(env.GetEVM())
	if err != nil {
		t.Errorf("failed to get eon key")
	}
	if len(key) != 0 {
		t.Errorf("eon key before broadcast is not empty")
	}

	env.BroadcastEonKey()
	key, err = GetCurrentEonKey(env.GetEVM())
	if err != nil {
		t.Errorf("failed to get eon key")
	}
	if !bytes.Equal(key, env.TestKeyGen.EonPublicKey.Marshal()) {
		t.Errorf("got unexpected eon key")
	}
}

func TestIsKeyperSetManagerPaused(t *testing.T) {
	env := newTestEnv(t)
	paused, err := IsShutterKeyperSetManagerPaused(env.GetEVM())
	if err != nil {
		t.Errorf("failed to check if keyper set manager is paused: %v", err)
	}
	if paused {
		t.Errorf("keyper set manager is initially paused")
	}

	env.PauseShutter()

	paused, err = IsShutterKeyperSetManagerPaused(env.GetEVM())
	if err != nil {
		t.Errorf("failed to check if keyper set manager is paused: %v", err)
	}
	if !paused {
		t.Errorf("keyper set manager is not paused")
	}
}

func TestIsShutterEnabled(t *testing.T) {
	env := newPreDeployTestEnv(t)
	check := func(shouldBeEnabled bool) {
		enabled, err := IsShutterEnabled(env.GetEVM())
		if err != nil {
			t.Errorf("failed to check if shutter is enabled: %v", err)
		}
		if enabled && !shouldBeEnabled {
			t.Errorf("should not be enabled, but is")
		}
		if !enabled && shouldBeEnabled {
			t.Errorf("should be enabled, but isn't")
		}
	}

	check(false)
	env.DeployContracts()
	check(false)
	env.ScheduleKeyperSet()
	env.ExtendChain(10, nil)
	check(false)
	env.BroadcastEonKey()
	check(true)
	env.PauseShutter()
	check(false)
}

func TestGetSubmittedEncryptedTransactions(t *testing.T) {
	env := newTestEnv(t)
	txs := [][]byte{
		[]byte("tx1"),
		[]byte("tx2"),
		[]byte("tx3"),
	}
	gasLimit := uint64(100_000)
	block := env.Chain.CurrentHeader().Number.Uint64() + 100
	for _, tx := range txs {
		env.SubmitEncryptedTransaction(block, tx, gasLimit, common.Address{})
	}

	txsReceived, err := GetSubmittedEncryptedTransactions(env.GetEVM(), block)
	if err != nil {
		t.Fatalf("failed to get inbox transactions: %v", err)
	}
	if len(txsReceived) != len(txs) {
		t.Fatalf("expected %v txs, got %d", len(txs), len(txsReceived))
	}
	for i := 0; i < len(txs); i++ {
		if !bytes.Equal(txsReceived[i].EncryptedTransaction, txs[i]) {
			t.Fatalf("submitted tx with encrypted data %v, received %v", txs[i], txsReceived[i].EncryptedTransaction)
		}
		if txsReceived[i].GasLimit != gasLimit {
			t.Fatalf("submitted tx with gas limit %v, received %v", gasLimit, txsReceived[i].GasLimit)
		}
		if txsReceived[i].CumulativeGasLimit != uint64(i+1)*gasLimit {
			t.Fatalf("unexpected cumulative gas limit")
		}
	}
}

func TestSubmittedEncryptedTransactionsAreCleared(t *testing.T) {
	env := newTestEnv(t)
	txs := [][]byte{
		[]byte("tx1"),
		[]byte("tx2"),
		[]byte("tx3"),
	}
	gasLimit := uint64(100_000)
	dBlock := uint64(10)
	block := env.Chain.CurrentHeader().Number.Uint64() + dBlock
	for _, tx := range txs {
		env.SubmitEncryptedTransaction(block, tx, gasLimit, common.Address{})
	}
	txsSubmitted, err := GetSubmittedEncryptedTransactions(env.GetEVM(), block)
	if err != nil {
		t.Fatalf("failed to get inbox transactions: %v", err)
	}
	if len(txsSubmitted) == 0 {
		t.Fatalf("no transactions were submitted")
	}

	env.ExtendChain(int(dBlock), nil)

	txsReceived, err := GetSubmittedEncryptedTransactions(env.GetEVM(), block)
	if err != nil {
		t.Fatalf("failed to get inbox transactions: %v", err)
	}
	if len(txsReceived) != 0 {
		t.Fatalf("transactions didn't get cleared")
	}
}

func TestBlocksStartWithRevealTx(t *testing.T) {
	env := newTestEnv(t)
	processor := NewStateProcessor(env.Chain.Config(), env.Chain, env.Chain.Engine())
	head := env.Chain.GetBlockByHash(env.Chain.CurrentBlock().Hash())

	blocks, _ := GenerateChain(env.Chain.Config(), head, env.Chain.Engine(), env.DB, 1, nil)
	_, _, _, err := processor.Process(blocks[0], env.GetStateDB(), vm.Config{})
	if err != ErrNoRevealTx {
		t.Errorf("expected no reveal tx error, got %v", err)
	}

	blocks, _ = GenerateChain(env.Chain.Config(), head, env.Chain.Engine(), env.DB, 1, func(n int, g *BlockGen) {
		key := env.ComputeDecryptionKey(g.header.Number.Uint64())
		revealTx := &types.RevealTx{Key: key.Marshal()}
		g.AddTx(types.NewTx(revealTx))
		g.AddTx(types.NewTx(revealTx))
	})
	_, _, _, err = processor.Process(blocks[0], env.GetStateDB(), vm.Config{})
	if err != ErrUnexpectedRevealTx {
		t.Errorf("expected unexpected reveal tx error, got %v", err)
	}

	blocks, _ = GenerateChain(env.Chain.Config(), head, env.Chain.Engine(), env.DB, 1, func(n int, g *BlockGen) {
		key := env.ComputeDecryptionKey(g.header.Number.Uint64())
		revealTx := &types.RevealTx{Key: key.Marshal()}
		g.AddTx(types.NewTx(revealTx))
	})
	_, _, _, err = processor.Process(blocks[0], env.GetStateDB(), vm.Config{})
	if err != nil {
		t.Errorf("processing block failed: %v", err)
	}
}

func TestEmptyRevealPausesShutter(t *testing.T) {
	env := newTestEnv(t)

	pausedBefore, err := IsShutterKeyperSetManagerPaused(env.GetEVM())
	if err != nil {
		t.Errorf("failed to check if shutter is paused: %v", err)
	}
	if pausedBefore {
		t.Errorf("shutter is paused")
	}

	env.PauseShutter()

	pausedAfter, err := IsShutterKeyperSetManagerPaused(env.GetEVM())
	if err != nil {
		t.Errorf("failed to check if shutter is paused: %v", err)
	}
	if !pausedAfter {
		t.Errorf("shutter is not paused after empty reveal tx")
	}
}

func TestTransactionDecryption(t *testing.T) {
	env := newTestEnv(t)
	decryptedTx := DecryptedTransaction{
		To:    deployAddress,
		Data:  []byte("data"),
		Value: big.NewInt(5),
	}
	decryptedTxBytesWithoutPrefix, err := rlp.EncodeToBytes(decryptedTx)
	if err != nil {
		t.Fatalf("failed to RLP encode tx: %v", err)
	}
	decryptedTxBytes := append([]byte{0}, decryptedTxBytesWithoutPrefix...)
	blockNumber := uint64(0)
	identityPreimage := ComputeIdentityPreimage(blockNumber)
	identity := shcrypto.ComputeEpochID(identityPreimage)

	sigma, err := shcrypto.RandomSigma(rand.Reader)
	if err != nil {
		t.Fatalf("failed to get random sigma: %v", err)
	}
	encryptedTxBytes := shcrypto.Encrypt(decryptedTxBytes, env.TestKeyGen.EonPublicKey, identity, sigma).Marshal()
	encryptedTx := EncryptedTransaction{
		EncryptedTransaction: encryptedTxBytes,
	}
	decryptedTx2, err := encryptedTx.GetDecryptedTransaction(env.ComputeDecryptionKey(blockNumber))
	if err != nil {
		t.Fatalf("failed to decrypt tx: %v", err)
	}
	if !bytes.Equal(decryptedTx2.To.Bytes(), decryptedTx.To.Bytes()) {
		t.Errorf("unexpected receiver after decryption")
	}
	if !bytes.Equal(decryptedTx2.Data, decryptedTx.Data) {
		t.Errorf("unexpected data after decryption")
	}
	if decryptedTx2.Value.Cmp(decryptedTx.Value) != 0 {
		t.Errorf("unexpected value after decryption")
	}
}

func TestBlocksValidateDecryptionKey(t *testing.T) {
	env := newTestEnv(t)
	head := env.Chain.GetBlockByHash(env.Chain.CurrentBlock().Hash())
	nextBlockNumber := head.Number().Uint64() + 1

	invalidKeys := [][]byte{
		[]byte("key"),
		env.ComputeDecryptionKey(nextBlockNumber - 1).Marshal(),
		env.ComputeDecryptionKey(nextBlockNumber + 1).Marshal(),
	}
	for _, key := range invalidKeys {
		func() {
			defer func() {
				err := recover()
				fmt.Println("recovered error:", err)
				if err == nil {
					t.Errorf("expected invalid decryption key error")
				}
			}()

			GenerateChain(env.Chain.Config(), head, env.Chain.Engine(), env.DB, 1, func(n int, g *BlockGen) {
				revealTx := &types.RevealTx{Key: key}
				g.AddTx(types.NewTx(revealTx))
			})
		}()
	}
}

func TestInvalidEncryptedTransaction(t *testing.T) {
	env := newTestEnv(t)
	block := env.Chain.CurrentHeader().Number.Uint64() + 2
	env.SubmitEncryptedTransaction(block, []byte("invalid"), 100_000, deployAddress)
	env.ExtendChain(1, nil)
	// TODO: check receipt
}

func TestEncryptedTransactionExecution(t *testing.T) {
	env := newTestEnv(t)
	block := env.Chain.CurrentHeader().Number.Uint64() + 2
	to := common.BigToAddress(common.Big1)
	balanceBefore := env.GetEVM().StateDB.GetBalance(to)

	decryptedTx := DecryptedTransaction{
		To:    to,
		Data:  []byte{},
		Value: big.NewInt(1),
	}
	decryptedTxBytesWithoutPrefix, err := rlp.EncodeToBytes(decryptedTx)
	if err != nil {
		t.Fatalf("failed to RLP encode tx: %v", err)
	}
	decryptedTxBytes := append([]byte{0}, decryptedTxBytesWithoutPrefix...)

	identityPreimage := ComputeIdentityPreimage(block)
	identity := shcrypto.ComputeEpochID(identityPreimage)
	sigma, err := shcrypto.RandomSigma(rand.Reader)
	if err != nil {
		t.Fatalf("failed to get random sigma: %v", err)
	}
	encryptedTx := shcrypto.Encrypt(decryptedTxBytes, env.TestKeyGen.EonPublicKey, identity, sigma).Marshal()
	env.SubmitEncryptedTransaction(block, encryptedTx, 100_000, deployAddress)

	env.ExtendChain(1, nil)

	balanceAfter := env.GetEVM().StateDB.GetBalance(to)
	if new(big.Int).Add(balanceBefore, decryptedTx.Value).Cmp(balanceAfter) != 0 {
		t.Errorf("balance not updated")
	}
}
