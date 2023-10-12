package core

import (
	"bytes"
	"crypto/ecdsa"
	"math/big"
	"testing"

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
	"github.com/ethereum/go-ethereum/trie"
)

var (
	deployKey     *ecdsa.PrivateKey
	deployAddress common.Address
	deploySigner  types.Signer
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
	}
	return &conf
}

type testEnv struct {
	DB    ethdb.Database
	Chain *BlockChain

	EonKey []byte
}

func newPreDeployTestEnv() *testEnv {
	db := rawdb.NewMemoryDatabase()
	engine := ethash.NewFaker()
	vmConfig := vm.Config{}
	chainConfig := makeTestChainConfig()

	alloc := make(GenesisAlloc)
	oneEth, ok := new(big.Int).SetString("1000000000000000000", 10)
	if !ok {
		panic("invalid int")
	}
	alloc[deployAddress] = GenesisAccount{Balance: oneEth}
	genesis := &Genesis{
		Config:   chainConfig,
		GasLimit: 100000000,
		Alloc:    alloc,
	}
	triedb := trie.NewDatabase(db, trie.HashDefaults)
	_, err := genesis.Commit(db, triedb)
	if err != nil {
		panic(err)
	}

	chain, err := NewBlockChain(db, nil, genesis, nil, engine, vmConfig, nil, nil)
	if err != nil {
		panic(err)
	}

	return &testEnv{
		DB:    db,
		Chain: chain,

		EonKey: []byte("key"),
	}
}

func newPreKeyperConfigTestEnv() *testEnv {
	env := newPreDeployTestEnv()
	env.DeployContracts()
	return env
}

func newPreKeyBroadcastTestEnv() *testEnv {
	env := newPreKeyperConfigTestEnv()
	env.ScheduleKeyperSet()
	env.ExtendChain(10, nil)
	return env
}

func (env *testEnv) GetStateDB() *state.StateDB {
	statedb, err := state.New(env.Chain.CurrentHeader().Root, state.NewDatabase(env.DB), nil)
	if err != nil {
		panic(err)
	}
	return statedb
}

func (env *testEnv) GetEVM(txCtx vm.TxContext, vmConfig vm.Config) *vm.EVM {
	author := &common.Address{}
	blockCtx := NewEVMBlockContext(env.Chain.CurrentHeader(), env.Chain, author, env.Chain.chainConfig, env.GetStateDB())
	vmenv := vm.NewEVM(blockCtx, txCtx, env.GetStateDB(), env.Chain.Config(), vmConfig)
	return vmenv
}

func (env *testEnv) GetSigner() types.Signer {
	return types.MakeSigner(
		env.Chain.Config(),
		env.Chain.CurrentBlock().Number,
		env.Chain.CurrentBlock().Time,
	)
}

func (env *testEnv) ExtendChain(n int, gen func(int, *BlockGen)) ([]*types.Block, []types.Receipts) {
	head := env.Chain.GetBlockByHash(env.Chain.CurrentBlock().Hash())
	blocks, receipts := GenerateChain(env.Chain.Config(), head, env.Chain.Engine(), env.DB, n, gen)
	_, err := env.Chain.InsertChain(blocks)
	if err != nil {
		panic(err)
	}
	return blocks, receipts
}

// SendTransaction signs and sends the given transaction. All fields but data and to are
// automatically populated with reasonable values.
func (env *testEnv) SendTransaction(unsignedTx *types.DynamicFeeTx, key *ecdsa.PrivateKey) *types.Receipt {
	signer := env.GetSigner()
	statedb := env.GetStateDB()

	unsignedTx.ChainID = env.Chain.Config().ChainID
	unsignedTx.Nonce = statedb.GetNonce(deployAddress)
	unsignedTx.GasTipCap = new(big.Int)
	unsignedTx.GasFeeCap = big.NewInt(1_000_000_000)
	unsignedTx.Gas = 1_000_000
	unsignedTx.Value = new(big.Int)

	tx, err := types.SignTx(types.NewTx(unsignedTx), signer, deployKey)
	if err != nil {
		panic(err)
	}
	_, receipts := env.ExtendChain(1, func(n int, g *BlockGen) {
		g.AddTx(tx)
	})
	if len(receipts) != 1 {
		panic("expected one set of receipts")
	}
	if len(receipts[0]) != 1 {
		panic("expected single receipt")
	}
	receipt := receipts[0][0]
	if receipt.Status == types.ReceiptStatusFailed {
		panic("transaction")
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
		panic(err)
	}
	_, receipts := env.ExtendChain(1, func(n int, g *BlockGen) {
		g.AddTx(tx)
	})
	if len(receipts) != 1 {
		panic("expected one set of receipts")
	}
	if len(receipts[0]) != 1 {
		panic("expected single receipt")
	}
	receipt := receipts[0][0]
	if receipt.Status == types.ReceiptStatusFailed {
		panic("deployment failed")
	}
	return receipt
}

func (env *testEnv) DeployContracts() {
	deployKeyperSetManagerTx := &types.DynamicFeeTx{
		To:   nil,
		Data: shutter.GetKeyperSetManagerDeployData(),
	}
	keyperSetManagerReceipt := env.SendTransaction(deployKeyperSetManagerTx, deployKey)

	deployKeyBroadcastContractTx := &types.DynamicFeeTx{
		To:   nil,
		Data: shutter.GetKeyBroadcastContractDeployData(&keyperSetManagerReceipt.ContractAddress),
	}
	keyBroadcastContractReceipt := env.SendTransaction(deployKeyBroadcastContractTx, deployKey)

	if keyperSetManagerReceipt.ContractAddress != env.Chain.Config().Shutter.KeyperSetManagerAddress {
		panic("keyper set manager deployed at unexpected address")
	}
	if keyBroadcastContractReceipt.ContractAddress != env.Chain.Config().Shutter.KeyBroadcastContractAddress {
		panic("key broadcast contract deployed at unexpected address")
	}
}

func (env *testEnv) ScheduleKeyperSet() {
	deployTx := &types.DynamicFeeTx{
		To:   nil,
		Data: shutter.GetKeyperSetDeployData(),
	}
	keyperSetReceipt := env.SendTransaction(deployTx, deployKey)

	setBroadcasterData, err := shutter.KeyperSetABI.Pack("setKeyBroadcaster", deployAddress)
	if err != nil {
		panic(err)
	}
	setBroadcasterTx := &types.DynamicFeeTx{
		To:   &keyperSetReceipt.ContractAddress,
		Data: setBroadcasterData,
	}
	env.SendTransaction(setBroadcasterTx, deployKey)

	finalizeData, err := shutter.KeyperSetABI.Pack("setFinalized")
	if err != nil {
		panic(err)
	}
	finalizeTx := &types.DynamicFeeTx{
		To:   &keyperSetReceipt.ContractAddress,
		Data: finalizeData,
	}
	env.SendTransaction(finalizeTx, deployKey)

	activationBlockNumber := env.Chain.CurrentBlock().Number.Uint64() + 10
	addKeyperSetData, err := shutter.KeyperSetManagerABI.Pack(
		"addKeyperSet",
		activationBlockNumber,
		keyperSetReceipt.ContractAddress,
	)
	if err != nil {
		panic(err)
	}
	addKeyperSetTx := &types.DynamicFeeTx{
		To:   &env.Chain.Config().Shutter.KeyperSetManagerAddress,
		Data: addKeyperSetData,
	}
	env.SendTransaction(addKeyperSetTx, deployKey)
}

func (env *testEnv) BroadcastEonKey() {
	data, err := shutter.KeyBroadcastContractABI.Pack("broadcastEonKey", uint64(0), env.EonKey)
	if err != nil {
		panic(err)
	}
	tx := &types.DynamicFeeTx{
		To:   &env.Chain.chainConfig.Shutter.KeyBroadcastContractAddress,
		Data: data,
	}
	env.SendTransaction(tx, deployKey)
}

func TestAreShutterContractsDeployed(t *testing.T) {
	env := newPreDeployTestEnv()
	deployed := AreShutterContractsDeployed(
		env.Chain.Config(),
		env.GetEVM(vm.TxContext{}, vm.Config{}),
	)
	if deployed {
		t.Fail()
	}

	env.DeployContracts()
	deployed = AreShutterContractsDeployed(
		env.Chain.Config(),
		env.GetEVM(vm.TxContext{}, vm.Config{}),
	)
	if !deployed {
		t.Fail()
	}
}

func TestGetCurrentEon(t *testing.T) {
	env := newPreKeyperConfigTestEnv()
	_, err := GetCurrentEon(env.Chain.Config(), env.GetEVM(vm.TxContext{}, vm.Config{}))
	if err == nil {
		t.Errorf("no error before keyper config")
	}

	env.ScheduleKeyperSet()
	_, err = GetCurrentEon(env.Chain.Config(), env.GetEVM(vm.TxContext{}, vm.Config{}))
	if err == nil {
		t.Errorf("no error before keyper set is activated")
	}

	env.ExtendChain(10, nil)
	eon, err := GetCurrentEon(env.Chain.Config(), env.GetEVM(vm.TxContext{}, vm.Config{}))
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

	eon, err = GetCurrentEon(env.Chain.Config(), env.GetEVM(vm.TxContext{}, vm.Config{}))
	if err != nil {
		t.Errorf("failed to get eon")
	}
	if eon != 1 {
		t.Errorf("unexpected eon index")
	}
}

func TestGetCurrentEonKey(t *testing.T) {
	env := newPreKeyBroadcastTestEnv()
	key, err := GetCurrentEonKey(env.Chain.Config(), env.GetEVM(vm.TxContext{}, vm.Config{}))
	if err != nil {
		t.Errorf("failed to get eon key")
	}
	if len(key) != 0 {
		t.Errorf("eon key before broadcast is not empty")
	}

	env.BroadcastEonKey()
	key, err = GetCurrentEonKey(env.Chain.Config(), env.GetEVM(vm.TxContext{}, vm.Config{}))
	if err != nil {
		t.Errorf("failed to get eon key")
	}
	if !bytes.Equal(key, env.EonKey) {
		t.Errorf("got unexpected eon key")
	}
}

func TestIsShutterEnabled(t *testing.T) {
	env := newPreDeployTestEnv()
	check := func(shouldBeEnabled bool) {
		enabled, err := IsShutterEnabled(env.Chain.Config(), env.GetEVM(vm.TxContext{}, vm.Config{}))
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
}
