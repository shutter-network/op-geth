package core

import (
	"bytes"
	"crypto/ecdsa"
	"fmt"
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

	t *testing.T
}

func newPreDeployTestEnv(t *testing.T) *testEnv {
	db := rawdb.NewMemoryDatabase()
	engine := ethash.NewFaker()
	vmConfig := vm.Config{}
	chainConfig := makeTestChainConfig()

	alloc := make(GenesisAlloc)
	oneEth, ok := new(big.Int).SetString("1000000000000000000", 10)
	if !ok {
		t.Fatalf("invalid genesis allocation amount")
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
		t.Fatalf("failed to commit genesis state: %v", err)
	}

	chain, err := NewBlockChain(db, nil, genesis, nil, engine, vmConfig, nil, nil)
	if err != nil {
		t.Fatalf("failed to create blockchain: %v", err)
	}

	return &testEnv{
		DB:    db,
		Chain: chain,

		EonKey: []byte("key"),

		t: t,
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

func (env *testEnv) ExtendChain(n int, gen func(int, *BlockGen)) ([]*types.Block, []types.Receipts) {
	head := env.Chain.GetBlockByHash(env.Chain.CurrentBlock().Hash())
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

	unsignedTx.ChainID = env.Chain.Config().ChainID
	unsignedTx.Nonce = statedb.GetNonce(deployAddress)
	unsignedTx.GasTipCap = new(big.Int)
	unsignedTx.GasFeeCap = big.NewInt(1_000_000_000)
	unsignedTx.Gas = 1_000_000
	unsignedTx.Value = new(big.Int)

	tx, err := types.SignTx(types.NewTx(unsignedTx), signer, deployKey)
	if err != nil {
		env.t.Fatalf("failed to sign tx: %v", err)
	}
	_, receipts := env.ExtendChain(1, func(n int, g *BlockGen) {
		if shutterEnabled {
			g.AddTx(types.NewTx(&types.RevealTx{}))
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
		env.t.Fatalf("transaction failed")
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
		Data: shutter.GetKeyperSetManagerDeployData(),
	}
	keyperSetManagerReceipt := env.SendTransaction(deployKeyperSetManagerTx, deployKey, false)

	deployKeyBroadcastContractTx := &types.DynamicFeeTx{
		To:   nil,
		Data: shutter.GetKeyBroadcastContractDeployData(&keyperSetManagerReceipt.ContractAddress),
	}
	keyBroadcastContractReceipt := env.SendTransaction(deployKeyBroadcastContractTx, deployKey, false)

	if keyperSetManagerReceipt.ContractAddress != env.Chain.Config().Shutter.KeyperSetManagerAddress {
		env.t.Fatalf("keyper set manager deployed at unexpected address")
	}
	if keyBroadcastContractReceipt.ContractAddress != env.Chain.Config().Shutter.KeyBroadcastContractAddress {
		env.t.Fatalf("key broadcast contract deployed at unexpected address")
	}

	pauserRole, err := getPauserRole(env.Chain.Config(), env.GetEVM())
	if err != nil {
		env.t.Fatalf("failed to read PAUSER_ROLE: %v", err)
	}
	grantPauserRoleData, err := shutter.KeyperSetManagerABI.Pack("grantRole", pauserRole, deployAddress)
	if err != nil {
		env.t.Fatalf("failed to encode grantRole data: %v", err)
	}
	grantPauserRoleTx := &types.DynamicFeeTx{
		To:   &env.Chain.Config().Shutter.KeyperSetManagerAddress,
		Data: grantPauserRoleData,
	}
	env.SendTransaction(grantPauserRoleTx, deployKey, false)
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
	data, err := shutter.KeyBroadcastContractABI.Pack("broadcastEonKey", uint64(0), env.EonKey)
	if err != nil {
		env.t.Fatalf("failed to encode broadcastEonKey data: %v", err)
	}
	tx := &types.DynamicFeeTx{
		To:   &env.Chain.chainConfig.Shutter.KeyBroadcastContractAddress,
		Data: data,
	}
	env.SendTransaction(tx, deployKey, false)
}

func (env *testEnv) PauseKeyperSetManager() {
	data, err := shutter.KeyperSetManagerABI.Pack("pause")
	if err != nil {
		env.t.Fatalf("failed to encode pause data: %v", err)
	}
	tx := &types.DynamicFeeTx{
		To:   &env.Chain.chainConfig.Shutter.KeyperSetManagerAddress,
		Data: data,
	}
	env.SendTransaction(tx, deployKey, true)
}

func getPauserRole(config *params.ChainConfig, evm *vm.EVM) (common.Hash, error) {
	data, err := shutter.KeyperSetManagerABI.Pack("PAUSER_ROLE")
	if err != nil {
		return common.Hash{}, err
	}
	sender := vm.AccountRef(common.Address{})
	ret, _, err := evm.Call(
		sender,
		config.Shutter.KeyperSetManagerAddress,
		data,
		100_000_000,
		new(big.Int),
	)
	if err != nil {
		return common.Hash{}, err
	}

	unpacked, err := shutter.KeyperSetManagerABI.Unpack("PAUSER_ROLE", ret)
	if err != nil {
		return common.Hash{}, err
	}
	if len(unpacked) != 1 {
		return common.Hash{}, fmt.Errorf("keyper set manager returned unexpected number of values")
	}
	pauserRole, ok := unpacked[0].([32]byte)
	if !ok {
		return common.Hash{}, fmt.Errorf("keyper set manager returned unexpected type")
	}
	return common.BytesToHash(pauserRole[:]), nil
}

func TestAreShutterContractsDeployed(t *testing.T) {
	env := newPreDeployTestEnv(t)
	deployed := AreShutterContractsDeployed(
		env.Chain.Config(),
		env.GetEVM(),
	)
	if deployed {
		t.Fail()
	}

	env.DeployContracts()
	deployed = AreShutterContractsDeployed(
		env.Chain.Config(),
		env.GetEVM(),
	)
	if !deployed {
		t.Fail()
	}
}

func TestGetCurrentEon(t *testing.T) {
	env := newPreKeyperConfigTestEnv(t)
	_, err := GetCurrentEon(env.Chain.Config(), env.GetEVM())
	if err == nil {
		t.Errorf("no error before keyper config")
	}

	env.ScheduleKeyperSet()
	_, err = GetCurrentEon(env.Chain.Config(), env.GetEVM())
	if err == nil {
		t.Errorf("no error before keyper set is activated")
	}

	env.ExtendChain(10, nil)
	eon, err := GetCurrentEon(env.Chain.Config(), env.GetEVM())
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

	eon, err = GetCurrentEon(env.Chain.Config(), env.GetEVM())
	if err != nil {
		t.Errorf("failed to get eon")
	}
	if eon != 1 {
		t.Errorf("unexpected eon index")
	}
}

func TestGetCurrentEonKey(t *testing.T) {
	env := newPreKeyBroadcastTestEnv(t)
	key, err := GetCurrentEonKey(env.Chain.Config(), env.GetEVM())
	if err != nil {
		t.Errorf("failed to get eon key")
	}
	if len(key) != 0 {
		t.Errorf("eon key before broadcast is not empty")
	}

	env.BroadcastEonKey()
	key, err = GetCurrentEonKey(env.Chain.Config(), env.GetEVM())
	if err != nil {
		t.Errorf("failed to get eon key")
	}
	if !bytes.Equal(key, env.EonKey) {
		t.Errorf("got unexpected eon key")
	}
}

func TestIsKeyperSetManagerPaused(t *testing.T) {
	env := newTestEnv(t)
	paused, err := IsShutterKeyperSetManagerPaused(env.Chain.Config(), env.GetEVM())
	if err != nil {
		t.Errorf("failed to check if keyper set manager is paused: %v", err)
	}
	if paused {
		t.Errorf("keyper set manager is initially paused")
	}

	env.PauseKeyperSetManager()
	paused, err = IsShutterKeyperSetManagerPaused(env.Chain.Config(), env.GetEVM())
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
		enabled, err := IsShutterEnabled(env.Chain.Config(), env.GetEVM())
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
		revealTx := &types.RevealTx{}
		g.AddTx(types.NewTx(revealTx))
		g.AddTx(types.NewTx(revealTx))
	})
	_, _, _, err = processor.Process(blocks[0], env.GetStateDB(), vm.Config{})
	if err != ErrUnexpectedRevealTx {
		t.Errorf("expected unexpected reveal tx error, got %v", err)
	}

	blocks, _ = GenerateChain(env.Chain.Config(), head, env.Chain.Engine(), env.DB, 1, func(n int, g *BlockGen) {
		revealTx := &types.RevealTx{}
		g.AddTx(types.NewTx(revealTx))
	})
	_, _, _, err = processor.Process(blocks[0], env.GetStateDB(), vm.Config{})
	if err != nil {
		t.Errorf("processing block failed: %v", err)
	}
}
