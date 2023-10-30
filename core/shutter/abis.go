package shutter

import (
	"bytes"
	_ "embed"
	"encoding/json"

	"github.com/ethereum/go-ethereum/accounts/abi"
)

//go:embed abis/KeyBroadcastContract.json
var keyBroacastContractFile []byte

//go:embed abis/KeyperSetManager.json
var keyperSetManagerFile []byte

//go:embed abis/KeyperSet.json
var keyperSetFile []byte

//go:embed abis/Inbox.json
var inboxFile []byte

var (
	keyBroadcastContractJSON map[string]interface{}
	keyperSetManagerJSON     map[string]interface{}
	keyperSetJSON            map[string]interface{}
	inboxJSON                map[string]interface{}
)

var (
	KeyBroadcastContractABI abi.ABI
	KeyperSetManagerABI     abi.ABI
	KeyperSetABI            abi.ABI
	InboxABI                abi.ABI
)

func init() {
	keyBroadcastContractJSON = loadJSON(keyBroacastContractFile)
	keyperSetManagerJSON = loadJSON(keyperSetManagerFile)
	keyperSetJSON = loadJSON(keyperSetFile)
	inboxJSON = loadJSON(inboxFile)

	KeyBroadcastContractABI = loadABI(keyBroadcastContractJSON)
	KeyperSetManagerABI = loadABI(keyperSetManagerJSON)
	KeyperSetABI = loadABI(keyperSetJSON)
	InboxABI = loadABI(inboxJSON)
}

func loadJSON(s []byte) map[string]interface{} {
	var data map[string]interface{}
	err := json.Unmarshal(s, &data)
	if err != nil {
		panic(err)
	}
	return data
}

func loadABI(data map[string]interface{}) abi.ABI {
	abiMapping, exists := data["abi"]
	if !exists {
		panic("json does not contain abi specification")
	}
	abiString, err := json.Marshal(abiMapping)
	if err != nil {
		panic(err)
	}
	abi, err := abi.JSON(bytes.NewReader(abiString))
	if err != nil {
		panic(err)
	}
	return abi
}
