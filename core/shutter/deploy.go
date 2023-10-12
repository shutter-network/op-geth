package shutter

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

func GetKeyBroadcastContractDeployData(keyperSetManagerAddress *common.Address) []byte {
	bytecode := getBytecode(keyBroadcastContractJSON)
	args, err := KeyBroadcastContractABI.Pack("", keyperSetManagerAddress)
	if err != nil {
		panic(err)
	}
	return append(bytecode, args...)
}

func GetKeyperSetManagerDeployData() []byte {
	return getBytecode(keyperSetManagerJSON)
}

func GetKeyperSetDeployData() []byte {
	return getBytecode(keyperSetJSON)
}

func getBytecode(json map[string]interface{}) []byte {
	d := json["bytecode"].(map[string]interface{})
	h := d["object"].(string)
	b, err := hexutil.Decode(h)
	if err != nil {
		panic(err)
	}
	return b
}
