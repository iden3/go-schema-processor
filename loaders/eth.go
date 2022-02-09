package loaders

import (
	"context"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/iden3/go-schema-registry-wrapper/wrapper"
	"github.com/pkg/errors"
)

// Eth is loader for getting schema from blockchain
type Eth struct {
	ContractAddress string
	URL             string
	SchemaName      string
	SchemaHash      string
}

// Load loads schema by name or hash
func (l Eth) Load(ctx context.Context) (schema []byte, extension string, err error) {
	if l.URL == "" || l.ContractAddress == "" {
		return nil, "", errors.New("RPC url, Contract address should not be empty")
	}

	if l.SchemaHash != "" {
		payload, err := wrapper.EncodeSchemaBytesByHash(l.SchemaHash)
		if err != nil {
			return nil, "", err
		}
		b, err := callContract(ctx, l.URL, l.ContractAddress, payload)
		if err != nil {
			return nil, "", err
		}
		schema, err = wrapper.DecodeSchemaBytesByHash(b)
		if err != nil {
			return nil, "", err
		}
		return schema, "json-ld", nil
	} else if l.SchemaName != "" {
		payload, err := wrapper.EncodeSchemaHashByName(l.SchemaName)
		if err != nil {
			return nil, "", err
		}
		b, err := callContract(ctx, l.URL, l.ContractAddress, payload)
		if err != nil {
			return nil, "", err
		}
		schema, err = wrapper.DecodeSchemaBytesByName(b)
		if err != nil {
			return nil, "", err
		}

		return schema, "json-ld", nil
	}

	return nil, "", errors.New("schema name and schema hash are empty")

}

func callContract(ctx context.Context, rpcURL, cAddress string, payload []byte) ([]byte, error) {
	cl, err := ethclient.DialContext(ctx, rpcURL)
	if err != nil {
		return nil, err
	}

	addr := common.HexToAddress(cAddress)

	res, err := cl.CallContract(ctx, ethereum.CallMsg{
		To:   &addr,
		Data: payload,
	}, nil)

	if err != nil {
		return nil, err
	}

	return res, nil
}
