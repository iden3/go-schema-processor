package loaders

import (
	"context"
	"github.com/iden3/go-schema-registry-wrapper/wrapper"
	"github.com/pkg/errors"
)

// Eth is loader for getting schema from blockchain
type Eth struct {
	ContractAddress string
	URL             string
	ShcemaName      string
	SchemaHash      string
}

// Load loads schema by name or hash
func (l Eth) Load(ctx context.Context) ([]byte, string, error) {
	if l.URL == "" || l.ContractAddress == "" {
		return nil, "", errors.New("RPC url, Contract address should not be empty")
	}

	var b []byte
	var err error
	if l.SchemaHash != "" {
		b, err = wrapper.GetSchemaBytesByHash(ctx, l.URL, l.ContractAddress, l.ShcemaName)
	} else if l.ShcemaName != "" {
		b, err = wrapper.GetSchemaBytesByName(ctx, l.URL, l.ContractAddress, l.ShcemaName)
	} else {
		return nil, "", errors.New("schema name and schema hash are empty")
	}

	if err != nil {
		return nil, "", err
	}
	return b, "json-ld", nil
}
