package loaders

import (
	"bytes"
	"context"
	shell "github.com/ipfs/go-ipfs-api"
	"github.com/pkg/errors"
)

// CIDEEmptyError is for error when CID is empty
var CIDEEmptyError = errors.New("CID is empty")

// IPFS loader for fetching schema
type IPFS struct {
	URL string
	CID string
}

// Load method IPFS implementation
func (l IPFS) Load(ctx context.Context) (schema []byte, extension string, err error) {

	if l.URL == "" {
		return nil, "", ErrorURLEmpty
	}

	if l.CID == "" {
		return nil, "", CIDEEmptyError
	}

	sh := shell.NewShell(l.URL)

	data, err := sh.Cat(l.CID)

	if err != nil {
		return nil, "", err
	}

	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(data)
	if err != nil {
		return nil, "", err
	}

	return buf.Bytes(), "json-ld", nil
}
