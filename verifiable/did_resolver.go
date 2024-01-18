package verifiable

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"

	"github.com/iden3/go-iden3-core/v2/w3c"
	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/pkg/errors"
)

type DIDResolver interface {
	Resolve(ctx context.Context, did *w3c.DID, state *big.Int) (DIDDocument, error)
}

type HTTPDIDResolver struct {
	resolverURL      string
	customHTTPClient *http.Client
}

func (r HTTPDIDResolver) Resolve(ctx context.Context, did *w3c.DID, state *big.Int) (out DIDDocument, err error) {
	type didResolutionResult struct {
		DIDDocument DIDDocument `json:"didDocument"`
	}
	res := &didResolutionResult{}

	var (
		resp       *http.Response
		httpClient *http.Client
	)
	if r.customHTTPClient != nil {
		httpClient = r.customHTTPClient
	} else {
		httpClient = http.DefaultClient
	}
	if state != nil {
		var (
			didStr        string
			didQueryParam string
			stateHash     *merkletree.Hash
		)
		didStr = did.String()
		didQueryParam = url.QueryEscape(didStr)
		stateHash, err = merkletree.NewHashFromBigInt(state)
		if err != nil {
			return out, err
		}
		resp, err = httpClient.Get(fmt.Sprintf("%s/%s?state=%s", strings.Trim(r.resolverURL, "/"), didQueryParam, stateHash.Hex()))
	} else {
		resp, err = httpClient.Get(fmt.Sprintf("%s/%s", strings.Trim(r.resolverURL, "/"), did))
	}

	if err != nil {
		return out, err
	}

	defer func() {
		err2 := resp.Body.Close()
		if err != nil {
			err = errors.WithStack(err2)
		}
	}()

	err = json.NewDecoder(resp.Body).Decode(&res)
	if err != nil {
		return out, err
	}

	return res.DIDDocument, nil
}
