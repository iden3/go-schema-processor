package verifiable

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/pkg/errors"
)

type IssuerResolver struct {
}

func (*IssuerResolver) Resolve(credentialStatus CredentialStatus, cfg CredentialStatusConfig) (out RevocationStatus, err error) {
	httpReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet, credentialStatus.ID,
		http.NoBody)
	if err != nil {
		return out, err
	}
	httpResp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return out, err
	}
	defer func() {
		err2 := httpResp.Body.Close()
		if err != nil {
			err = errors.WithStack(err2)
		}
	}()
	if httpResp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("unexpected status code: %v",
			httpResp.StatusCode)
	}
	respData, err := io.ReadAll(io.LimitReader(httpResp.Body, 16*1024))
	if err != nil {
		return out, err
	}
	var obj struct {
		TreeState struct {
			State          *hexHash `json:"state"`              // identity state
			ClaimsRoot     *hexHash `json:"claimsTreeRoot"`     // claims tree root
			RevocationRoot *hexHash `json:"revocationTreeRoot"` // revocation tree root
			RootOfRoots    *hexHash `json:"rootOfRoots"`        // root of roots tree root

		} `json:"issuer"`
		Proof *merkletree.Proof `json:"mtp"`
	}
	err = json.Unmarshal(respData, &obj)
	if err != nil {
		return out, err
	}
	out.MTP = *obj.Proof
	stateHashHex := (*merkletree.Hash)(obj.TreeState.State).Hex()
	out.Issuer.State = &stateHashHex
	claimsRootHashHex := (*merkletree.Hash)(obj.TreeState.ClaimsRoot).Hex()
	out.Issuer.ClaimsTreeRoot = &claimsRootHashHex
	revocationRootHashHex := (*merkletree.Hash)(obj.TreeState.RevocationRoot).Hex()
	out.Issuer.RevocationTreeRoot = &revocationRootHashHex
	rootOfRootsHashHex := (*merkletree.Hash)(obj.TreeState.RootOfRoots).Hex()
	out.Issuer.RootOfRoots = &rootOfRootsHashHex
	return out, nil
}
