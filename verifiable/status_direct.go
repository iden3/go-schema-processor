package verifiable

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/pkg/errors"
)

type IssuerResolver struct {
}

func (IssuerResolver) Resolve(credentialStatus CredentialStatus, cfg CredentialStatusConfig) (out RevocationStatus, err error) {
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
	err = json.Unmarshal(respData, &out)
	if err != nil {
		return out, err
	}
	return out, nil
}
