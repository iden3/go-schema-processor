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

const limitReaderBytes = 16 * 1024

func (IssuerResolver) Resolve(context context.Context, credentialStatus CredentialStatus, opts ...CredentialStatusResolveOpt) (out RevocationStatus, err error) {
	httpReq, err := http.NewRequestWithContext(context, http.MethodGet, credentialStatus.ID,
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

	statusOK := httpResp.StatusCode >= 200 && httpResp.StatusCode < 300
	if !statusOK {
		return out, fmt.Errorf("unexpected status code: %v",
			httpResp.StatusCode)
	}

	respData, err := io.ReadAll(io.LimitReader(httpResp.Body, limitReaderBytes))
	if err != nil {
		return out, err
	}
	err = json.Unmarshal(respData, &out)
	if err != nil {
		return out, err
	}
	return out, nil
}
