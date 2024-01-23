package verifiable

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type IssuerResolver struct {
}

const limitReaderBytes = 16 * 1024

func (IssuerResolver) Resolve(ctx context.Context,
	credentialStatus CredentialStatus) (out RevocationStatus, err error) {

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet,
		credentialStatus.ID, http.NoBody)
	if err != nil {
		return out, err
	}
	httpResp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return out, err
	}
	defer func() {
		err2 := httpResp.Body.Close()
		if err2 != nil && err == nil {
			err = err2
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
