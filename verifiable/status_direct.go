package verifiable

import (
	"context"
	"encoding/json"
	goerr "errors"
	"fmt"
	"io"
	"net/http"

	"github.com/pkg/errors"
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
	// TODO: Maybe this place is a candidate to get a non-default http client from the context tha same way as User/Issuer DIDs.
	httpResp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return out, err
	}
	defer func() {
		// TODO: review this error handing.
		err2 := httpResp.Body.Close()
		if err2 != nil {
			err2 = errors.WithStack(err2)
			if err == nil {
				err = err2
			} else {
				err = goerr.Join(err, err2)
			}
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
