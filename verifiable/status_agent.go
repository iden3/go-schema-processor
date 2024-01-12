package verifiable

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	"github.com/google/uuid"
	"github.com/iden3/iden3comm/v2"
	"github.com/pkg/errors"
)

// revocationStatusRequestMessageBody is struct the represents request for revocation status
type revocationStatusRequestMessageBody struct {
	RevocationNonce uint64 `json:"revocation_nonce"`
}

const (
	// RevocationStatusRequestMessageType is type for request of revocation status
	revocationStatusRequestMessageType iden3comm.ProtocolMessage = iden3comm.Iden3Protocol + "revocation/1.0/request-status"
	// RevocationStatusResponseMessageType is type for response with a revocation status
	revocationStatusResponseMessageType iden3comm.ProtocolMessage = iden3comm.Iden3Protocol + "revocation/1.0/status"
)

// MediaTypePlainMessage is media type for plain message
const mediaTypePlainMessage iden3comm.MediaType = "application/iden3comm-plain-json"

// RevocationStatusResponseMessageBody is struct the represents request for revocation status
type revocationStatusResponseMessageBody struct {
	RevocationStatus
}

type AgentResolver struct {
}

func (AgentResolver) Resolve(status CredentialStatus, cfg CredentialStatusConfig) (out RevocationStatus, err error) {
	revocationBody := revocationStatusRequestMessageBody{
		RevocationNonce: status.RevocationNonce,
	}
	rawBody, err := json.Marshal(revocationBody)
	if err != nil {
		return out, errors.WithStack(err)
	}

	msg := iden3comm.BasicMessage{
		ID:       uuid.New().String(),
		ThreadID: uuid.New().String(),
		From:     *cfg.userDID,
		To:       *cfg.issuerDID,
		Type:     revocationStatusRequestMessageType,
		Body:     rawBody,
	}
	bytesMsg, err := json.Marshal(msg)
	if err != nil {
		return out, errors.WithStack(err)
	}

	iden3commMsg, err := cfg.packageManager.Pack(mediaTypePlainMessage, bytesMsg, nil)
	if err != nil {
		return out, errors.WithStack(err)
	}

	resp, err := http.DefaultClient.Post(status.ID, "application/json", bytes.NewBuffer(iden3commMsg))
	if err != nil {
		return out, errors.WithStack(err)
	}
	defer func() {
		err2 := resp.Body.Close()
		if err != nil {
			err = errors.WithStack(err2)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return out, errors.Errorf("bad status code: %d", resp.StatusCode)
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return out, errors.WithStack(err)
	}

	basicMessage, _, err := cfg.packageManager.Unpack(b)
	if err != nil {
		return out, errors.WithStack(err)
	}

	if basicMessage.Type != revocationStatusResponseMessageType {
		return out, errors.Errorf("unexpected message type: %s", basicMessage.Type)
	}

	var revocationStatus revocationStatusResponseMessageBody
	if err := json.Unmarshal(basicMessage.Body, &revocationStatus); err != nil {
		return out, errors.WithStack(err)
	}

	return revocationStatus.RevocationStatus, nil
}
