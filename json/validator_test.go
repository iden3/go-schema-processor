package json

import (
	"testing"

	"github.com/iden3/go-schema-processor/v2/verifiable"
	"github.com/stretchr/testify/assert"
)

func TestValidator_ValidateData(t *testing.T) {

	jsonDIDDocument := `{"service":[{"id":"did:example:123#linked-domain","type":"LinkedDomains","serviceEndpoint":"https://bar.example.com"},{"id":"did:example:123#linked-domain","type":"push-notification","metadata":{"devices":[{"ciphertext":"base64encoded","alg":"rsa"}]},"serviceEndpoint":"https://bar.example.com"}],"id":"did:example:123#linked-domain"}`

	v := Validator{}

	err := v.ValidateData([]byte(jsonDIDDocument), []byte(verifiable.DIDDocumentJSONSchema))

	assert.NoError(t, err)
}

func TestValidator_ValidateDataNoTypeInService(t *testing.T) {

	// no type in did document service
	jsonDIDDocument := `{"service":[{"id":"did:example:123#linked-domain","serviceEndpoint":"https://bar.example.com"},{"id":"did:example:123#linked-domain","type":"push-notification","metadata":{"devices":[{"ciphertext":"base64encoded","alg":"rsa"}]},"serviceEndpoint":"https://bar.example.com"}],"id":"did:example:123#linked-domain"}`

	v := Validator{}

	err := v.ValidateData([]byte(jsonDIDDocument), []byte(verifiable.DIDDocumentJSONSchema))

	assert.ErrorContains(t, err, "\"type\" value is required")

}
func TestValidator_ValidateDataNoIDinDocument(t *testing.T) {

	// no type in did document service
	jsonDIDDocument := `{"service":[{"id":"did:example:123#linked-domain","type":"LinkedDomains","serviceEndpoint":"https://bar.example.com"},{"id":"did:example:123#linked-domain","type":"push-notification","metadata":{"devices":[{"ciphertext":"base64encoded","alg":"rsa"}]},"serviceEndpoint":"https://bar.example.com"}]}`

	v := Validator{}

	err := v.ValidateData([]byte(jsonDIDDocument), []byte(verifiable.DIDDocumentJSONSchema))

	assert.ErrorContains(t, err, "\"id\" value is required")

}
