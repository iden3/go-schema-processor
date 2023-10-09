package loaders_test

import (
	"net/http"
	"testing"

	"github.com/iden3/go-schema-processor/v2/loaders"
	"github.com/stretchr/testify/require"
)

func TestW3CLoader_JSONUnmarshal(t *testing.T) {

	w3cLoader := loaders.NewW3CDocumentLoader(nil, "https://ipfs.io", createDisabledHTTPClient())
	doc, err := w3cLoader.LoadDocument(loaders.W3CCredential2018ContextURL)
	require.NoError(t, err)

	require.NotNil(t, (doc.Document.(map[string]interface{}))["@context"])
}

type DisableHTTPTransport struct{}

func (t *DisableHTTPTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Do nothing and return a dummy response
	return &http.Response{
		StatusCode: http.StatusNotImplemented, // You can choose any status code
		Body:       nil,
	}, nil
}
func createDisabledHTTPClient() *http.Client {
	return &http.Client{
		Transport: &DisableHTTPTransport{},
	}
}
