package loaders

import (
	"net/http"
	"strings"

	shell "github.com/ipfs/go-ipfs-api"
	"github.com/piprate/json-gold/ld"
)

type W3CDocumentLoader struct {
	documentLoader
}

// NewW3CDocumentLoader creates a new document loader with a predefined http schema
func NewW3CDocumentLoader(ipfsCli *shell.Shell, ipfsGW string, httpClient *http.Client) ld.DocumentLoader {
	return &W3CDocumentLoader{
		documentLoader: documentLoader{
			httpLoader: ld.NewRFC7324CachingDocumentLoader(httpClient),
			ipfsCli:    ipfsCli,
			ipfsGW:     ipfsGW,
		},
	}
}

func (d *W3CDocumentLoader) LoadDocument(
	u string) (doc *ld.RemoteDocument, err error) {

	if u == W3CCredential2018ContextURL {
		w3cDoc, errIn := ld.DocumentFromReader(strings.NewReader(W3CCredential2018ContextDocument))
		if errIn != nil {
			return nil, errIn
		}
		return &ld.RemoteDocument{
			DocumentURL: u,
			Document:    w3cDoc,
			ContextURL:  u,
		}, nil
	}
	return d.LoadDocument(u)
}
