package merklize

import (
	"errors"
	"io"
	"strings"

	shell "github.com/ipfs/go-ipfs-api"
	"github.com/piprate/json-gold/ld"
)

type documentLoader struct {
	httpLoader *ld.RFC7324CachingDocumentLoader
	ipfsCli    *shell.Shell
}

// NewDocumentLoader creates a new document loader with a cache for http.
// ipfs cache is not implemented yet.
func NewDocumentLoader(ipfsCli *shell.Shell) ld.DocumentLoader {
	return &documentLoader{
		httpLoader: ld.NewRFC7324CachingDocumentLoader(nil),
		ipfsCli:    ipfsCli,
	}
}

func (d *documentLoader) LoadDocument(
	u string) (doc *ld.RemoteDocument, err error) {

	const ipfsPrefix = "ipfs://"

	if strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://") {
		return d.httpLoader.LoadDocument(u)

	} else if strings.HasPrefix(u, ipfsPrefix) {
		// ipfs://<cid>/dir/schema.json
		// ipfs://<cid>

		// strip ipfs:// prefix
		u = u[len(ipfsPrefix):]

		if d.ipfsCli == nil {
			err = errors.New("ipfs is not configured")
			return nil, ld.NewJsonLdError(ld.LoadingDocumentFailed, err)
		}

		doc = &ld.RemoteDocument{DocumentURL: u}

		var r io.ReadCloser
		r, err = d.ipfsCli.Cat(u)
		if err != nil {
			return nil, ld.NewJsonLdError(ld.LoadingDocumentFailed, err)
		}
		defer func() {
			err2 := r.Close()
			if err == nil {
				err = err2
			}
		}()

		doc.Document, err = ld.DocumentFromReader(r)
		if err != nil {
			return nil, err
		}

		return doc, nil

	} else {
		err = errors.New("unsupported URL schema")
		return nil, ld.NewJsonLdError(ld.LoadingDocumentFailed, err)
	}
}
