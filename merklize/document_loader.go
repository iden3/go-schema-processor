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
	ipfsGW     string
}

// NewDocumentLoader creates a new document loader with a cache for http.
// ipfs cache is not implemented yet.
func NewDocumentLoader(ipfsCli *shell.Shell, ipfsGW string) ld.DocumentLoader {
	return &documentLoader{
		httpLoader: ld.NewRFC7324CachingDocumentLoader(nil),
		ipfsCli:    ipfsCli,
		ipfsGW:     ipfsGW,
	}
}

func (d *documentLoader) LoadDocument(
	u string) (doc *ld.RemoteDocument, err error) {

	const ipfsPrefix = "ipfs://"

	switch {
	case strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://"):
		return d.httpLoader.LoadDocument(u)

	case strings.HasPrefix(u, ipfsPrefix):
		// supported URLs:
		// ipfs://<cid>/dir/schema.json
		// ipfs://<cid>

		doc = &ld.RemoteDocument{DocumentURL: u}

		// strip ipfs:// prefix
		u = u[len(ipfsPrefix):]

		switch {
		case d.ipfsCli != nil:
			doc.Document, err = d.loadDocumentFromIPFSNode(u)
		case d.ipfsGW != "":
			doc.Document, err = d.loadDocumentFromIPFSGW(u)
		default:
			err = ld.NewJsonLdError(ld.LoadingDocumentFailed,
				errors.New("ipfs is not configured"))
		}
		if err != nil {
			return nil, err
		}

		return doc, nil

	default:
		err = errors.New("unsupported URL schema")
		return nil, ld.NewJsonLdError(ld.LoadingDocumentFailed, err)
	}
}

func (d *documentLoader) loadDocumentFromIPFSNode(
	ipfsURL string) (document any, err error) {

	if d.ipfsCli == nil {
		return nil, errors.New("ipfs is not configured")
	}

	var r io.ReadCloser
	r, err = d.ipfsCli.Cat(ipfsURL)
	if err != nil {
		return nil, ld.NewJsonLdError(ld.LoadingDocumentFailed, err)
	}
	defer func() {
		err2 := r.Close()
		if err == nil {
			err = err2
		}
	}()

	return ld.DocumentFromReader(r)
}

func (d *documentLoader) loadDocumentFromIPFSGW(
	ipfsURL string) (any, error) {

	ipfsURL = strings.TrimRight(d.ipfsGW, "/") + "/ipfs/" +
		strings.TrimLeft(ipfsURL, "/")
	doc, err := d.httpLoader.LoadDocument(ipfsURL)
	if err != nil {
		return nil, err
	}
	return doc.Document, nil
}
