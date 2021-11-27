package loaders

import (
	"github.com/pkg/errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// HTTP is loader for http / https schemas
type HTTP struct {
}

// Load loads schema by url
func (l HTTP) Load(_url string) (schema []byte, extension string, err error) {

	//parse schema url
	u, err := url.Parse(_url)
	if err != nil {
		return nil, "", err
	}
	// get a file extension
	segments := strings.Split(u.Path, "/")
	extension = segments[len(segments)-1][strings.Index(segments[len(segments)-1], ".")+1:]

	http.DefaultClient.Timeout = 30 * time.Second
	resp, err := http.Get(u.String())
	if err != nil {
		return nil, "", errors.WithMessage(err, "http request failed")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", errors.Errorf("request failed with status code %v", resp.StatusCode)
	}
	defer func() {
		if tempErr := resp.Body.Close(); tempErr != nil {
			err = tempErr
		}
	}()

	// We Read the response body on the line below.
	schema, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, "", err
	}
	return schema, extension, err
}
