package loaders

import (
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

	http.DefaultClient.Timeout = 2 * time.Second
	resp, err := http.Get(u.String())
	if err != nil {
		return nil, "", err
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
