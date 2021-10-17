package json_ld

import (
	"github.com/pkg/errors"
)

type Parser struct {
}

func (s Parser) ParseSlots(_data, _schema []byte) (index, value []byte, err error) {
	return nil, nil, errors.New("not implemented")
}
