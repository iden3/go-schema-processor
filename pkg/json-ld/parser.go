package json_ld

import (
	"github.com/iden3/go-claim-schema-processor/pkg/processor"
	"github.com/pkg/errors"
)

type Parser struct {
}

func (s Parser) ParseSlots(_, _ []byte) (processor.ParsedSlots, error) {
	return processor.ParsedSlots{}, errors.New("not implemented")
}
