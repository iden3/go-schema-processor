package json

import (
	"github.com/iden3/iden3-claim-processor/pkg/json"
	"github.com/iden3/iden3-claim-processor/pkg/loaders"
	"github.com/iden3/iden3-claim-processor/pkg/processor"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestInit(t *testing.T) {

	loader := loaders.HTTP{}
	validator := json.Validator{}
	parser := json.Parser{}

	jsonProcessor := New(processor.WithValidator(validator), processor.WithParser(parser), processor.WithSchemaLoader(loader))
	errLoaderNotDefined := errors.New("loader is not defined")

	_, _, err := jsonProcessor.Load("https://google.com/custom.json")

	notDefinedError := errors.Is(errLoaderNotDefined, err)
	assert.Equal(t, false, notDefinedError)

}
