package json

import (
	"context"
	"testing"

	"github.com/iden3/go-schema-processor/v2/json"
	"github.com/iden3/go-schema-processor/v2/loaders"
	"github.com/iden3/go-schema-processor/v2/processor"
	tst "github.com/iden3/go-schema-processor/v2/testing"
	"github.com/stretchr/testify/require"
)

func TestInit(t *testing.T) {
	defer tst.MockHTTPClient(t, map[string]string{
		"https://example.com/schema.json": "testdata/schema.json",
	}, tst.IgnoreUntouchedURLs())()

	loader := loaders.NewDocumentLoader(nil, "")
	validator := json.Validator{}
	parser := json.Parser{}

	jsonProcessor := New(processor.WithValidator(validator),
		processor.WithParser(parser), processor.WithDocumentLoader(loader))

	ctx := context.Background()
	_, err := jsonProcessor.Load(ctx, "https://example.com/schema.json")
	require.NoError(t, err)
}

func TestValidator(t *testing.T) {
	defer tst.MockHTTPClient(t, map[string]string{
		"https://example.com/schema.json": "testdata/schema.json",
	}, tst.IgnoreUntouchedURLs())()

	loader := loaders.NewDocumentLoader(nil, "")
	validator := json.Validator{}
	parser := json.Parser{}

	jsonProcessor := New(processor.WithValidator(validator),
		processor.WithParser(parser), processor.WithDocumentLoader(loader))

	ctx := context.Background()
	schema, err := jsonProcessor.Load(ctx, "https://example.com/schema.json")
	require.NoError(t, err)
	require.NotEmpty(t, schema)

	dataBytes := []byte(`{
  "birthday": 1,
  "documentType": 1
}`)

	err = jsonProcessor.ValidateData(dataBytes, schema)
	require.NoError(t, err)
}

func TestValidatorWithInvalidField(t *testing.T) {
	defer tst.MockHTTPClient(t, map[string]string{
		"https://example.com/schema.json": "testdata/schema.json",
	}, tst.IgnoreUntouchedURLs())()

	loader := loaders.NewDocumentLoader(nil, "")
	validator := json.Validator{}
	parser := json.Parser{}

	jsonProcessor := New(processor.WithValidator(validator),
		processor.WithParser(parser), processor.WithDocumentLoader(loader))

	schema, err := jsonProcessor.Load(context.Background(),
		"https://example.com/schema.json")

	require.NoError(t, err)
	require.NotEmpty(t, schema)

	dataBytes := []byte(`{
  "documentType": 1
}`)

	err = jsonProcessor.ValidateData(dataBytes, schema)
	require.ErrorContains(t, err, "missing properties: 'birthday'")
}
