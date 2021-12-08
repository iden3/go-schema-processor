package jsonld

import (
	commonJSON "encoding/json"
	"github.com/iden3/go-claim-schema-processor/json"
	jsonld "github.com/iden3/go-claim-schema-processor/json-ld"
	"github.com/iden3/go-claim-schema-processor/loaders"
	"github.com/iden3/go-claim-schema-processor/processor"
	"github.com/stretchr/testify/assert"
	"testing"
)

var url = "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc.json-ld"

func TestParserWithSimpleData(t *testing.T) {
	loader := loaders.HTTP{}
	validator := json.Validator{}
	parser := jsonld.Parser{ClaimType: "KYCAgeCredential", ParsingStrategy: processor.SlotFullfilmentStrategy}

	jsonLdProcessor := New(processor.WithValidator(validator), processor.WithParser(parser), processor.WithSchemaLoader(loader))
	schema, ext, err := jsonLdProcessor.Load(url)

	assert.Nil(t, err)
	assert.Equal(t, ext, "json-ld")
	assert.NotEmpty(t, schema)

	data := make(map[string]interface{})

	// it will be processed in reverse alphabetical order
	data["birthdayYear"] = 1996
	data["birthdayMonth"] = 4
	data["birthdayDay"] = 24
	data["documentType"] = 1

	dataBytes, err := commonJSON.Marshal(data)
	assert.Nil(t, err)

	parsedData, err := jsonLdProcessor.ParseSlots(dataBytes, schema)
	expetctedSlotA := []uint8{24, 0, 0, 0, 4, 0, 0, 0, 204, 7, 0, 0, 1, 0, 0, 0}

	t.Log(parsedData.IndexA)
	assert.Nil(t, err)
	assert.NotEmpty(t, parsedData.IndexA)
	assert.Equal(t, expetctedSlotA, parsedData.IndexA)

	assert.Empty(t, parsedData.IndexB)
	assert.Empty(t, parsedData.ValueA)
	assert.Empty(t, parsedData.ValueB)

}

func TestParserWithPositionedData(t *testing.T) {
	loader := loaders.HTTP{}
	validator := json.Validator{}
	parser := jsonld.Parser{ClaimType: "KYCAgeCredential", ParsingStrategy: processor.SlotFullfilmentStrategy}

	jsonLdProcessor := New(processor.WithValidator(validator), processor.WithParser(parser), processor.WithSchemaLoader(loader))
	schema, ext, err := jsonLdProcessor.Load(url)

	assert.Nil(t, err)
	assert.Equal(t, ext, "json-ld")
	assert.NotEmpty(t, schema)

	data := make(map[string]interface{})

	data["birthdayDay"] = map[string]interface{}{"position": 0, "data": 24}
	data["birthdayMonth"] = map[string]interface{}{"position": 1, "data": 4}
	data["birthdayYear"] = map[string]interface{}{"position": 2, "data": 1996}
	data["documentType"] = map[string]interface{}{"position": 3, "data": 1}

	dataBytes, err := commonJSON.Marshal(data)
	assert.Nil(t, err)

	parsedData, err := jsonLdProcessor.ParseSlots(dataBytes, schema)

	exptectedSlotA := []uint8{24, 0, 0, 0, 4, 0, 0, 0, 204, 7, 0, 0, 1, 0, 0, 0}

	assert.Nil(t, err)
	assert.NotEmpty(t, parsedData.IndexA)
	assert.Equal(t, exptectedSlotA, parsedData.IndexA)
	assert.Empty(t, parsedData.IndexB)
	assert.Empty(t, parsedData.ValueA)
	assert.Empty(t, parsedData.ValueB)

}

func TestValidator(t *testing.T) {

	loader := loaders.HTTP{}
	validator := jsonld.Validator{ClaimType: "KYCAgeCredential"}

	p := New(processor.WithValidator(validator), processor.WithSchemaLoader(loader))

	schema, ext, err := p.Load(url)

	assert.Nil(t, err)
	assert.Equal(t, ext, "json-ld")
	assert.NotEmpty(t, schema)

	data := make(map[string]interface{})
	data["birthdayDay"] = 24
	data["birthdayMonth"] = 4
	data["birthdayYear"] = 1996
	data["documentType"] = 1

	dataBytes, err := commonJSON.Marshal(data)
	assert.Nil(t, err)

	err = p.ValidateData(dataBytes, schema)

	assert.Nil(t, err)

}

func TestValidatorWithInvalidField(t *testing.T) {

	loader := loaders.HTTP{}
	validator := jsonld.Validator{ClaimType: "KYCAgeCredential"}

	p := New(processor.WithValidator(validator), processor.WithSchemaLoader(loader))

	schema, ext, err := p.Load(url)

	assert.Nil(t, err)
	assert.Equal(t, ext, "json-ld")
	assert.NotEmpty(t, schema)

	data := make(map[string]interface{})
	data["birthdayDay"] = 24
	data["birthdayMonth"] = 4
	data["documentType"] = 1

	dataBytes, err := commonJSON.Marshal(data)
	assert.Nil(t, err)

	err = p.ValidateData(dataBytes, schema)

	assert.NotNil(t, err)
	assert.Containsf(t, err.Error(), "field birthdayYear is missign in the payload, but required in schema", "expected error containing %q, got %s", "\"birthdayYear\" value is required", err)

}

func TestValidatorWithPositionedData(t *testing.T) {

	loader := loaders.HTTP{}
	validator := jsonld.Validator{ClaimType: "KYCAgeCredential"}

	p := New(processor.WithValidator(validator), processor.WithSchemaLoader(loader))

	schema, ext, err := p.Load(url)

	assert.Nil(t, err)
	assert.Equal(t, ext, "json-ld")
	assert.NotEmpty(t, schema)

	data := make(map[string]interface{})
	data["birthdayDay"] = map[string]interface{}{"position": 0, "data": 24}
	data["birthdayMonth"] = map[string]interface{}{"position": 1, "data": 4}
	data["birthdayYear"] = map[string]interface{}{"position": 2, "data": 1996}
	data["documentType"] = map[string]interface{}{"position": 3, "data": 1}

	dataBytes, err := commonJSON.Marshal(data)
	assert.Nil(t, err)

	err = p.ValidateData(dataBytes, schema)

	assert.Nil(t, err)

}

func TestParserWithSlotsTypes(t *testing.T) {

	url = "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v2.json-ld"

	loader := loaders.HTTP{}
	validator := json.Validator{}
	parser := jsonld.Parser{ClaimType: "KYCAgeCredential", ParsingStrategy: processor.OneFieldPerSlotStrategy}

	jsonLdProcessor := New(processor.WithValidator(validator), processor.WithParser(parser), processor.WithSchemaLoader(loader))
	schema, ext, err := jsonLdProcessor.Load(url)

	assert.Nil(t, err)
	assert.Equal(t, ext, "json-ld")
	assert.NotEmpty(t, schema)

	data := make(map[string]interface{})

	data["birthday"] = 828522341
	data["documentType"] = 1

	dataBytes, err := commonJSON.Marshal(data)
	assert.Nil(t, err)

	parsedData, err := jsonLdProcessor.ParseSlots(dataBytes, schema)
	assert.Nil(t, err)
	t.Log(parsedData.IndexA)
	expetctedSlotA := []uint8{101, 63, 98, 49}
	expetctedSlotB := []uint8{1, 0, 0, 0}

	t.Log(parsedData.IndexA)
	assert.Nil(t, err)
	assert.NotEmpty(t, parsedData.IndexA)
	assert.Equal(t, expetctedSlotA, parsedData.IndexA)
	assert.Equal(t, expetctedSlotB, parsedData.IndexB)

	assert.Empty(t, parsedData.ValueA)
	assert.Empty(t, parsedData.ValueB)

}