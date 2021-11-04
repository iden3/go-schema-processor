package json_ld

import (
	"encoding/json"
	"github.com/iden3/go-claim-schema-processor/pkg/claims"
	"github.com/iden3/go-claim-schema-processor/pkg/processor"
	"github.com/pkg/errors"
	"sort"
)

// Parser can parse claim data according to specification
type Parser struct {
	ClaimType string
}

// ClaimSchema is description of schema for specific claim type
type ClaimSchema struct {
	ID      string                 `json:"@id"`
	Context map[string]interface{} `json:"@context"`
}

// ClaimBasicContext is representation of default fields for claim schema
type ClaimBasicContext struct {
	Version   float64 `json:"@version"`
	Protected bool    `json:"@protected"`
	ID        string  `json:"id"`
	Type      string  `json:"type"`
}

const serializationIndexType = "serialization:Index"
const serializationValueType = "serialization:Value"

// SerializationField represents fields that rather must be parsed to value or index
type SerializationField struct {
	ID   string `json:"@id"`
	Type string `json:"@type"`
}

// ClaimContext all parsed fields of ClaimSchema
type ClaimContext struct {
	ClaimBasicContext
	Fields map[string]SerializationField
	Vocab  map[string]string
}

// SchemaContext is top-level wrapper of json-ld schema
type SchemaContext struct {
	Context []map[string]interface{} `json:"@context"`
}

// ParseSlots converts payload to claim slots using provided schema
func (p Parser) ParseSlots(data, schema []byte) (processor.ParsedSlots, error) {

	claimContext, err := getClaimContext(p.ClaimType, schema)
	if err != nil {
		return processor.ParsedSlots{}, err
	}
	var indexFields []string
	var valueFields []string

	for k, v := range claimContext.Fields {
		switch v.Type {
		case serializationIndexType:
			indexFields = append(indexFields, k)
		case serializationValueType:
			valueFields = append(valueFields, k)
		default:
			return processor.ParsedSlots{}, errors.New("field type is not supported")
		}
	}

	// NOW fields are in reverse alphabetical order ( based on KYC circuits implementation)
	sort.Slice(indexFields, func(i, j int) bool {
		return indexFields[j] < indexFields[i]
	})
	sort.Slice(valueFields, func(i, j int) bool {
		return valueFields[j] < valueFields[i]
	})

	/*  if all data fields have position property then we need to process it
	`"baseType"
	"data":
	"position":
	*/

	preparedData := map[string]interface{}{}
	var extendedData map[string]map[string]interface{}

	err = json.Unmarshal(data, &extendedData)
	if err != nil {
		// that means that data is not presented as extended format
		return claims.PrepareClaimSlots(data, indexFields, valueFields)

	}
	// that means that data is presented in the extended format (each field has a detailed description how it should be processed)

	positionedIndexes := make([]string, len(indexFields))

	for _, fieldName := range indexFields {
		position, ok := extendedData[fieldName]["position"].(float64)
		if !ok {
			return processor.ParsedSlots{}, errors.New("position is not found")
		}
		positionedIndexes[int(position)] = fieldName
		preparedData[fieldName] = extendedData[fieldName]["data"]

	}
	positionedValues := make([]string, len(valueFields))

	for _, fieldName := range valueFields {
		position, ok := extendedData[fieldName]["position"].(float64)
		if !ok {
			return processor.ParsedSlots{}, errors.New("position is not found")
		}
		positionedValues[int(position)] = fieldName
		preparedData[fieldName] = extendedData[fieldName]["data"]
	}

	preparedDataBytes, err := json.Marshal(preparedData)
	if err != nil {
		return processor.ParsedSlots{}, err
	}
	return claims.PrepareClaimSlots(preparedDataBytes, positionedIndexes, positionedValues)
}

func isVocabField(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return false
		}
	}
	return true
}
