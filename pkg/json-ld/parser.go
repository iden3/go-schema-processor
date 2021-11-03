package json_ld

import (
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

	return claims.PrepareClaimSlots(data, indexFields, valueFields)
}

func isVocabField(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return false
		}
	}
	return true
}
