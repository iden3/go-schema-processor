package jsonld

import (
	"encoding/json"
	"github.com/pkg/errors"
)

func getClaimContext(claimType string, schema []byte) (*ClaimContext, error) {
	var schemaContext SchemaContext

	err := json.Unmarshal(schema, &schemaContext)
	if err != nil {
		return nil, err
	}

	// find type

	var claimSchemaData *ClaimSchema
	for _, c := range schemaContext.Context {
		data, ok := c[claimType]
		if !ok {
			continue
		} else {
			b, err := json.Marshal(data)
			if err != nil {
				return nil, err
			}
			err = json.Unmarshal(b, &claimSchemaData)
			if err != nil {
				return nil, err
			}
			break
		}
	}
	if claimSchemaData == nil {
		return nil, errors.New("no type in provided schema")
	}

	claimContext := ClaimContext{
		ClaimBasicContext: ClaimBasicContext{},
		Fields:            map[string]SerializationField{},
		Vocab:             map[string]string{},
	}

	claimContext.ID = claimSchemaData.Context["id"].(string)
	claimContext.Protected = claimSchemaData.Context["@protected"].(bool)
	claimContext.Type = claimSchemaData.Context["type"].(string)
	claimContext.Version = claimSchemaData.Context["@version"].(float64)

	for k, v := range claimSchemaData.Context {
		switch schemaField := v.(type) {
		case map[string]interface{}:
			b, err := json.Marshal(schemaField)
			if err != nil {
				return nil, err
			}
			var f SerializationField
			err = json.Unmarshal(b, &f)
			if err != nil {
				return nil, err
			}
			claimContext.Fields[k] = f
		case string:
			if isVocabField(k, []string{"id", "@protected", "type", "@version"}) {
				claimContext.Vocab[k] = schemaField
			}
		default:
			continue
		}
	}

	return &claimContext, nil
}
