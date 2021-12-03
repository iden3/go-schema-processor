package jsonld

import (
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
)

// Validator is responsible for document verification
type Validator struct {
	ClaimType string
}

// ValidateData validates JSON data by JSON-LD Schema
func (v Validator) ValidateData(data, schema []byte) error {

	claimContext, err := getClaimContext(v.ClaimType, schema)
	if err != nil {
		return err
	}
	var dataMap map[string]interface{}
	err = json.Unmarshal(data, &dataMap)
	if err != nil {
		return err
	}
	for schemaField := range claimContext.Fields {
		_, ok := dataMap[schemaField]
		if !ok {
			return fmt.Errorf("field %s is missign in the payload, but required in schema", schemaField)
		}
		// TODO: later we can check the type of data field
		// use claimContext.Fields["schemaField"].Type
	}
	//TODO: validate positioned data

	return nil
}

// ValidateDocument validates JSON data by JSON-LD Schema
func (v Validator) ValidateDocument(doc, schema []byte) error {
	return errors.New("not implemented")
}
