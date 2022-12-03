package json

import (
	"context"
	"encoding/json"
	"fmt"

	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-schema-processor/processor"
	"github.com/iden3/go-schema-processor/utils"
	"github.com/iden3/go-schema-processor/verifiable"
	"github.com/pkg/errors"
)

// SerializationSchema Common JSON
type SerializationSchema struct {
	IndexDataSlotA string `json:"indexDataSlotA"`
	IndexDataSlotB string `json:"indexDataSlotB"`
	ValueDataSlotA string `json:"valueDataSlotA"`
	ValueDataSlotB string `json:"valueDataSlotB"`
}

// SchemaMetadata is metadata of json schema
type SchemaMetadata struct {
	Uris          map[string]interface{} `json:"uris"`
	Serialization *SerializationSchema   `json:"serialization"`
}

type Schema struct {
	Metadata *SchemaMetadata `json:"$metadata"`
	Schema   string          `json:"$schema"`
	Type     string          `json:"type"`
}

// Parser can parse claim data according to specification
type Parser struct {
}

// ParseClaim creates Claim object from W3CCredential
func (s Parser) ParseClaim(ctx context.Context, credential verifiable.W3CCredential, credentialType string,
	jsonSchemaBytes []byte, opts *processor.CoreClaimOptions) (*core.Claim, error) {

	if opts == nil {
		opts = &processor.CoreClaimOptions{
			RevNonce:              0,
			Version:               0,
			SubjectPosition:       "index",
			MerklizedRootPosition: "none",
			Updatable:             false,
		}
	}

	subjectID := credential.CredentialSubject["id"]

	slots, err := s.ParseSlots(credential, jsonSchemaBytes)
	if err != nil {
		return nil, err
	}

	claim, err := core.NewClaim(
		utils.CreateSchemaHash([]byte(credentialType)),
		core.WithIndexDataBytes(slots.IndexA, slots.IndexB),
		core.WithValueDataBytes(slots.ValueA, slots.ValueB),
		core.WithRevocationNonce(opts.RevNonce),
		core.WithVersion(opts.Version))

	if opts.Updatable {
		claim.SetFlagUpdatable(opts.Updatable)
	}
	if err != nil {
		return nil, err
	}
	if credential.Expiration != nil {
		claim.SetExpirationDate(*credential.Expiration)
	}
	if subjectID != nil {
		var did *core.DID
		did, err = core.ParseDID(fmt.Sprintf("%v", subjectID))
		if err != nil {
			return nil, err
		}

		switch opts.SubjectPosition {
		case "", utils.SubjectPositionIndex:
			claim.SetIndexID(did.ID)
		case utils.SubjectPositionValue:
			claim.SetValueID(did.ID)
		default:
			return nil, errors.New("unknown subject position")
		}
	}

	switch opts.MerklizedRootPosition {
	case utils.MerklizedRootPositionIndex:
		mkRoot, err := credential.Merklize(ctx)
		if err != nil {
			return nil, err
		}
		err = claim.SetIndexMerklizedRoot(mkRoot.Root().BigInt())
		if err != nil {
			return nil, err
		}
	case utils.MerklizedRootPositionValue:
		mkRoot, err := credential.Merklize(ctx)
		if err != nil {
			return nil, err
		}
		err = claim.SetValueMerklizedRoot(mkRoot.Root().BigInt())
		if err != nil {
			return nil, err
		}
	case utils.MerklizedRootPositionNone:
		break
	default:
		return nil, errors.New("unknown merklized root position")
	}

	return claim, nil
}

// ParseSlots converts payload to claim slots using provided schema
func (s Parser) ParseSlots(credential verifiable.W3CCredential, schemaBytes []byte) (processor.ParsedSlots, error) {

	var schema Schema

	err := json.Unmarshal(schemaBytes, &schema)
	if err != nil {
		return processor.ParsedSlots{}, err
	}

	if schema.Metadata != nil && schema.Metadata.Serialization != nil {
		return s.assignSlots(credential.CredentialSubject, *schema.Metadata.Serialization)
	}

	return processor.ParsedSlots{
		IndexA: make([]byte, 0, 32),
		IndexB: make([]byte, 0, 32),
		ValueA: make([]byte, 0, 32),
		ValueB: make([]byte, 0, 32),
	}, nil

}

// GetFieldSlotIndex return index of slot from 0 to 7 (each claim has by default 8 slots)
func (s Parser) GetFieldSlotIndex(field string, schemaBytes []byte) (int, error) {

	var schema Schema

	err := json.Unmarshal(schemaBytes, &schema)
	if err != nil {
		return 0, err
	}

	if schema.Metadata == nil || schema.Metadata.Serialization == nil {
		return -1, errors.New("serialization info is not set")
	}

	switch field {
	case schema.Metadata.Serialization.IndexDataSlotA:
		return 2, nil
	case schema.Metadata.Serialization.IndexDataSlotB:
		return 3, nil
	case schema.Metadata.Serialization.ValueDataSlotA:
		return 6, nil
	case schema.Metadata.Serialization.ValueDataSlotB:
		return 7, nil
	default:
		return -1, errors.Errorf("field `%s` not specified in serialization info", field)
	}
}

// assignSlots assigns index and value fields to specific slot according array order
func (s Parser) assignSlots(data map[string]interface{}, schema SerializationSchema) (processor.ParsedSlots, error) {

	var err error
	result := processor.ParsedSlots{
		IndexA: make([]byte, 0, 32),
		IndexB: make([]byte, 0, 32),
		ValueA: make([]byte, 0, 32),
		ValueB: make([]byte, 0, 32),
	}

	result.IndexA, err = fillSlot(data, schema.IndexDataSlotA)
	if err != nil {
		return result, err
	}
	result.IndexB, err = fillSlot(data, schema.IndexDataSlotB)
	if err != nil {
		return result, err
	}
	result.ValueA, err = fillSlot(data, schema.ValueDataSlotB)
	if err != nil {
		return result, err
	}
	result.ValueB, err = fillSlot(data, schema.ValueDataSlotB)
	if err != nil {
		return result, err
	}

	return result, nil
}

func fillSlot(data map[string]interface{}, fieldName string) ([]byte, error) {
	slot := make([]byte, 0, 32)

	if fieldName == "" {
		return slot, nil
	}
	field, ok := data[fieldName]
	if !ok {
		return slot, errors.Errorf("%s field is not in data", fieldName)
	}
	byteValue, err := utils.FieldToByteArray(field)
	if err != nil {
		return nil, err
	}
	if utils.DataFillsSlot(slot, byteValue) {
		slot = append(slot, byteValue...)
	} else {
		return nil, processor.ErrSlotsOverflow
	}
	return slot, nil
}
