package json

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"strings"

	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-iden3-core/v2/w3c"
	"github.com/iden3/go-schema-processor/v2/merklize"
	"github.com/iden3/go-schema-processor/v2/processor"
	"github.com/iden3/go-schema-processor/v2/utils"
	"github.com/iden3/go-schema-processor/v2/verifiable"
	"github.com/piprate/json-gold/ld"
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
// TODO: remove jsonSchemaBytes
// TODO: remove credentialType (get the same way as in parseSlots)
func (s Parser) ParseClaim(ctx context.Context, credential verifiable.W3CCredential, credentialType string,
	jsonSchemaBytes []byte, opts *processor.CoreClaimOptions) (*core.Claim, error) {

	if opts == nil {
		opts = &processor.CoreClaimOptions{
			RevNonce:              0,
			Version:               0,
			SubjectPosition:       verifiable.CredentialSubjectPositionIndex,
			MerklizedRootPosition: verifiable.CredentialMerklizedRootPositionNone,
			Updatable:             false,
			MerklizerOpts:         nil,
		}
	}

	subjectID := credential.CredentialSubject["id"]

	slots, err := s.parseSlots(credential, jsonSchemaBytes)
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
		var did *w3c.DID
		did, err = w3c.ParseDID(fmt.Sprintf("%v", subjectID))
		if err != nil {
			return nil, err
		}

		id, err := core.IDFromDID(*did)
		if err != nil {
			return nil, err
		}

		switch opts.SubjectPosition {
		case "", verifiable.CredentialSubjectPositionIndex:
			claim.SetIndexID(id)
		case verifiable.CredentialSubjectPositionValue:
			claim.SetValueID(id)
		default:
			return nil, errors.New("unknown subject position")
		}
	}

	switch opts.MerklizedRootPosition {
	case verifiable.CredentialMerklizedRootPositionIndex:
		mkRoot, err := credential.Merklize(ctx, opts.MerklizerOpts...)
		if err != nil {
			return nil, err
		}
		err = claim.SetIndexMerklizedRoot(mkRoot.Root().BigInt())
		if err != nil {
			return nil, err
		}
	case verifiable.CredentialMerklizedRootPositionValue:
		mkRoot, err := credential.Merklize(ctx, opts.MerklizerOpts...)
		if err != nil {
			return nil, err
		}
		err = claim.SetValueMerklizedRoot(mkRoot.Root().BigInt())
		if err != nil {
			return nil, err
		}
	case verifiable.CredentialMerklizedRootPositionNone:
		break
	default:
		return nil, errors.New("unknown merklized root position")
	}

	return claim, nil
}

func logI(i any, n int) {
	ib, err := json.MarshalIndent(i, "", "    ")
	if err != nil {
		panic(err)
	}

	log.Printf("[%v] %v", n, string(ib))
}

// Get @serialization attr definition from context document either using
// type name like DeliverAddressMultiTestForked or by type id like
// urn:uuid:ac2ede19-b3b9-454d-b1a9-a7b3d5763100.
func getSerializationAttr(doc any, opts *ld.JsonLdOptions,
	tp string) (string, error) {

	docM, ok := doc.(map[string]any)
	if !ok {
		return "", errors.New("document is not an object")
	}

	docCtx, ok := docM["@context"]
	if !ok {
		return "", errors.New("no @context in document")
	}

	ldCtx, err := ld.NewContext(nil, opts).Parse(docCtx)
	if err != nil {
		return "", err
	}

	termDef, ok := ldCtx.AsMap()["termDefinitions"]
	if !ok {
		return "", errors.New("types now found in context")
	}

	termDefM, ok := termDef.(map[string]any)
	if !ok {
		return "", errors.New("terms definitions is not of correct type")
	}

	for typeName, typeDef := range termDefM {
		typeDefM, ok := typeDef.(map[string]any)
		if !ok {
			// not a type
			continue
		}
		typeCtx, ok := typeDefM["@context"]
		if !ok {
			// not a type
			continue
		}
		typeCtxM, ok := typeCtx.(map[string]any)
		if !ok {
			return "", errors.New("type @context is not of correct type")
		}
		typeID, _ := typeDefM["@id"].(string)
		if typeName != tp && typeID != tp {
			continue
		}

		serStr, _ := typeCtxM["@serialization"].(string)
		return serStr, nil
	}

	return "", nil
}

func expandDoc(doc any, options *ld.JsonLdOptions) (any, error) {
	proc := ld.NewJsonLdProcessor()
	return proc.Expand(doc, options)
}

type jsonObj struct {
	obj any
	err error
}

// assert that jsonObj is a list of length 1 and return the first element
func (j *jsonObj) uniqObjFromList() *jsonObj {
	if j.err != nil {
		return &jsonObj{err: j.err}
	}

	l, isList := j.obj.([]any)
	if !isList {
		return &jsonObj{err: errors.New("not a list")}
	}

	if len(l) != 1 {
		return &jsonObj{err: errors.New("list is not of length 1")}
	}

	return &jsonObj{obj: l[0]}
}

// assert that jsonObj is an object and return the value by key
func (j *jsonObj) valueByKey(key string) *jsonObj {
	if j.err != nil {
		return &jsonObj{err: j.err}
	}

	m, isMap := j.obj.(map[string]any)
	if !isMap {
		return &jsonObj{err: errors.New("not a map")}
	}

	v, ok := m[key]
	if !ok {
		return &jsonObj{err: errors.New("key not found")}
	}

	return &jsonObj{obj: v}
}

// assert that jsonObj is a string and return it.
func (j *jsonObj) toString() (string, error) {
	if j.err != nil {
		return "", j.err
	}

	s, isStr := j.obj.(string)
	if !isStr {
		return "", errors.New("not a string")
	}

	return s, nil
}

type slotsPaths struct {
	indexAPath string
	indexBPath string
	valueAPath string
	valueBPath string
}

func (p slotsPaths) isEmpty() bool {
	return p.indexAPath == "" && p.indexBPath == "" &&
		p.valueAPath == "" && p.valueBPath == ""
}

func parseSerializationAttr(serAttr string) (slotsPaths, error) {
	prefix := "iden3:v1:"
	if !strings.HasPrefix(serAttr, prefix) {
		return slotsPaths{},
			errors.New("serialization attribute does not have correct prefix")
	}
	parts := strings.Split(serAttr[len(prefix):], "&")
	if len(parts) > 4 {
		return slotsPaths{},
			errors.New("serialization attribute has too many parts")
	}
	var paths slotsPaths
	for _, part := range parts {
		kv := strings.Split(part, "=")
		if len(kv) != 2 {
			return slotsPaths{}, errors.New(
				"serialization attribute part does not have correct format")
		}
		switch kv[0] {
		case "slotIndexA":
			paths.indexAPath = kv[1]
		case "slotIndexB":
			paths.indexBPath = kv[1]
		case "slotValueA":
			paths.valueAPath = kv[1]
		case "slotValueB":
			paths.valueBPath = kv[1]
		default:
			return slotsPaths{},
				errors.New("unknown serialization attribute slot")
		}
	}
	return paths, nil
}

func jsonDocToReader(doc any) (io.Reader, error) {
	b, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(b), nil
}

func (s Parser) assignSlots2(ctx context.Context,
	credential verifiable.W3CCredential) (processor.ParsedSlots, error) {

	slots := processor.ParsedSlots{
		IndexA: make([]byte, 32),
		IndexB: make([]byte, 32),
		ValueA: make([]byte, 32),
		ValueB: make([]byte, 32),
	}

	var doc any = map[string]any{
		"@context":          anySlice(credential.Context),
		"@type":             anySlice(credential.Type),
		"credentialSubject": credential.CredentialSubject,
	}
	logI(doc, 1)

	options := ld.NewJsonLdOptions("")
	options.Algorithm = ld.AlgorithmURDNA2015
	options.SafeMode = true

	expandedDoc, err := expandDoc(doc, options)
	if err != nil {
		return slots, err
	}

	subKey := "https://www.w3.org/2018/credentials#credentialSubject"
	// TODO: find type another way by looking to type in upper level.
	typeID, err := (&jsonObj{obj: expandedDoc}).
		uniqObjFromList().
		valueByKey(subKey).
		uniqObjFromList().
		valueByKey("@type").
		uniqObjFromList().
		toString()
	if err != nil {
		return slots, err
	}

	log.Printf("[20] %v", typeID)

	serAddr, err := getSerializationAttr(doc, options, typeID)
	if err != nil {
		return slots, err
	}

	log.Printf("[21] %v", serAddr)
	if serAddr == "" {
		return slots, nil
	}

	sPaths, err := parseSerializationAttr(serAddr)
	if err != nil {
		return slots, err
	}

	log.Printf("[22] %#v", sPaths)

	if sPaths.isEmpty() {
		return slots, nil
	}

	docReader, err := jsonDocToReader(doc)
	if err != nil {
		return slots, err
	}
	mz, err := merklize.MerklizeJSONLD(ctx, docReader)
	if err != nil {
		return slots, err
	}
	err = fillSlot2(slots.IndexA, mz, sPaths.indexAPath)
	if err != nil {
		return slots, err
	}
	err = fillSlot2(slots.IndexB, mz, sPaths.indexBPath)
	if err != nil {
		return slots, err
	}
	err = fillSlot2(slots.ValueA, mz, sPaths.valueAPath)
	if err != nil {
		return slots, err
	}
	err = fillSlot2(slots.ValueB, mz, sPaths.valueBPath)
	if err != nil {
		return slots, err
	}

	return slots, nil
}

func fillSlot2(slotData []byte, mz *merklize.Merklizer, path string) error {
	if path == "" {
		return nil
	}
	path = "credentialSubject." + path
	p, err := mz.ResolveDocPath(path)
	if err != nil {
		return err
	}
	log.Printf("[23] %v", p)
	entry, err := mz.Entry(p)
	if err != nil {
		return err
	}
	log.Printf("[24] %v", entry)

	intVal, err := entry.ValueMtEntry()
	if err != nil {
		return err
	}
	bytesVal := utils.SwapEndianness(intVal.Bytes())
	copy(slotData, bytesVal)
	return nil
}

// parseSlots converts payload to claim slots using provided schema
// TODO: break, make private
func (s Parser) parseSlots(credential verifiable.W3CCredential, schemaBytes []byte) (processor.ParsedSlots, error) {

	if len(schemaBytes) > 0 {
		var schema Schema

		err := json.Unmarshal(schemaBytes, &schema)
		if err != nil {
			return processor.ParsedSlots{}, err
		}

		if schema.Metadata != nil && schema.Metadata.Serialization != nil {
			return s.assignSlots(credential.CredentialSubject,
				*schema.Metadata.Serialization)
		}
	}

	ctx := context.TODO()
	return s.assignSlots2(ctx, credential)
}

// convert from the slice of concrete type to the slice of interface{}
func anySlice[T any](in []T) []any {
	if in == nil {
		return nil
	}
	s := make([]any, len(in))
	for i := range in {
		s[i] = in[i]
	}
	return s
}

// GetFieldSlotIndex return index of slot from 0 to 7 (each claim has by default 8 slots)
// TODO: pass options too.
// TODO: may be pass ctx for future use in ld.Parse
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
	// TODO: Make support for other types as with merklized.
	//       (?) should we change anything here for old json-schema shit?
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
