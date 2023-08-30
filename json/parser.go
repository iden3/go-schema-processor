package json

import (
	"context"
	"encoding/json"
	"fmt"
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

const (
	credentialSubjectKey = "credentialSubject"
	//nolint:gosec // G101: this is not a hardcoded credential
	credentialSubjectFullKey = "https://www.w3.org/2018/credentials#credentialSubject"
	//nolint:gosec // G101: this is not a hardcoded credential
	verifiableCredentialFullKey = "https://www.w3.org/2018/credentials#VerifiableCredential"
	typeFullKey                 = "@type"
	contextFullKey              = "@context"
	serializationFullKey        = "iden3_serialization"
)

// Parser can parse claim data according to specification
type Parser struct {
}

// ParseClaim creates Claim object from W3CCredential
func (s Parser) ParseClaim(ctx context.Context,
	credential verifiable.W3CCredential,
	opts *processor.CoreClaimOptions) (*core.Claim, error) {

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

	mz, err := credential.Merklize(ctx, opts.MerklizerOpts...)
	if err != nil {
		return nil, err
	}

	credentialType, err := findCredentialType(mz)
	if err != nil {
		return nil, err
	}

	subjectID := credential.CredentialSubject["id"]

	slots, nonMerklized, err := s.parseSlots(mz, credential, credentialType)
	if err != nil {
		return nil, err
	}

	// if schema is for non merklized credential, root position must be set to none ('')
	// otherwise default position for merklized position is index.
	if !nonMerklized {
		if opts.MerklizedRootPosition == verifiable.CredentialMerklizedRootPositionNone {
			opts.MerklizedRootPosition = verifiable.CredentialMerklizedRootPositionIndex
		}
	} else {
		if opts.MerklizedRootPosition != verifiable.CredentialMerklizedRootPositionNone {
			return nil, errors.New(
				"merklized root position is not supported for non-merklized claims")
		}
	}

	claim, err := core.NewClaim(
		utils.CreateSchemaHash([]byte(credentialType)),
		core.WithIndexDataBytes(slots.IndexA, slots.IndexB),
		core.WithValueDataBytes(slots.ValueA, slots.ValueB),
		core.WithRevocationNonce(opts.RevNonce),
		core.WithVersion(opts.Version))
	if err != nil {
		return nil, err
	}
	if opts.Updatable {
		claim.SetFlagUpdatable(opts.Updatable)
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

		var id core.ID
		id, err = core.IDFromDID(*did)
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
		err = claim.SetIndexMerklizedRoot(mz.Root().BigInt())
		if err != nil {
			return nil, err
		}
	case verifiable.CredentialMerklizedRootPositionValue:
		err = claim.SetValueMerklizedRoot(mz.Root().BigInt())
		if err != nil {
			return nil, err
		}
	case verifiable.CredentialMerklizedRootPositionNone:
		// Slots where filled earlier. Nothing to do here.
		break
	default:
		return nil, errors.New("unknown merklized root position")
	}

	return claim, nil
}

func getSerializationAttrFromParsedContext(ldCtx *ld.Context,
	tp string) (string, error) {

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
		typeCtx, ok := typeDefM[contextFullKey]
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

		serStr, _ := typeCtxM[serializationFullKey].(string)
		return serStr, nil
	}

	return "", nil
}

// Get `iden3_serialization` attr definition from context document either using
// type name like DeliverAddressMultiTestForked or by type id like
// urn:uuid:ac2ede19-b3b9-454d-b1a9-a7b3d5763100.
func getSerializationAttr(credential verifiable.W3CCredential,
	opts *ld.JsonLdOptions, tp string) (string, error) {

	ldCtx, err := ld.NewContext(nil, opts).Parse(anySlice(credential.Context))
	if err != nil {
		return "", err
	}

	return getSerializationAttrFromParsedContext(ldCtx, tp)
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

func fillSlot(slotData []byte, mz *merklize.Merklizer, path string) error {
	if path == "" {
		return nil
	}

	path = credentialSubjectKey + "." + path
	p, err := mz.ResolveDocPath(path)
	if err != nil {
		return errors.Wrapf(err, "field not found in credential %s", path)
	}

	entry, err := mz.Entry(p)
	if errors.Is(err, merklize.ErrorEntryNotFound) {
		return errors.Wrapf(err, "field not found in credential %s", path)
	} else if err != nil {
		return err
	}

	intVal, err := entry.ValueMtEntry()
	if err != nil {
		return err
	}

	bytesVal := utils.SwapEndianness(intVal.Bytes())
	copy(slotData, bytesVal)
	return nil
}

func findCredentialType(mz *merklize.Merklizer) (string, error) {
	opts := mz.Options()

	// try to look into credentialSubject.@type to get type of credentials
	path1, err := opts.NewPath(credentialSubjectFullKey, typeFullKey)
	if err == nil {
		var e any
		e, err = mz.RawValue(path1)
		if err == nil {
			tp, ok := e.(string)
			if ok {
				return tp, nil
			}
		}
	}

	// if type of credentials not found in credentialSubject.@type, loop at
	// top level @types if it contains two elements: type we are looking for
	// and "VerifiableCredential" type.
	path2, err := opts.NewPath(typeFullKey)
	if err != nil {
		return "", err
	}

	e, err := mz.RawValue(path2)
	if err != nil {
		return "", err
	}

	eArr, ok := e.([]any)
	if !ok {
		return "", fmt.Errorf("top level @type expected to be an array")
	}
	topLevelTypes, err := toStringSlice(eArr)
	if err != nil {
		return "", err
	}
	if len(topLevelTypes) != 2 {
		return "", fmt.Errorf("top level @type expected to be of length 2")
	}

	switch verifiableCredentialFullKey {
	case topLevelTypes[0]:
		return topLevelTypes[1], nil
	case topLevelTypes[1]:
		return topLevelTypes[0], nil
	default:
		return "", fmt.Errorf(
			"@type(s) are expected to contain VerifiableCredential type")
	}
}

// parsedSlots is struct that represents iden3 claim specification
type parsedSlots struct {
	IndexA, IndexB []byte
	ValueA, ValueB []byte
}

// parseSlots converts payload to claim slots using provided schema
func (s Parser) parseSlots(mz *merklize.Merklizer,
	credential verifiable.W3CCredential,
	credentialType string) (parsedSlots, bool, error) {

	slots := parsedSlots{
		IndexA: make([]byte, 32),
		IndexB: make([]byte, 32),
		ValueA: make([]byte, 32),
		ValueB: make([]byte, 32),
	}

	jsonLDOpts := mz.Options().JSONLDOptions()
	serAttr, err := getSerializationAttr(credential, jsonLDOpts,
		credentialType)
	if err != nil {
		return slots, false, err
	}

	if serAttr == "" {
		return slots, false, nil
	}

	sPaths, err := parseSerializationAttr(serAttr)
	if err != nil {
		return slots, true, err
	}

	if sPaths.isEmpty() {
		return slots, true, nil
	}

	err = fillSlot(slots.IndexA, mz, sPaths.indexAPath)
	if err != nil {
		return slots, true, err
	}
	err = fillSlot(slots.IndexB, mz, sPaths.indexBPath)
	if err != nil {
		return slots, true, err
	}
	err = fillSlot(slots.ValueA, mz, sPaths.valueAPath)
	if err != nil {
		return slots, true, err
	}
	err = fillSlot(slots.ValueB, mz, sPaths.valueBPath)
	if err != nil {
		return slots, true, err
	}

	return slots, true, nil
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
func (s Parser) GetFieldSlotIndex(field string, typeName string,
	schemaBytes []byte) (int, error) {

	var ctxDoc any
	err := json.Unmarshal(schemaBytes, &ctxDoc)
	if err != nil {
		return -1, err
	}

	ctxDocM, ok := ctxDoc.(map[string]any)
	if !ok {
		return -1, errors.New("document is not an object")
	}

	ctxDoc, ok = ctxDocM[contextFullKey]
	if !ok {
		return -1, errors.New("document has no @context")
	}

	ldCtx, err := ld.NewContext(nil, nil).Parse(ctxDoc)
	if err != nil {
		return -1, err
	}

	serAttr, err := getSerializationAttrFromParsedContext(ldCtx, typeName)
	if err != nil {
		return -1, err
	}
	if serAttr == "" {
		return -1, errors.Errorf(
			"field `%s` not specified in serialization info", field)
	}

	sPaths, err := parseSerializationAttr(serAttr)
	if err != nil {
		return -1, err
	}

	switch field {
	case sPaths.indexAPath:
		return 2, nil
	case sPaths.indexBPath:
		return 3, nil
	case sPaths.valueAPath:
		return 6, nil
	case sPaths.valueBPath:
		return 7, nil
	default:
		return -1, errors.Errorf(
			"field `%s` not specified in serialization info", field)
	}
}

func toStringSlice(in []any) ([]string, error) {
	out := make([]string, len(in))
	for i, v := range in {
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("element #%v is not a string", i)
		}
		out[i] = s
	}
	return out, nil
}
