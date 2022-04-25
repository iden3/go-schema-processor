package jsonld

import (
	"context"
	commonJSON "encoding/json"
	schemaUtils "github.com/iden3/go-schema-processor/utils"
	"math/big"
	"testing"

	"github.com/iden3/go-iden3-crypto/utils"
	"github.com/iden3/go-schema-processor/json"
	jsonld "github.com/iden3/go-schema-processor/json-ld"
	"github.com/iden3/go-schema-processor/loaders"
	"github.com/iden3/go-schema-processor/processor"
	"github.com/iden3/go-schema-processor/verifiable"
	"github.com/stretchr/testify/assert"
)

func getIPFSLoader(t string) processor.SchemaLoader {
	var cid string

	switch t {
	case "kyc":
		cid = "QmaniifmAkPfmTkpNzVQPcdn4Bu5LuNx1qn1dpNFmU6en6"
	case "kyc-v2":
		cid = "QmP8NrKqoBKjmKwMsC8pwBCBxXR2PhwSepwXx31gnJxAbP"
	case "auth":
		cid = "QmWf7fD5txHaMH1zhrWUKSVvACgTLLqcdWbFPqQkKHa9yJ"
	default:
		cid = ""
	}
	return &loaders.IPFS{
		CID: cid,
		URL: "https://25CLrk5mJXWhONKzbMQtQHEvepN:888f2b0d89b97887358b6a762ba9d95f@ipfs.infura.io:5001",
	}
}

func TestParserWithSimpleDataIPFSLoader(t *testing.T) {
	loader := getIPFSLoader("kyc")
	validator := json.Validator{}
	parser := jsonld.Parser{ClaimType: "KYCAgeCredential",
		ParsingStrategy: processor.SlotFullfilmentStrategy}

	jsonLdProcessor := New(processor.WithValidator(validator),
		processor.WithParser(parser), processor.WithSchemaLoader(loader))
	schema, ext, err := jsonLdProcessor.Load(context.Background())

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
	expetctedSlotA := []uint8{24, 4, 204, 7, 1}

	t.Log(parsedData.IndexA)
	assert.Nil(t, err)
	assert.NotEmpty(t, parsedData.IndexA)
	assert.Equal(t, expetctedSlotA, parsedData.IndexA)

	assert.Empty(t, parsedData.IndexB)
	assert.Empty(t, parsedData.ValueA)
	assert.Empty(t, parsedData.ValueB)

}

func TestParserWithPositionedDataPFSLoader(t *testing.T) {
	loader := getIPFSLoader("kyc")
	validator := json.Validator{}
	parser := jsonld.Parser{ClaimType: "KYCAgeCredential",
		ParsingStrategy: processor.SlotFullfilmentStrategy}

	jsonLdProcessor := New(processor.WithValidator(validator),
		processor.WithParser(parser), processor.WithSchemaLoader(loader))
	schema, ext, err := jsonLdProcessor.Load(context.Background())

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

	exptectedSlotA := []uint8{24, 4, 204, 7, 1}

	assert.Nil(t, err)
	assert.NotEmpty(t, parsedData.IndexA)
	assert.Equal(t, exptectedSlotA, parsedData.IndexA)
	assert.Empty(t, parsedData.IndexB)
	assert.Empty(t, parsedData.ValueA)
	assert.Empty(t, parsedData.ValueB)

}

func TestValidatorPFSLoader(t *testing.T) {

	loader := getIPFSLoader("kyc")
	validator := jsonld.Validator{ClaimType: "KYCAgeCredential"}

	p := New(processor.WithValidator(validator),
		processor.WithSchemaLoader(loader))

	schema, ext, err := p.Load(context.Background())

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

func TestValidatorWithInvalidFieldIPFSLoader(t *testing.T) {

	loader := getIPFSLoader("kyc")
	validator := jsonld.Validator{ClaimType: "KYCAgeCredential"}

	p := New(processor.WithValidator(validator),
		processor.WithSchemaLoader(loader))

	schema, ext, err := p.Load(context.Background())

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
	assert.Containsf(t, err.Error(),
		"field birthdayYear is missign in the payload, but required in schema",
		"expected error containing %q, got %s",
		"\"birthdayYear\" value is required", err)

}

func TestValidatorWithPositionedDataIPFSLoader(t *testing.T) {

	loader := getIPFSLoader("kyc")
	validator := jsonld.Validator{ClaimType: "KYCAgeCredential"}

	p := New(processor.WithValidator(validator),
		processor.WithSchemaLoader(loader))

	schema, ext, err := p.Load(context.Background())

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

func TestParserWithSlotsTypesIPFSLoader(t *testing.T) {

	loader := getIPFSLoader("kyc-v2")
	validator := json.Validator{}
	parser := jsonld.Parser{ClaimType: "KYCAgeCredential",
		ParsingStrategy: processor.OneFieldPerSlotStrategy}

	jsonLdProcessor := New(processor.WithValidator(validator),
		processor.WithParser(parser), processor.WithSchemaLoader(loader))
	schema, ext, err := jsonLdProcessor.Load(context.Background())

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
	expetctedSlotB := []uint8{1}

	t.Log(parsedData.IndexA)
	assert.Nil(t, err)
	assert.NotEmpty(t, parsedData.IndexA)
	assert.Equal(t, expetctedSlotA, parsedData.IndexA)
	assert.Equal(t, expetctedSlotB, parsedData.IndexB)

	assert.Empty(t, parsedData.ValueA)
	assert.Empty(t, parsedData.ValueB)

}

func TestGetFieldIndexWithSlotsTypesIPFSLoader(t *testing.T) {

	loader := getIPFSLoader("kyc-v2")
	validator := json.Validator{}
	parser := jsonld.Parser{ClaimType: "KYCAgeCredential",
		ParsingStrategy: processor.OneFieldPerSlotStrategy}

	jsonLdProcessor := New(processor.WithValidator(validator),
		processor.WithParser(parser), processor.WithSchemaLoader(loader))
	schema, ext, err := jsonLdProcessor.Load(context.Background())

	assert.Nil(t, err)
	assert.Equal(t, ext, "json-ld")
	assert.NotEmpty(t, schema)

	data := make(map[string]interface{})

	data["birthday"] = 828522341
	data["documentType"] = 1

	slot2, err := jsonLdProcessor.GetFieldSlotIndex("birthday", schema)
	assert.Nil(t, err)
	assert.Equal(t, 2, slot2)
	slot3, err := jsonLdProcessor.GetFieldSlotIndex("documentType", schema)
	assert.Nil(t, err)
	assert.Equal(t, 3, slot3)

}

func TestParserForBigIntegersIPFSLoader(t *testing.T) {

	loader := getIPFSLoader("auth")
	validator := json.Validator{}
	parser := jsonld.Parser{ClaimType: "AuthBJJCredential",
		ParsingStrategy: processor.OneFieldPerSlotStrategy}

	jsonLdProcessor := New(processor.WithValidator(validator),
		processor.WithParser(parser), processor.WithSchemaLoader(loader))
	schema, ext, err := jsonLdProcessor.Load(context.Background())

	assert.Nil(t, err)
	assert.Equal(t, ext, "json-ld")
	assert.NotEmpty(t, schema)

	data := make(map[string]interface{})

	data["x"] = "12747559771369266961976321746772881814229091957322087014312756428846389160887"
	data["y"] = "7732074634595480184356588475330446395691728690271550550016720788712795268212"

	dataBytes, err := commonJSON.Marshal(data)
	assert.Nil(t, err)

	parsedData, err := jsonLdProcessor.ParseSlots(dataBytes, schema)
	assert.Nil(t, err)

	x, _ := new(big.Int).SetString(data["x"].(string), 10)
	y, _ := new(big.Int).SetString(data["y"].(string), 10)

	expetctedSlotA := utils.SwapEndianness(x.Bytes())
	expetctedSlotB := utils.SwapEndianness(y.Bytes())

	assert.Nil(t, err)
	assert.NotEmpty(t, parsedData.IndexA)
	assert.Equal(t, expetctedSlotA, parsedData.IndexA)
	assert.Equal(t, expetctedSlotB, parsedData.IndexB)

	assert.Empty(t, parsedData.ValueA)
	assert.Empty(t, parsedData.ValueB)
}

func TestParserParseClaimWithSubjectIDPFSLoader(t *testing.T) {

	jsonLDDocument := `{"id":"e65a0bfb-d1a0-4f8d-bbd4-7705a17f6b5d","@context":["https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential.json-ld","ipfs://QmP8NrKqoBKjmKwMsC8pwBCBxXR2PhwSepwXx31gnJxAbP"],"@type":["Iden3Credential"],"expiration":"2361-03-21T21:14:48+02:00","updatable":false,"version":0,"rev_nonce":1427136406,"credentialSubject":{"countryCode":980,"documentType":1,"id":"116iPg7dwEP5VqNr1DHQKo4JRbypL2ccJryV3626yV","type":"KYCCountryOfResidenceCredential"},"credentialStatus":{"id":"http://localhost:8001/api/v1/identities/118HT4DprVZDh1hwxNbgXvj3WYfs7aJMejdKBCr3fz/claims/revocation/status/1427136406","type":"SparseMerkleTreeProof"},"credentialSchema":{"@id":"ipfs://QmP8NrKqoBKjmKwMsC8pwBCBxXR2PhwSepwXx31gnJxAbP","type":"KYCCountryOfResidenceCredential"},"proof":{"@type":"BJJSignature2021","issuer":"118HT4DprVZDh1hwxNbgXvj3WYfs7aJMejdKBCr3fz","h_index":"6e43eefcb286da6410752683af39ac01fe4c2b71bb6bc33153f817c1ff72b323","h_value":"095192dcc00fc43d0df69c59905b150376c317a92f0f29e5cb958cd2856b8908","created":1650903921,"issuer_mtp":{"@type":"Iden3SparseMerkleProof","issuer":"118HT4DprVZDh1hwxNbgXvj3WYfs7aJMejdKBCr3fz","h_index":"90feb35f5b65f0b51d24d88a933dd6bde9809dc0d5bfe1f48219864036e61105","h_value":"46993eb76d20c1880406798b1b9237092515c2d9949620510ec7196e43fd3205","state":{"claims_tree_root":"4a215db950a071439fee5c2d4862d6fab89c2f7b1e06735e1c23e96b0584142e","value":"c4000e554cc3a6a725e0298b816e1952c3b1681bbed44e0a84fc6957b908900f","status":"created"},"mtp":{"existence":true,"siblings":[]}},"verification_method":"d2050abbe1e4d788621e5e54ef0e40081d3e1a1e5753b08e159608f60eb48715","proof_value":"6b3b95fa5365df397cb2d0d638fc2d9ec2e7bb687937a50d3c9aa8820343c01c80821f66eea8c706cf836040e7b58dc85513b3aad99abbc7067cbe1ee6a36701","proof_purpose":"Authentication"}}`
	var vc verifiable.Iden3Credential

	err := commonJSON.Unmarshal([]byte(jsonLDDocument), &vc)
	assert.Nil(t, err)

	credType := vc.CredentialSubject["type"].(string)
	subjectID := vc.CredentialSubject["id"].(string)
	parser := jsonld.Parser{ClaimType: credType,
		ParsingStrategy: processor.OneFieldPerSlotStrategy}

	loader := getIPFSLoader("kyc-v2")
	schemaBytes, ext, err := loader.Load(context.Background())
	assert.Nil(t, err)
	assert.Equal(t, ext, "json-ld")
	assert.NotEmpty(t, schemaBytes)

	coreClaim, err := parser.ParseClaim(&vc, schemaBytes)
	assert.Nil(t, err)
	id, err := coreClaim.GetID()
	assert.Nil(t, err)
	assert.Equal(t, subjectID, id.String())

	schemaClaimBytes, err := coreClaim.GetSchemaHash().MarshalText()
	assert.Nil(t, err)
	assert.Equal(t, "ce38102464833febf36e714922a83050",
		string(schemaClaimBytes))

	revNonce := coreClaim.GetRevocationNonce()
	assert.Equal(t, vc.RevNonce, revNonce)

	expTime, _ := coreClaim.GetExpirationDate()
	assert.Equal(t, vc.Expiration.Unix(), expTime.Unix())

	updatable := coreClaim.GetFlagUpdatable()
	assert.Equal(t, vc.Updatable, updatable)

	err = schemaUtils.VerifyClaimHash(&vc, coreClaim)
	assert.Nil(t, err)
}
