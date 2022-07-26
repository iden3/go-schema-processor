package jsonld

import (
	"context"
	commonJSON "encoding/json"
	"math/big"
	"testing"

	"github.com/iden3/go-schema-processor/json"
	jsonld "github.com/iden3/go-schema-processor/json-ld"
	"github.com/iden3/go-schema-processor/loaders"
	"github.com/iden3/go-schema-processor/processor"
	"github.com/iden3/go-schema-processor/utils"
	"github.com/iden3/go-schema-processor/verifiable"
	"github.com/stretchr/testify/assert"
)

func TestParserWithSimpleData(t *testing.T) {
	url := "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc.json-ld"
	loader := loaders.HTTP{URL: url}
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

func TestParserWithPositionedData(t *testing.T) {
	url := "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc.json-ld"
	loader := loaders.HTTP{URL: url}
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

func TestValidator(t *testing.T) {
	url := "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc.json-ld"
	loader := loaders.HTTP{URL: url}
	validator := jsonld.Validator{Type: "KYCAgeCredential"}

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

func TestValidatorWithInvalidField(t *testing.T) {
	url := "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc.json-ld"
	loader := loaders.HTTP{URL: url}
	validator := jsonld.Validator{Type: "KYCAgeCredential"}

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

func TestValidatorWithPositionedData(t *testing.T) {
	url := "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc.json-ld"
	loader := loaders.HTTP{URL: url}
	validator := jsonld.Validator{Type: "KYCAgeCredential"}

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

func TestParserWithSlotsTypes(t *testing.T) {

	url := "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v2.json-ld"

	loader := loaders.HTTP{URL: url}
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

func TestGetFieldIndexWithSlotsTypes(t *testing.T) {

	url := "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v2.json-ld"

	loader := loaders.HTTP{URL: url}
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

func TestParserForBigIntegers(t *testing.T) {

	url := "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/auth.json-ld"

	loader := loaders.HTTP{URL: url}
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

func TestParserParseClaimWithoutSubjectID(t *testing.T) {

	jsonLDDocument := `{"id":"43a43795-bbf2-4793-8bb3-b2c7adda38c2","@context":["https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential.json-ld","https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/auth.json-ld"],"@type":["Iden3Credential"],"expiration":"2361-03-21T21:14:48+02:00","updatable":false,"version":0,"rev_nonce":2718740429,"credentialSubject":{"type":"AuthBJJCredential","x":"20409658749787088412096793141437101561442676297213277276857597798284501440331","y":"3183003504125265840590980610899311014430663361485132256793125936481857108909"},"credentialStatus":{"id":"http://localhost:8001/api/v1/identities/1129q213BgoVEnnvUGB4TsmNuScS1icbiN2C1RBpPF/claims/revocation/status/2718740429","type":"SparseMerkleTreeProof"},"credentialSchema":{"@id":"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/auth.json-ld","type":"AuthBJJCredential"},"proof":{"@type":"BJJSignature2021","issuer":"1129q213BgoVEnnvUGB4TsmNuScS1icbiN2C1RBpPF","h_index":"c423a3e302df8d1b3acc126b23a7bc670923b7a25bed848df0df77695a15ff26","h_value":"72c0318618293988eb9d7820fb762b09c4f906ac54eebe0108959313a4f8441d","created":1650898704,"issuer_mtp":{"@type":"Iden3SparseMerkleProof","issuer":"1129q213BgoVEnnvUGB4TsmNuScS1icbiN2C1RBpPF","h_index":"b530c7ed22879305e899914ba8a378c713bd023144cb79808a1d2adf4947a517","h_value":"46993eb76d20c1880406798b1b9237092515c2d9949620510ec7196e43fd3205","state":{"claims_tree_root":"f93fd2d63e1961711b996de149efe0a5297e8651203eb42f6a90245e82fa9500","value":"a4b6b022a2b95f34ad63b4ef589ea60282af283e833f26a456588e9b563b1e1e","status":"created"},"mtp":{"existence":true,"siblings":[]}},"verification_method":"93f822075aefe096f69a66e1623bdbf907230c49950ef41738c00f6b91682425","proof_value":"68818ecc8cf007fd07bf82c0c2aa1b456b91d7d560d0a642c442b0e34a6bca245143a99b04c14e2499d2a9009c8a22fb6438f09da55daf10185834e6dcb48604","proof_purpose":"Authentication"}}`
	var vc verifiable.Iden3Credential

	err := commonJSON.Unmarshal([]byte(jsonLDDocument), &vc)
	assert.Nil(t, err)

	credType := vc.CredentialSubject["type"].(string)
	loader := loaders.HTTP{URL: vc.CredentialSchema.ID}
	parser := jsonld.Parser{ClaimType: credType,
		ParsingStrategy: processor.OneFieldPerSlotStrategy}

	schemaBytes, ext, err := loader.Load(context.Background())
	assert.Nil(t, err)
	assert.Equal(t, ext, "json-ld")
	assert.NotEmpty(t, schemaBytes)

	coreClaim, err := parser.ParseClaim(&vc, schemaBytes)
	assert.Nil(t, err)
	_, err = coreClaim.GetID()
	assert.Errorf(t, err, "ID is not set")
	schemaClaimBytes, err := coreClaim.GetSchemaHash().MarshalText()
	assert.Nil(t, err)
	assert.Equal(t, "ca938857241db9451ea329256b9c06e5",
		string(schemaClaimBytes))

	revNonce := coreClaim.GetRevocationNonce()
	assert.Equal(t, vc.RevNonce, revNonce)

	expTime, _ := coreClaim.GetExpirationDate()
	assert.Equal(t, vc.Expiration.Unix(), expTime.Unix())

	updatable := coreClaim.GetFlagUpdatable()
	assert.Equal(t, vc.Updatable, updatable)
}
func TestParserParseClaimWithSubjectID(t *testing.T) {

	jsonLDDocument := `{
  "id": "4102dcf4-9382-443a-8108-959e631b5d2f",
  "@context": [
    "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential.json-ld",
    "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v2.json-ld"
  ],
  "@type": [
    "Iden3Credential"
  ],
  "expiration": "2361-03-21T21:14:48+02:00",
  "updatable": false,
  "version": 0,
  "rev_nonce": 2761125786,
  "credentialSubject": {
    "birthday": 19960424,
    "documentType": 1,
    "id": "118akjaAsZ2i3bSSYEaM88mCMpXAcL6WvpZH68fKZn",
    "type": "KYCAgeCredential"
  },
  "credentialStatus": {
    "id": "http://localhost:8001/api/v1/identities/1129q213BgoVEnnvUGB4TsmNuScS1icbiN2C1RBpPF/claims/revocation/status/2761125786",
    "type": "SparseMerkleTreeProof"
  },
  "credentialSchema": {
    "@id": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v2.json-ld",
    "type": "KYCAgeCredential"
  },
  "proof": [
    {
      "@type": "BJJSignature2021",
      "issuer": "1129q213BgoVEnnvUGB4TsmNuScS1icbiN2C1RBpPF",
      "h_index": "2c3a63fb838bbc1809c1e80a19139019fe37b24b1623ce2daba44183872cc41d",
      "h_value": "463b48e77f0661d31a56f61681c97b6223b1412505e3b04c7a4e0b08f3181819",
      "created": 1650898533,
      "issuer_mtp": {
        "@type": "Iden3SparseMerkleProof",
        "issuer": "1129q213BgoVEnnvUGB4TsmNuScS1icbiN2C1RBpPF",
        "h_index": "b530c7ed22879305e899914ba8a378c713bd023144cb79808a1d2adf4947a517",
        "h_value": "46993eb76d20c1880406798b1b9237092515c2d9949620510ec7196e43fd3205",
        "state": {
          "claims_tree_root": "f93fd2d63e1961711b996de149efe0a5297e8651203eb42f6a90245e82fa9500",
          "value": "a4b6b022a2b95f34ad63b4ef589ea60282af283e833f26a456588e9b563b1e1e",
          "status": "created"
        },
        "mtp": {
          "existence": true,
          "siblings": []
        }
      },
      "verification_method": "93f822075aefe096f69a66e1623bdbf907230c49950ef41738c00f6b91682425",
      "proof_value": "842a7044245669d898bb42106573469fa3e56805eaeab78cbd06ecda0cd82490a1c03d3438705a764b5cef11d764c16d17dd86d9463966c703286ccb80139d00",
      "proof_purpose": "Authentication"
    },
    {
      "@type": "Iden3SparseMerkleProof",
      "issuer": "1129q213BgoVEnnvUGB4TsmNuScS1icbiN2C1RBpPF",
      "h_index": "2c3a63fb838bbc1809c1e80a19139019fe37b24b1623ce2daba44183872cc41d",
      "h_value": "463b48e77f0661d31a56f61681c97b6223b1412505e3b04c7a4e0b08f3181819",
      "state": {
        "tx_id": "0x7482579da9942ce9c218174fb509ab15fa9f94e70cb29d63cb7072b306b3b866",
        "block_timestamp": 1650900717,
        "block_number": 26082637,
        "root_of_roots": "ffa2d0eec32ee4588b5fdac7aaa2d136d5d3ab96bb25d8507570a391dfd14922",
        "claims_tree_root": "682409da4fdaf072f30314e0578848662975d2d3aa967a46b0b678745368e12b",
        "revocation_tree_root": "0000000000000000000000000000000000000000000000000000000000000000",
        "value": "0d3a999d58f26f1ccc21bbe745ee9d62efdc618613caf930009c533e2e56831f",
        "status": "confirmed"
      },
      "mtp": {
        "existence": true,
        "siblings": [
          "264989163946140659119067438613111086251856808194270247179339188846199980025",
          "0",
          "0",
          "412703772382477972262931479259998079304255691105270144442886052862988158651"
        ]
      }
    }
  ]
}`
	var vc verifiable.Iden3Credential

	err := commonJSON.Unmarshal([]byte(jsonLDDocument), &vc)
	assert.Nil(t, err)

	credType := vc.CredentialSubject["type"].(string)
	subjectID := vc.CredentialSubject["id"].(string)

	loader := loaders.HTTP{URL: vc.CredentialSchema.ID}
	parser := jsonld.Parser{ClaimType: credType,
		ParsingStrategy: processor.OneFieldPerSlotStrategy}

	schemaBytes, ext, err := loader.Load(context.Background())
	assert.Nil(t, err)
	assert.Equal(t, ext, "json-ld")
	assert.NotEmpty(t, schemaBytes)

	coreClaim, err := parser.ParseClaim(&vc, schemaBytes)
	assert.Nil(t, err)
	id, err := coreClaim.GetID()
	assert.Nil(t, err)
	assert.Equal(t, subjectID, id.String())
}
