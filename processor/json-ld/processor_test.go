package jsonld

import (
	commonJSON "encoding/json"
	"github.com/iden3/go-iden3-crypto/utils"
	"github.com/iden3/go-schema-processor/json"
	jsonld "github.com/iden3/go-schema-processor/json-ld"
	"github.com/iden3/go-schema-processor/loaders"
	"github.com/iden3/go-schema-processor/processor"
	"github.com/iden3/go-schema-processor/verifiable"
	"github.com/stretchr/testify/assert"
	"math/big"
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

	exptectedSlotA := []uint8{24, 4, 204, 7, 1}

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

	slot2, err := jsonLdProcessor.GetFieldSlotIndex("birthday", schema)
	assert.Nil(t, err)
	assert.Equal(t, 2, slot2)
	slot3, err := jsonLdProcessor.GetFieldSlotIndex("documentType", schema)
	assert.Nil(t, err)
	assert.Equal(t, 3, slot3)

}

func TestParserForBigIntegers(t *testing.T) {

	url = "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/auth.json-ld"

	loader := loaders.HTTP{}
	validator := json.Validator{}
	parser := jsonld.Parser{ClaimType: "AuthBJJCredential", ParsingStrategy: processor.OneFieldPerSlotStrategy}

	jsonLdProcessor := New(processor.WithValidator(validator), processor.WithParser(parser), processor.WithSchemaLoader(loader))
	schema, ext, err := jsonLdProcessor.Load(url)

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

	jsonLDDocument := `{"id":"c0f6ac87-603e-44cd-8d83-0caeb458d50d","@context":["https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential.json-ld","https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/auth.json-ld"],"@type":["Iden3Credential"],"expiration":"2361-03-21T21:14:48+02:00","updatable":false,"version":0,"rev_nonce":2034832188220019200,"credentialSubject":{"type":"AuthBJJCredential","x":"12747559771369266961976321746772881814229091957322087014312756428846389160887","y":"7732074634595480184356588475330446395691728690271550550016720788712795268212"},"credentialStatus":{"id":"http://localhost:8001/api/v1/identities/118VhAf6ng6J44FhNrGeYzSbJgGVmcpeXYFR2YTrZ6/claims/revocation/status/2034832188220019081","type":"SparseMerkleTreeProof"},"credentialSchema":{"@id":"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/auth.json-ld","type":"JsonSchemaValidator2018"},"proof":[{"@type":"BJJSignature2021","issuer":"118VhAf6ng6J44FhNrGeYzSbJgGVmcpeXYFR2YTrZ6","h_index":"c89cf5b95157f091f2d8bf49bc1a57cd7988da83bbcd982a74c5e8c70e566403","h_value":"0262b2cd6b9ae44cd9a39045c9bb03ad4e1f056cb81d855f1fc4ef0cdf827912","created":1642518655,"issuer_mtp":{"@type":"Iden3SparseMerkleProof","issuer":"118VhAf6ng6J44FhNrGeYzSbJgGVmcpeXYFR2YTrZ6","h_index":"201a02eb979be695702ea37d930309d2965d803541be5f7b3900459b2fad8726","h_value":"0654da1d53ca201cb42b767a6f12265ff7a08720b88a82182e0f20702479d12d","state":{"claims_tree_root":"a5087cfa6f2c7c565d831327091533f09999133df1df51104d2ce6f8e4d90529","value":"dca344e95da517a301729d94b213298b9de96dfddaf7aad9423d918ea3208820"},"mtp":{"existence":true,"siblings":[]}},"verification_method":"2764e2d8241b18c217010ebf90bebb30240d32c33f3007f33e42d58680813123","proof_value":"c354eb1006534c59766ed8398d49a9a614312e430c5373ea493395db6369d49485e9a0d63f3bfe9fd157294ffbf706b6b7df7a8662a58fae0056a046af1caa04","proof_purpose":"Authentication"},{"@type":"Iden3SparseMerkleProof","issuer":"118VhAf6ng6J44FhNrGeYzSbJgGVmcpeXYFR2YTrZ6","h_index":"c89cf5b95157f091f2d8bf49bc1a57cd7988da83bbcd982a74c5e8c70e566403","h_value":"0262b2cd6b9ae44cd9a39045c9bb03ad4e1f056cb81d855f1fc4ef0cdf827912","state":{"tx_id":"0xf2e23524ab76cb4f371b921a214ff411d5d391962899a2afe20f356e3bdc0c71","block_timestamp":1642522496,"block_number":11837707,"claims_tree_root":"bebcaee8444e93b6e32855f54e9f617d5fd654570badce7d6bc649304169681d","revocation_tree_root":"0000000000000000000000000000000000000000000000000000000000000000","value":"2806aa9a045b2a5503b12f2979b2d19933e803fd3dd73d8ad40dc138bc9a582e"},"mtp":{"existence":true,"siblings":["0","0","0","18555164879275043542501047154170418730098376961920428892719505858997411121317"]}}]}`

	var vc verifiable.Iden3Credential

	err := commonJSON.Unmarshal([]byte(jsonLDDocument), &vc)
	assert.Nil(t, err)

	credType := vc.CredentialSubject["type"].(string)
	loader := loaders.HTTP{}
	parser := jsonld.Parser{ClaimType: credType, ParsingStrategy: processor.OneFieldPerSlotStrategy}

	schemaBytes, ext, err := loader.Load(vc.CredentialSchema.ID)
	assert.Nil(t, err)
	assert.Equal(t, ext, "json-ld")
	assert.NotEmpty(t, schemaBytes)

	coreClaim, err := parser.ParseClaim(&vc, schemaBytes)
	assert.Nil(t, err)
	_, err = coreClaim.GetID()
	assert.Errorf(t, err, "ID is not set")
	schemaClaimBytes, err := coreClaim.GetSchemaHash().MarshalText()
	assert.Equal(t, "7c0844a075a9ddc7fcbdfb4f88acd9bc", string(schemaClaimBytes))

	revNonce := coreClaim.GetRevocationNonce()
	assert.Equal(t, vc.RevNonce, revNonce)

	expTime, _ := coreClaim.GetExpirationDate()
	assert.Equal(t, vc.Expiration.Unix(), expTime.Unix())

	updatable := coreClaim.GetFlagUpdatable()
	assert.Equal(t, vc.Updatable, updatable)

	entry := coreClaim.TreeEntry()

	hIndex, err := entry.HIndex()
	hValue, err := entry.HValue()
	xBigInt, ok := new(big.Int).SetString("12747559771369266961976321746772881814229091957322087014312756428846389160887", 10)
	assert.True(t, ok)
	yBigInt, ok := new(big.Int).SetString("7732074634595480184356588475330446395691728690271550550016720788712795268212", 10)
	assert.True(t, ok)
	assert.Equal(t, "c89cf5b95157f091f2d8bf49bc1a57cd7988da83bbcd982a74c5e8c70e566403", hIndex.Hex())
	assert.Equal(t, "449c53013992e70856c3cb7c7a10ac0b3aa455de305f4af5a93b9ade4592f319", hValue.Hex())
	assert.Equal(t, xBigInt, entry.Index()[2].BigInt())
	assert.Equal(t, yBigInt, entry.Index()[3].BigInt())

}
func TestParserParseClaimWithSubjectID(t *testing.T) {

	jsonLDDocument := `{"id":"2caf3139-7f69-4f9c-a2cb-5a35cff78aab","@context":["https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential.json-ld","https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v2.json-ld"],"@type":["Iden3Credential"],"expiration":"2361-03-21T21:14:48+02:00","updatable":false,"version":0,"rev_nonce":3473370693766599700,"credentialSubject":{"countryCode":980,"documentType":1,"id":"114RrowVvS5fz1XDmTG1EXBuYsruvdYzGByqFBvpHc","type":"KYCCountryOfResidenceCredential"},"credentialStatus":{"id":"http://localhost:8001/api/v1/identities/115mN2C7gh65EpfKt6skXeKGcJ53PACCSGfapzYkAW/claims/revocation/status/3473370693766599916","type":"SparseMerkleTreeProof"},"credentialSchema":{"@id":"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v2.json-ld","type":"JsonSchemaValidator2018"},"proof":[{"@type":"BJJSignature2021","issuer":"115mN2C7gh65EpfKt6skXeKGcJ53PACCSGfapzYkAW","h_index":"6a3978073c5828f2760381ba02b24bdfddf0456a244fe5d485e1135ee472042e","h_value":"1d4895af94c1d4abfe658876f75baf527711d20b130cba4589e879afdaed7520","created":1642497726,"issuer_mtp":{"@type":"Iden3SparseMerkleProof","issuer":"115mN2C7gh65EpfKt6skXeKGcJ53PACCSGfapzYkAW","h_index":"eaa341a91db8b914d61326d9642c35ac2ca4f6dbb1a87609f84b669685141f11","h_value":"46993eb76d20c1880406798b1b9237092515c2d9949620510ec7196e43fd3205","state":{"claims_tree_root":"5ce2c11a4474fe4c6041e5105b0b381c0efb203ef0ce4d88c4ed32d3d8877001","value":"9a47b0353868f5c0ec3eae7a20bab97cbfd789b334424ab41c9bd40c1f762823"},"mtp":{"existence":true,"siblings":[]}},"verification_method":"ddba158931e361d48f195417413a2ec931441847200fe276bcb1648a4e184c1e","proof_value":"40dd0fb06386d78021d999c4b49d659dd90333a64d87d27870297d31188f95948e86ea2d37f605295074f16a837b6a9bc6189d90aaed1be10bcaca06292a4005","proof_purpose":"Authentication"},{"@type":"Iden3SparseMerkleProof","issuer":"115mN2C7gh65EpfKt6skXeKGcJ53PACCSGfapzYkAW","h_index":"6a3978073c5828f2760381ba02b24bdfddf0456a244fe5d485e1135ee472042e","h_value":"1d4895af94c1d4abfe658876f75baf527711d20b130cba4589e879afdaed7520","state":{"tx_id":"0x8537e0645996e34a8115da9a60b307094580e840a030668127393826d61cd0d1","block_timestamp":1642497740,"block_number":11836551,"claims_tree_root":"0511047e551c7e0d2ae1884636fbdf86c1a5a0156938b6ea857a4e34e06a7a0c","revocation_tree_root":"0000000000000000000000000000000000000000000000000000000000000000","value":"c5803aeb2c6d0a357855e070c24fddd5c4ccfef4692cfbf5e1c9068581d53712"},"mtp":{"existence":true,"siblings":["5691303581499283741098849603802493433441417335538778353796518252917364457995","0","0","0","0","0","0","651137301185586690938826662242457730822130240763746109003863565068434268764"]}}]}`

	var vc verifiable.Iden3Credential

	err := commonJSON.Unmarshal([]byte(jsonLDDocument), &vc)
	assert.Nil(t, err)

	credType := vc.CredentialSubject["type"].(string)
	subjectID := vc.CredentialSubject["id"].(string)

	loader := loaders.HTTP{}
	parser := jsonld.Parser{ClaimType: credType, ParsingStrategy: processor.OneFieldPerSlotStrategy}

	schemaBytes, ext, err := loader.Load(vc.CredentialSchema.ID)
	assert.Nil(t, err)
	assert.Equal(t, ext, "json-ld")
	assert.NotEmpty(t, schemaBytes)

	coreClaim, err := parser.ParseClaim(&vc, schemaBytes)
	assert.Nil(t, err)
	id, err := coreClaim.GetID()
	assert.Nil(t, err)
	assert.Equal(t, subjectID, id.String())

	schemaClaimBytes, err := coreClaim.GetSchemaHash().MarshalText()
	assert.Equal(t, "68041e1ca18544ece92e2ad6f17538e4", string(schemaClaimBytes))

	revNonce := coreClaim.GetRevocationNonce()
	assert.Equal(t, vc.RevNonce, revNonce)

	expTime, _ := coreClaim.GetExpirationDate()
	assert.Equal(t, vc.Expiration.Unix(), expTime.Unix())

	updatable := coreClaim.GetFlagUpdatable()
	assert.Equal(t, vc.Updatable, updatable)

	entry := coreClaim.TreeEntry()

	hIndex, err := entry.HIndex()
	hValue, err := entry.HValue()
	xBigInt, ok := new(big.Int).SetString("980", 10)
	assert.True(t, ok)
	yBigInt, ok := new(big.Int).SetString("1", 10)
	assert.True(t, ok)
	assert.Equal(t, "6a3978073c5828f2760381ba02b24bdfddf0456a244fe5d485e1135ee472042e", hIndex.Hex())
	assert.Equal(t, "4da320609775b1caa029c7058f27069eccfb70560c582e8df7319ce54124b00c", hValue.Hex())
	assert.Equal(t, xBigInt, entry.Index()[2].BigInt())
	assert.Equal(t, yBigInt, entry.Index()[3].BigInt())

}
