package merklize

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/gob"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/iden3/go-merkletree-sql/v2/db/memory"
	"github.com/stretchr/testify/require"
)

type md5Hasher struct{}

func (h *md5Hasher) Hash(inpBI []*big.Int) (*big.Int, error) {
	mh := md5.New()
	for _, i := range inpBI {
		mh.Write(i.Bytes())
	}
	sumBytes := mh.Sum(nil)
	return new(big.Int).SetBytes(sumBytes), nil
}
func (h *md5Hasher) HashBytes(msg []byte) (*big.Int, error) {
	s := md5.Sum(msg)
	return new(big.Int).SetBytes(s[:]), nil
}
func (h *md5Hasher) Prime() *big.Int {
	bs := make([]byte, md5.Size)
	for i := 0; i < md5.Size; i++ {
		bs[i] = 0xff
	}
	return new(big.Int).SetBytes(bs)
}

func TestRDFEntry_BinaryMashaler(t *testing.T) {
	testCases := []struct {
		title string
		value any
	}{
		{
			title: "int64",
			value: int64(100500),
		},
		{
			title: "bool",
			value: true,
		},
		{
			title: "string",
			value: "xyz",
		},
		{
			title: "time.Time",
			value: time.Date(2020, 1, 1, 10, 20, 0, 0, time.UTC),
		},
		{
			title: "*big.Int",
			value: big.NewInt(100500),
		},
	}

	path, err := NewPath("x", "y", 1, "z")
	require.NoError(t, err)

	for _, tc := range testCases {
		t.Run(tc.title, func(t *testing.T) {
			ent, err := NewRDFEntry(path, tc.value)
			require.NoError(t, err)

			entBytes, err := ent.MarshalBinary()
			require.NoError(t, err)
			require.NotEmpty(t, entBytes)

			var version int
			err = gob.NewDecoder(bytes.NewReader(entBytes)).Decode(&version)
			require.NoError(t, err)
			require.Equal(t, rdfEntryEncodingVersion, version)

			var ent2 RDFEntry
			err = ent2.UnmarshalBinary(entBytes)
			require.NoError(t, err)

			require.Equal(t, ent, ent2)
		})
	}
}

func TestRDFEntry_Gob(t *testing.T) {
	testCases := []struct {
		title string
		value any
	}{
		{
			title: "int64",
			value: int64(100500),
		},
		{
			title: "bool",
			value: true,
		},
		{
			title: "string",
			value: "xyz",
		},
		{
			title: "time.Time",
			value: time.Date(2020, 1, 1, 10, 20, 0, 0, time.UTC),
		},
		{
			title: "*big.Int",
			value: big.NewInt(100500),
		},
	}

	path, err := NewPath("x", "y", 1, "z")
	require.NoError(t, err)

	for _, tc := range testCases {
		t.Run(tc.title, func(t *testing.T) {
			ent, err := NewRDFEntry(path, tc.value)
			require.NoError(t, err)

			var buf bytes.Buffer
			enc := gob.NewEncoder(&buf)
			err = enc.Encode(&ent)
			require.NoError(t, err)

			require.NotEmpty(t, buf.Bytes())

			var ent2 RDFEntry
			err = gob.NewDecoder(&buf).Decode(&ent2)
			require.NoError(t, err)

			require.Equal(t, ent, ent2)
		})
	}
}

func TestRDFEntry_BinaryMashaler_CustomHasher(t *testing.T) {
	opts := Options{Hasher: &md5Hasher{}}
	path, err := opts.NewPath("x", "y", 1, "z")
	require.NoError(t, err)
	value := "abc"
	ent, err := opts.NewRDFEntry(path, value)
	require.NoError(t, err)

	key, val, err := ent.KeyValueMtEntries()
	require.NoError(t, err)

	entBytes, err := ent.MarshalBinary()
	require.NoError(t, err)
	require.NotEmpty(t, entBytes)

	var version int
	err = gob.NewDecoder(bytes.NewReader(entBytes)).Decode(&version)
	require.NoError(t, err)

	require.Equal(t, rdfEntryEncodingVersion, version)

	var ent2 RDFEntry

	path, err = opts.NewPath("")
	require.NoError(t, err)
	ent2, err = opts.NewRDFEntry(path, "")
	require.NoError(t, err)

	err = ent2.UnmarshalBinary(entBytes)
	require.NoError(t, err)

	require.Equal(t, ent, ent2)

	key2, val2, err := ent2.KeyValueMtEntries()
	require.NoError(t, err)

	require.Zero(t, key.Cmp(key2))
	require.Zero(t, val.Cmp(val2))
}

func testMarshalCompactObj_customFunction(t testing.TB, obj map[string]any) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := gobJsonObjectEncode(enc, obj)
	require.NoError(t, err)
	require.NotEmpty(t, buf.Bytes())

	dec := gob.NewDecoder(bytes.NewReader(buf.Bytes()))
	obj2, err := gobJsonObjectDecode(dec)
	require.NoError(t, err)
	require.Equal(t, obj, obj2)
}

func testMarshalCompactObj_gob(t testing.TB, obj map[string]any) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(obj)
	require.NoError(t, err)
	require.NotEmpty(t, buf.Bytes())

	var obj2 map[string]any
	dec := gob.NewDecoder(bytes.NewReader(buf.Bytes()))
	err = dec.Decode(&obj2)

	require.NoError(t, err)
	require.Equal(t, obj, obj2)
}

func testMarshalCompactObj_jsonMarshal(t testing.TB, obj map[string]any) {
	var buf2 bytes.Buffer
	buf2.Grow(1000)
	bs, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	err = gob.NewEncoder(&buf).Encode(bs)
	if err != nil {
		t.Fatal(err)
	}

	var bs2 []byte
	err = gob.NewDecoder(bytes.NewReader(buf.Bytes())).Decode(&bs2)
	if err != nil {
		t.Fatal(err)
	}

	var obj2 map[string]any
	err = json.Unmarshal(bs2, &obj2)
	if err != nil {
		t.Fatal(err)
	}

	require.Equal(t, obj, obj2)
}

func TestMerklizer_BinaryMashaler(t *testing.T) {
	ctx := context.Background()
	mz, err := MerklizeJSONLD(ctx, strings.NewReader(testDocument))
	require.NoError(t, err)

	mzBytes, err := mz.MarshalBinary()
	require.NoError(t, err)
	require.NotEmpty(t, mzBytes)

	mz2, err := MerklizerFromBytes(mzBytes)
	require.NoError(t, err)

	require.Equal(t, mz.Root(), mz2.Root())
}

func TestMerklizer_BinaryMashaler_WithMT(t *testing.T) {
	ctx := context.Background()
	mt, err := merkletree.NewMerkleTree(ctx, memory.NewMemoryStorage(), 40)
	if err != nil {
		t.Fatal(err)
	}
	mzMT := MerkleTreeSQLAdapter(mt)

	mz, err := MerklizeJSONLD(ctx, strings.NewReader(testDocument), WithMerkleTree(mzMT))
	require.NoError(t, err)

	mzBytes, err := mz.MarshalBinary()
	require.NoError(t, err)
	require.NotEmpty(t, mzBytes)

	mz2, err := MerklizerFromBytes(mzBytes, WithMerkleTree(mzMT))
	require.NoError(t, err)

	require.Equal(t, mz.Root(), mz2.Root())
}

func TestMerklizer_BinaryMashaler_3(t *testing.T) {
	ctx := context.Background()
	mt, err := merkletree.NewMerkleTree(ctx, memory.NewMemoryStorage(), 40)
	if err != nil {
		t.Fatal(err)
	}
	mzMT := MerkleTreeSQLAdapter(mt)

	mz, err := MerklizeJSONLD(ctx, strings.NewReader(testDocument), WithMerkleTree(mzMT))
	require.NoError(t, err)

	testMarshalCompactObj_customFunction(t, mz.compacted)
}

func BenchmarkMerkalizerSerializationTrims(b *testing.B) {
	gob.Register(map[string]interface{}{})
	gob.Register([]interface{}{})
	ctx := context.Background()
	mt, err := merkletree.NewMerkleTree(ctx, memory.NewMemoryStorage(), 40)
	if err != nil {
		b.Fatal(err)
	}
	mzMT := MerkleTreeSQLAdapter(mt)

	mz, err := MerklizeJSONLD(ctx, strings.NewReader(testDocument), WithMerkleTree(mzMT))
	require.NoError(b, err)

	b.ResetTimer()

	b.ReportAllocs()

	b.Run("custom function", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			testMarshalCompactObj_customFunction(b, mz.compacted)
		}
	})

	b.Run("gob", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			testMarshalCompactObj_gob(b, mz.compacted)
		}
	})

	b.Run("through json marshalling", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			testMarshalCompactObj_jsonMarshal(b, mz.compacted)
		}
	})
}

func BenchmarkMerklizer_BinaryMashaler_2(b *testing.B) {
	gob.Register(map[string]interface{}{})
	gob.Register([]interface{}{})
	gob.Register(time.Time{})
	gob.Register(&big.Int{})

	ctx := context.Background()
	mt, err := merkletree.NewMerkleTree(ctx, memory.NewMemoryStorage(), 40)
	if err != nil {
		b.Fatal(err)
	}
	mzMT := MerkleTreeSQLAdapter(mt)

	mz, err := MerklizeJSONLD(ctx, strings.NewReader(testDocument), WithMerkleTree(mzMT))
	require.NoError(b, err)

	for i := 0; i < b.N; i++ {
		mzBytes, err := mz.MarshalBinary()
		if err != nil {
			b.Fatal(err)
		}
		mz2, err := MerklizerFromBytes(mzBytes, WithMerkleTree(mzMT))
		if err != nil {
			b.Fatal(err)
		}

		if mz.Root().BigInt().Cmp(mz2.Root().BigInt()) != 0 {
			b.Fatal("root mismatch")
		}
	}
}

func TestName(t *testing.T) {
	gob.Register(big.NewInt(0))
	var i = map[string]interface{}{
		"one": 1,
		"two": big.NewInt(2),
	}
	var b bytes.Buffer
	err := gob.NewEncoder(&b).Encode(i)
	require.NoError(t, err)
	//t.Log(b.String())

	var i2 map[string]interface{}
	err = gob.NewDecoder(&b).Decode(&i2)
	require.NoError(t, err)
	t.Logf("%[1]T, %[1]v", i2["two"])
}

func BenchmarkName(b *testing.B) {
	gob.Register(map[string]interface{}{})
	gob.Register([]interface{}{})
	x := `{"@context":null,"@id":"https://issuer.oidp.uscis.gov/credentials/83627465","@type":["https://www.w3.org/2018/credentials#VerifiableCredential","https://w3id.org/citizenship#PermanentResidentCard"],"http://schema.org/description":"Government of Example Permanent Resident Card.","http://schema.org/identifier":83627465,"http://schema.org/name":"Permanent Resident Card","https://www.w3.org/2018/credentials#credentialSubject":[{"@id":"did:example:b34ca6cd37bbf23","@type":["https://w3id.org/citizenship#PermanentResident","http://schema.org/Person"],"http://schema.org/birthDate":{"@type":"http://www.w3.org/2001/XMLSchema#dateTime","@value":"1958-07-17"},"http://schema.org/familyName":"SMITH","http://schema.org/gender":"Male","http://schema.org/givenName":"JOHN","http://schema.org/image":{"@id":"data:image/png;base64,iVBORw0KGgokJggg=="},"https://w3id.org/citizenship#birthCountry":"Bahamas","https://w3id.org/citizenship#commuterClassification":"C1","https://w3id.org/citizenship#lprCategory":"C09","https://w3id.org/citizenship#lprNumber":"999-999-999","https://w3id.org/citizenship#residentSince":{"@type":"http://www.w3.org/2001/XMLSchema#dateTime","@value":"2015-01-01"}},{"@id":"did:example:b34ca6cd37bbf24","@type":["https://w3id.org/citizenship#PermanentResident","http://schema.org/Person"],"http://schema.org/birthDate":{"@type":"http://www.w3.org/2001/XMLSchema#dateTime","@value":"1958-07-18"},"http://schema.org/familyName":"SMITH","http://schema.org/gender":"Male","http://schema.org/givenName":"JOHN","http://schema.org/image":{"@id":"data:image/png;base64,iVBORw0KGgokJggg=="},"https://w3id.org/citizenship#birthCountry":"Bahamas","https://w3id.org/citizenship#commuterClassification":"C1","https://w3id.org/citizenship#lprCategory":"C09","https://w3id.org/citizenship#lprNumber":"999-999-999","https://w3id.org/citizenship#residentSince":{"@type":"http://www.w3.org/2001/XMLSchema#dateTime","@value":"2015-01-01"}}],"https://www.w3.org/2018/credentials#expirationDate":{"@type":"http://www.w3.org/2001/XMLSchema#dateTime","@value":"2029-12-03T12:19:52Z"},"https://www.w3.org/2018/credentials#issuanceDate":{"@type":"http://www.w3.org/2001/XMLSchema#dateTime","@value":"2019-12-03T12:19:52Z"},"https://www.w3.org/2018/credentials#issuer":{"@id":"did:example:489398593"}}`
	var obj interface{}
	err := json.Unmarshal([]byte(x), &obj)
	require.NoError(b, err)

	buf := make([]byte, 0, 1000)
	for i := 0; i < b.N; i++ {
		buf2 := bytes.NewBuffer(buf[:0])
		err := gob.NewEncoder(buf2).Encode(&obj)
		require.NoError(b, err)

		var obj2 interface{}
		err = gob.NewDecoder(bytes.NewReader(buf2.Bytes())).Decode(&obj2)
		require.NoError(b, err)
		require.Equal(b, obj, obj2)
	}
}
func BenchmarkName2(b *testing.B) {
	gob.Register(map[string]interface{}{})
	gob.Register([]interface{}{})
	x := `{"@context":null,"@id":"https://issuer.oidp.uscis.gov/credentials/83627465","@type":["https://www.w3.org/2018/credentials#VerifiableCredential","https://w3id.org/citizenship#PermanentResidentCard"],"http://schema.org/description":"Government of Example Permanent Resident Card.","http://schema.org/identifier":83627465,"http://schema.org/name":"Permanent Resident Card","https://www.w3.org/2018/credentials#credentialSubject":[{"@id":"did:example:b34ca6cd37bbf23","@type":["https://w3id.org/citizenship#PermanentResident","http://schema.org/Person"],"http://schema.org/birthDate":{"@type":"http://www.w3.org/2001/XMLSchema#dateTime","@value":"1958-07-17"},"http://schema.org/familyName":"SMITH","http://schema.org/gender":"Male","http://schema.org/givenName":"JOHN","http://schema.org/image":{"@id":"data:image/png;base64,iVBORw0KGgokJggg=="},"https://w3id.org/citizenship#birthCountry":"Bahamas","https://w3id.org/citizenship#commuterClassification":"C1","https://w3id.org/citizenship#lprCategory":"C09","https://w3id.org/citizenship#lprNumber":"999-999-999","https://w3id.org/citizenship#residentSince":{"@type":"http://www.w3.org/2001/XMLSchema#dateTime","@value":"2015-01-01"}},{"@id":"did:example:b34ca6cd37bbf24","@type":["https://w3id.org/citizenship#PermanentResident","http://schema.org/Person"],"http://schema.org/birthDate":{"@type":"http://www.w3.org/2001/XMLSchema#dateTime","@value":"1958-07-18"},"http://schema.org/familyName":"SMITH","http://schema.org/gender":"Male","http://schema.org/givenName":"JOHN","http://schema.org/image":{"@id":"data:image/png;base64,iVBORw0KGgokJggg=="},"https://w3id.org/citizenship#birthCountry":"Bahamas","https://w3id.org/citizenship#commuterClassification":"C1","https://w3id.org/citizenship#lprCategory":"C09","https://w3id.org/citizenship#lprNumber":"999-999-999","https://w3id.org/citizenship#residentSince":{"@type":"http://www.w3.org/2001/XMLSchema#dateTime","@value":"2015-01-01"}}],"https://www.w3.org/2018/credentials#expirationDate":{"@type":"http://www.w3.org/2001/XMLSchema#dateTime","@value":"2029-12-03T12:19:52Z"},"https://www.w3.org/2018/credentials#issuanceDate":{"@type":"http://www.w3.org/2001/XMLSchema#dateTime","@value":"2019-12-03T12:19:52Z"},"https://www.w3.org/2018/credentials#issuer":{"@id":"did:example:489398593"}}`
	var obj interface{}
	err := json.Unmarshal([]byte(x), &obj)
	require.NoError(b, err)

	buf := make([]byte, 0, 1000)
	for i := 0; i < b.N; i++ {
		b1, err := json.Marshal(obj)
		require.NoError(b, err)

		buf2 := bytes.NewBuffer(buf[:0])
		err = gob.NewEncoder(buf2).Encode(b1)
		require.NoError(b, err)

		var b2 []byte
		err = gob.NewDecoder(bytes.NewReader(buf2.Bytes())).Decode(&b2)
		require.NoError(b, err)

		var obj2 interface{}
		err = json.Unmarshal(b2, &obj2)
		require.NoError(b, err)

		require.Equal(b, obj, obj2)
	}
}
