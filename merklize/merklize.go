package merklize

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/iden3/go-iden3-crypto/constants"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/iden3/go-merkletree-sql"
	"github.com/iden3/go-merkletree-sql/db/memory"
	"github.com/piprate/json-gold/ld"
)

var defaultHasher Hasher = PoseidonHasher{}

// SetHasher changes default hasher
func SetHasher(h Hasher) {
	if h == nil {
		panic("hasher is nil")
	}
	defaultHasher = h
}

// Options type allows to change hashing algorithm and create Path and RDFEntry
// instances with hasher different from default one.
type Options struct {
	Hasher Hasher
}

func (o Options) getHasher() Hasher {
	if o.Hasher != nil {
		return o.Hasher
	}
	return defaultHasher
}

func (o Options) NewPath(parts ...interface{}) (Path, error) {
	p := Path{hasher: o.getHasher()}
	err := p.Append(parts)
	return p, err
}

func (o Options) PathFromContext(ctxBytes []byte, path string) (Path, error) {
	out := Path{hasher: o.getHasher()}
	err := out.pathFromContext(ctxBytes, path)
	return out, err
}

func (o Options) NewRDFEntry(key Path, value interface{}) (RDFEntry, error) {
	e := RDFEntry{
		key:    key,
		hasher: o.getHasher(),
	}
	if len(key.parts) == 0 {
		return e, errors.New("key length is zero")
	}

	switch v := value.(type) {
	case int:
		e.value = int64(v)
	case int64, string, bool, time.Time:
		e.value = value
	default:
		return e, fmt.Errorf("incorrect value type: %T", value)
	}

	return e, nil
}

type Path struct {
	parts  []interface{} // string or int types
	hasher Hasher
}

func (p *Path) reverse() {
	for i, j := 0, len(p.parts)-1; i < j; i, j = i+1, j-1 {
		p.parts[i], p.parts[j] = p.parts[j], p.parts[i]
	}
}

func NewPath(parts ...interface{}) (Path, error) {
	p := Path{}
	err := p.Append(parts...)
	return p, err
}

// NewPathFromContext parses context and do its best to generate full Path
// from shortcut line field1.field2.field3...
func NewPathFromContext(ctxBytes []byte, path string) (Path, error) {
	var out Path
	err := out.pathFromContext(ctxBytes, path)
	return out, err
}

func NewPathFromDocument(docBytes []byte, path string) (Path, error) {
	var docObj map[string]interface{}
	err := json.Unmarshal(docBytes, &docObj)
	if err != nil {
		return Path{}, err
	}

	pathParts := strings.Split(path, ".")
	if len(pathParts) == 0 {
		return Path{}, errors.New("path is empty")
	}

	pathPartsI, err := pathFromDocument(nil, docObj, pathParts, false)
	if err != nil {
		return Path{}, err
	}

	return Path{parts: pathPartsI}, nil
}

func (p *Path) pathFromContext(ctxBytes []byte, path string) error {

	var ctxObj map[string]interface{}
	err := json.Unmarshal(ctxBytes, &ctxObj)
	if err != nil {
		return err
	}

	ldCtx, err := ld.NewContext(nil, nil).Parse(ctxObj["@context"])
	if err != nil {
		return err
	}

	parts := strings.Split(path, ".")

	for _, term := range parts {
		if numRE.MatchString(term) {
			i64, err := strconv.ParseInt(term, 10, 32)
			if err != nil {
				return err
			}
			p.parts = append(p.parts, int(i64))
			continue
		}

		if ldCtx == nil {
			return errors.New("context is nil")
		}

		m := ldCtx.GetTermDefinition(term)
		id, ok := m["@id"]
		if !ok {
			return fmt.Errorf("no @id attribute for term: %v", term)
		}

		nextCtx, ok := m["@context"]
		if ok {
			var err error
			ldCtx, err = ldCtx.Parse(nextCtx)
			if err != nil {
				return err
			}
		}

		p.parts = append(p.parts, id)
	}

	return nil
}

var numRE = regexp.MustCompile(`^\d+$`)

// Create path JSON-LD document.
// If acceptArray is true, the previous element was index, and we accept an
// array
func pathFromDocument(ldCtx *ld.Context, docObj interface{},
	pathParts []string, acceptArray bool) ([]interface{}, error) {

	if len(pathParts) == 0 {
		return nil, nil
	}

	term := pathParts[0]
	newPathParts := pathParts[1:]

	if numRE.MatchString(term) {
		i64, err := strconv.ParseInt(term, 10, 32)
		if err != nil {
			return nil, err
		}

		moreParts, err := pathFromDocument(ldCtx, docObj, newPathParts, true)
		if err != nil {
			return nil, err
		}

		return append([]interface{}{int(i64)}, moreParts...), nil
	}

	var docObjMap map[string]interface{}

	switch docObjT := docObj.(type) {
	case []interface{}:
		if len(docObjT) == 0 {
			return nil, errors.New("can't generate path on zero-sized array")
		}

		if !acceptArray {
			return nil, errors.New("unexpected array element")
		}

		return pathFromDocument(ldCtx, docObjT[0], pathParts, false)
	case map[string]interface{}:
		// pass
		docObjMap = docObjT
	default:
		return nil, fmt.Errorf("expect array or object type, got: %T", docObj)
	}

	if ldCtx == nil {
		ldCtx = ld.NewContext(nil, nil)
	}

	var err error
	ctxData, haveCtx := docObjMap["@context"]
	if haveCtx {
		ldCtx, err = ldCtx.Parse(ctxData)
		if err != nil {
			return nil, err
		}
	}

	elemOrderedKeys := ld.GetOrderedKeys(docObjMap)
	typeScopedContext := ldCtx
	for _, key := range elemOrderedKeys {
		var expandedProperty string
		expandedProperty, err = ldCtx.ExpandIri(key, false, true, nil, nil)
		if err != nil {
			return nil, err
		}

		if expandedProperty != "@type" {
			continue
		}

		types := make([]string, 0)
		switch v := docObjMap[key].(type) {
		case []interface{}:
			for _, t := range v {
				if typeStr, isString := t.(string); isString {
					types = append(types, typeStr)
				} else {
					return nil, fmt.Errorf(
						"@type value must be an array of strings: %T", t)
				}
			}
			sort.Strings(types)
		case string:
			types = append(types, v)
		default:
			return nil, fmt.Errorf("unexpected @type field type: %T",
				docObjMap[key])
		}

		for _, tt := range types {
			td := typeScopedContext.GetTermDefinition(tt)
			if ctxObj, hasCtx := td["@context"]; hasCtx {
				ldCtx, err = ldCtx.Parse(ctxObj)
				if err != nil {
					return nil, err
				}
			}
		}
		break
	}

	m := ldCtx.GetTermDefinition(term)
	id, ok := m["@id"]
	if !ok {
		return nil, fmt.Errorf("no @id attribute for term: %v", term)
	}
	idStr, ok := id.(string)
	if !ok {
		return nil, fmt.Errorf("@id attr is not of type string: %T", id)
	}

	moreParts, err := pathFromDocument(ldCtx, docObjMap[term], newPathParts,
		true)
	if err != nil {
		return nil, err
	}

	prts := append([]interface{}{idStr}, moreParts...)
	return prts, nil
}

func (p *Path) Key() (*big.Int, error) {
	var err error
	h := p.hasher
	if h == nil {
		h = defaultHasher
	}

	intKeyParts := make([]*big.Int, len(p.parts))
	for i := range p.parts {
		switch v := p.parts[i].(type) {
		case string:
			intKeyParts[i], err = h.HashBytes([]byte(v))
			if err != nil {
				return nil, err
			}
		case int:
			intKeyParts[i] = big.NewInt(int64(v))
		default:
			return nil, fmt.Errorf("unexpected type %T", v)
		}
	}

	return h.Hash(intKeyParts)
}

func (p *Path) Append(parts ...interface{}) error {
	for i := range parts {
		switch parts[i].(type) {
		case string, int:
		default:
			return fmt.Errorf("incorrect part type: %T", parts)
		}
	}

	p.parts = append(p.parts, parts...)
	return nil
}

// Prepend path's parts from the beginning
func (p *Path) Prepend(parts ...interface{}) error {
	for i := range parts {
		switch parts[i].(type) {
		case string, int:
		default:
			return fmt.Errorf("incorrect part type: %T", parts)
		}
	}

	p.parts = append(parts, p.parts...)
	return nil
}

// type RDFEntryValueType interface {
// 	int | int32 | int64 | uint | uint32 | uint64 | string | bool | time.Time
// }

// type RDFEntry[T RDFEntryValueType] struct {
// 	key Path
// 	// valid types are: int64, string, bool, time.Time
// 	value  T
// 	hasher Hasher
// }

type RDFEntry struct {
	key Path
	// valid types are: int64, string, bool, time.Time
	value  any
	hasher Hasher
}

func NewRDFEntry(key Path, value any) (RDFEntry, error) {
	e := RDFEntry{key: key}
	if len(key.parts) == 0 {
		return e, errors.New("key length is zero")
	}

	switch v := value.(type) {
	case int:
		e.value = int64(v)
	case int64, string, bool:
		e.value = value
	default:
		return e, fmt.Errorf("incorrect value type: %T", value)
	}

	return e, nil
}

func (e RDFEntry) KeyHash() (*big.Int, error) {
	return e.key.Key()
}

func (e RDFEntry) ValueHash() (*big.Int, error) {
	return hashValue(e.getHasher(), e.value)
}

func (e RDFEntry) KeyValueHashes() (
	keyHash *big.Int, valueHash *big.Int, err error) {

	keyHash, err = e.KeyHash()
	if err != nil {
		return nil, nil, err
	}

	valueHash, err = e.ValueHash()
	if err != nil {
		return nil, nil, err
	}

	return keyHash, valueHash, nil
}

// Identifies ld.Node by string representation of Type and Value.
// This type allows us to use ld.Node as keys in maps.
type nodeID struct {
	tp  string
	val string
}

func newNodeID(n ld.Node) (nodeID, error) {
	var id nodeID

	if n == nil {
		return id, errors.New("ld.Node is nil")
	}

	id.tp = reflect.TypeOf(n).Name()

	switch val := n.(type) {
	case *ld.IRI:
		if val == nil {
			return id, errors.New("ld.Node is nil")
		}
		id.val = val.Value
	case *ld.BlankNode:
		if val == nil {
			return id, errors.New("ld.Node is nil")
		}
		id.val = val.Attribute
	default:
		return id, errors.New("ld.Node type is not *ld.IRI or *ld.BlankNode")
	}

	return id, nil
}

type quadKey struct {
	subjectID nodeID
	predicate ld.IRI
}

type relationship struct {
	// mapping from child Subject to its parent
	parents map[nodeID]quadKey
	// mapping from parent to array of children
	children map[nodeID][]nodeID
}

func newRelationship(quads []*ld.Quad) (*relationship, error) {
	r := relationship{
		parents:  make(map[nodeID]quadKey),
		children: make(map[nodeID][]nodeID),
	}

	subjectSet := make(map[nodeID]struct{})
	for _, q := range quads {
		subjID, err := newNodeID(q.Subject)
		if err != nil {
			return nil, err
		}
		subjectSet[subjID] = struct{}{}
	}

	for _, q := range quads {
		objID, err := newNodeID(q.Object)
		if err != nil {
			continue
		}

		_, ok := subjectSet[objID]
		if !ok {
			continue
		}

		qk, err := getQuadKey(q)
		if err != nil {
			return nil, err
		}

		r.parents[objID] = qk

		r.children[qk.subjectID] = append(r.children[qk.subjectID], objID)
	}

	return &r, nil
}

func (r *relationship) path(n *ld.Quad, idx *int) (Path, error) {
	var k Path

	if n == nil {
		return k, errors.New("quad is nil")
	}

	subjID, err := newNodeID(n.Subject)
	if err != nil {
		return k, err
	}

	var predicate ld.IRI
	switch qp := n.Predicate.(type) {
	case *ld.IRI:
		if qp == nil {
			return k, errors.New("predicate IRI is nil")
		}
		predicate = *qp
	default:
		return k, errors.New("unexpected Quad's Predicate type")
	}

	if idx != nil {
		err = k.Append(*idx)
		if err != nil {
			return k, err
		}
	}

	err = k.Append(predicate.Value)
	if err != nil {
		return k, err
	}

	nextKey := subjID
	for {
		parent, ok := r.parents[nextKey]
		if !ok {
			break
		}

		children, ok := r.children[parent.subjectID]
		if !ok {
			return k, errors.New("[assertion] parent not found in children")
		}

		if len(children) == 1 {
			err = k.Append(parent.predicate.Value)
			if err != nil {
				return k, err
			}
		} else {
			found := false
			for i, child := range children {
				if child == nextKey {
					found = true
					err = k.Append(i, parent.predicate.Value)
					if err != nil {
						return k, err
					}
					break
				}
			}
			if !found {
				return k, errors.New(
					"[assertion] child not found in parent's relations")
			}
		}

		nextKey = parent.subjectID
	}

	k.reverse()
	return k, nil
}

var dateRE = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

// EntriesFromRDF creates entries from RDF dataset suitable to add to
// merkle tree
func EntriesFromRDF(ds *ld.RDFDataset) ([]RDFEntry, error) {
	if len(ds.Graphs) != 1 {
		return nil, errors.New("support only dataset with one @default graph")
	}

	quads, ok := ds.Graphs["@default"]
	if !ok {
		return nil, errors.New("@default graph not found in dataset")
	}

	counts, err := countEntries(quads)
	if err != nil {
		return nil, err
	}

	seenCount := make(map[quadKey]int)

	rs, err := newRelationship(quads)
	if err != nil {
		return nil, err
	}

	entries := make([]RDFEntry, 0, len(quads))
	for _, q := range quads {
		var e RDFEntry
		switch qo := q.Object.(type) {
		case *ld.Literal:
			if qo == nil {
				return nil, errors.New("object Literal is nil")
			}
			switch qo.Datatype {
			case "http://www.w3.org/2001/XMLSchema#boolean":
				switch qo.Value {
				case "false":
					e.value = false
				case "true":
					e.value = true
				default:
					return nil, errors.New("incorrect boolean value")
				}
			case "http://www.w3.org/2001/XMLSchema#integer",
				"http://www.w3.org/2001/XMLSchema#nonNegativeInteger",
				"http://www.w3.org/2001/XMLSchema#nonPositiveInteger",
				"http://www.w3.org/2001/XMLSchema#negativeInteger",
				"http://www.w3.org/2001/XMLSchema#positiveInteger":
				e.value, err = strconv.ParseInt(qo.Value, 10, 64)
				if err != nil {
					return nil, err
				}
			case "http://www.w3.org/2001/XMLSchema#dateTime":
				if dateRE.MatchString(qo.Value) {
					e.value, err = time.ParseInLocation("2006-01-02",
						qo.Value, time.UTC)
				} else {
					e.value, err = time.Parse(time.RFC3339Nano, qo.Value)
				}
				if err != nil {
					return nil, err
				}
			default:
				e.value = qo.GetValue()
			}
		case *ld.IRI:
			if qo == nil {
				return nil, errors.New("object IRI is nil")
			}
			e.value = qo.GetValue()
		case *ld.BlankNode:
			nID, err := newNodeID(qo)
			if err != nil {
				return nil, err
			}
			_, ok := rs.parents[nID]
			if ok {
				// this node is a reference to known children,
				// skip it and do not put it into merkle tree because it
				// has no defined @id attribute
				continue
			}
			return nil, errors.New("[1] BlankNode is not supported yet")
		default:
			return nil, errors.New("unexpected Quad's Object type")
		}

		qKey, err := getQuadKey(q)
		if err != nil {
			return nil, err
		}

		var idx *int
		switch counts[qKey] {
		case 0:
			return nil, errors.New("[assertion] key not found in counts")
		case 1:
			// leave idx nil: only one element, do not consider it as an array
		default:
			idx = new(int)
			*idx = seenCount[qKey]
			seenCount[qKey]++
		}
		e.key, err = rs.path(q, idx)
		if err != nil {
			return nil, err
		}

		entries = append(entries, e)
	}

	return entries, nil
}

// count number of entries with same key to distinguish between plain values
// and arrays (sets)
func countEntries(nodes []*ld.Quad) (map[quadKey]int, error) {
	res := make(map[quadKey]int, len(nodes))
	for _, q := range nodes {
		key, err := getQuadKey(q)
		if err != nil {
			return nil, err
		}
		res[key]++
	}
	return res, nil
}

func getQuadKey(q *ld.Quad) (quadKey, error) {
	var key quadKey

	if q == nil {
		return key, errors.New("quad is nil")
	}

	var err error
	key.subjectID, err = newNodeID(q.Subject)
	if err != nil {
		return key, err
	}

	predicate, ok := q.Predicate.(*ld.IRI)
	if !ok || predicate == nil {
		return key, errors.New("predicate is not of IRI type or nil")
	}
	key.predicate = *predicate

	return key, nil
}

type mtAppender interface {
	Add(context.Context, *big.Int, *big.Int) error
}

func AddEntriesToMerkleTree(ctx context.Context, mt mtAppender,
	entries []RDFEntry) error {

	for _, e := range entries {
		key, val, err := e.KeyValueHashes()
		if err != nil {
			return err
		}

		err = mt.Add(ctx, key, val)
		if err != nil {
			return err
		}
	}

	return nil
}

func (e RDFEntry) getHasher() Hasher {
	h := e.hasher
	if h == nil {
		h = defaultHasher
	}
	return h
}

type Hasher interface {
	Hash(inpBI []*big.Int) (*big.Int, error)
	HashBytes(msg []byte) (*big.Int, error)
	Prime() *big.Int
}

type PoseidonHasher struct{}

func (p PoseidonHasher) Hash(inpBI []*big.Int) (*big.Int, error) {
	return poseidon.Hash(inpBI)
}

func (p PoseidonHasher) HashBytes(msg []byte) (*big.Int, error) {
	return poseidon.HashBytes(msg)
}

func (p PoseidonHasher) Prime() *big.Int {
	return new(big.Int).Set(constants.Q)
}

type MerkleTree interface {
	Add(context.Context, *big.Int, *big.Int) error
	GenerateProof(context.Context, *big.Int) (*merkletree.Proof, error)
	Root() *merkletree.Hash
}

type mtSQLAdapter merkletree.MerkleTree

func (a *mtSQLAdapter) Add(ctx context.Context, key, value *big.Int) error {
	return (*merkletree.MerkleTree)(a).Add(ctx, key, value)
}

func (a *mtSQLAdapter) GenerateProof(ctx context.Context,
	key *big.Int) (*merkletree.Proof, error) {
	p, _, err := (*merkletree.MerkleTree)(a).GenerateProof(ctx, key, nil)
	return p, err
}

func (a *mtSQLAdapter) Root() *merkletree.Hash {
	return (*merkletree.MerkleTree)(a).Root()
}

func MerkleTreeSQLAdapter(mt *merkletree.MerkleTree) MerkleTree {
	return (*mtSQLAdapter)(mt)
}

type Merklizer struct {
	srcDoc []byte
	mt     MerkleTree
	hasher Hasher
}

type MerklizeOption func(m *Merklizer)

func WithHasher(h Hasher) MerklizeOption {
	return func(m *Merklizer) {
		m.hasher = h
	}
}

func WithMerkleTree(mt MerkleTree) MerklizeOption {
	return func(m *Merklizer) {
		m.mt = mt
	}
}

func Merklize(ctx context.Context, in io.Reader,
	opts ...MerklizeOption) (*Merklizer, error) {

	mz := &Merklizer{}
	for _, o := range opts {
		o(mz)
	}

	// if merkletree is not set with options, initialize new in-memory MT.
	if mz.mt == nil {
		mt, err := merkletree.NewMerkleTree(ctx, memory.NewMemoryStorage(), 40)
		if err != nil {
			return nil, err
		}
		mz.mt = MerkleTreeSQLAdapter(mt)
	}

	// if hasher is not set with options, initialize it to default
	if mz.hasher == nil {
		mz.hasher = defaultHasher
	}

	var err error
	mz.srcDoc, err = io.ReadAll(in)
	if err != nil {
		return nil, err
	}

	var obj map[string]interface{}
	err = json.Unmarshal(mz.srcDoc, &obj)
	if err != nil {
		return nil, err
	}

	proc := ld.NewJsonLdProcessor()
	options := ld.NewJsonLdOptions("")
	options.Algorithm = "URDNA2015"

	normDoc, err := proc.Normalize(obj, options)
	if err != nil {
		return nil, err
	}

	dataset, ok := normDoc.(*ld.RDFDataset)
	if !ok {
		return nil, errors.New("[assertion] expected *ld.RDFDataset type")
	}

	entries, err := EntriesFromRDF(dataset)
	if err != nil {
		return nil, err
	}

	err = AddEntriesToMerkleTree(ctx, mz.mt, entries)
	if err != nil {
		return nil, err
	}

	return mz, nil
}

// Proof generate and return Proof and Path hash to verify this proof.
func (m *Merklizer) Proof(ctx context.Context,
	path interface{}) (*merkletree.Proof, Path, error) {

	var realPath Path
	var err error
	switch p := path.(type) {
	case string:
		realPath, err = NewPathFromDocument(m.srcDoc, p)
		if err != nil {
			return nil, realPath, err
		}
		realPath.hasher = m.hasher
	case Path:
		realPath = p
	default:
		return nil, realPath,
			errors.New("path should be of type either string or Path")
	}

	keyHash, err := realPath.Key()
	if err != nil {
		return nil, realPath, err
	}

	proof, err := m.mt.GenerateProof(ctx, keyHash)
	return proof, realPath, err
}

func (m *Merklizer) HashValue(value interface{}) (*big.Int, error) {
	return hashValue(m.hasher, value)
}

func (m *Merklizer) Root() *merkletree.Hash {
	return m.mt.Root()
}

func hashValue(h Hasher, v interface{}) (*big.Int, error) {
	switch et := v.(type) {
	case int64:
		return mkValueInt(h, et)
	case int32:
		return mkValueInt(h, et)
	case int:
		return mkValueInt(h, et)
	case uint64:
		return mkValueUInt(h, et)
	case uint32:
		return mkValueUInt(h, et)
	case uint:
		return mkValueUInt(h, et)
	case bool:
		return mkValueBool(h, et)
	case string:
		return mkValueString(h, et)
	case time.Time:
		return mkValueTime(h, et)
	default:
		return nil, fmt.Errorf("unexpected value type: %T", v)
	}
}

func mkValueInt[I int64 | int32 | int](h Hasher, val I) (*big.Int, error) {
	if val >= 0 {
		return big.NewInt(int64(val)), nil
	} else {
		return new(big.Int).Add(h.Prime(), big.NewInt(int64(val))), nil
	}
}

func mkValueUInt[I uint64 | uint32 | uint](h Hasher, val I) (*big.Int, error) {
	return new(big.Int).SetUint64(uint64(val)), nil
}

func mkValueBool(h Hasher, val bool) (*big.Int, error) {
	if val {
		return h.Hash([]*big.Int{big.NewInt(1)})
	} else {
		return h.Hash([]*big.Int{big.NewInt(0)})
	}
}

func mkValueString(h Hasher, val string) (*big.Int, error) {
	return h.HashBytes([]byte(val))
}

func mkValueTime(h Hasher, val time.Time) (*big.Int, error) {
	return mkValueInt(h, val.UnixNano())
}
