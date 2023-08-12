package processor

import (
	"context"

	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-schema-processor/v2/merklize"
	"github.com/iden3/go-schema-processor/v2/verifiable"
	"github.com/pkg/errors"
)

// Processor is set of tool for claim processing
type Processor struct {
	Validator    Validator
	SchemaLoader SchemaLoader
	Parser       Parser
}

// Validator is interface to validate data and documents
type Validator interface {
	ValidateData(data, schema []byte) error
}

// SchemaLoader is interface to load schema
type SchemaLoader interface {
	Load(ctx context.Context) (schema []byte, extension string, err error)
}

// ParsedSlots is struct that represents iden3 claim specification
type ParsedSlots struct {
	IndexA, IndexB []byte
	ValueA, ValueB []byte
}

// Parser is an interface to parse claim slots
type Parser interface {
	ParseClaim(ctx context.Context, credential verifiable.W3CCredential,
		options *CoreClaimOptions) (*core.Claim, error)
	GetFieldSlotIndex(field string, schema []byte) (int, error)
}

// CoreClaimOptions is params for core claim parsing
type CoreClaimOptions struct {
	RevNonce              uint64 `json:"revNonce"`
	Version               uint32 `json:"version"`
	SubjectPosition       string `json:"subjectPosition"`
	MerklizedRootPosition string `json:"merklizedRootPosition"`
	Updatable             bool   `json:"updatable"`
	MerklizerOpts         []merklize.MerklizeOption
}

var (
	errParserNotDefined    = errors.New("parser is not defined")
	errLoaderNotDefined    = errors.New("loader is not defined")
	errValidatorNotDefined = errors.New("validator is not defined")
)

// Opt returns configuration options for processor suite
type Opt func(opts *Processor)

// WithValidator return new options
func WithValidator(s Validator) Opt {
	return func(opts *Processor) {
		opts.Validator = s
	}
}

// WithSchemaLoader return new options
func WithSchemaLoader(s SchemaLoader) Opt {
	return func(opts *Processor) {
		opts.SchemaLoader = s
	}
}

// WithParser return new options
func WithParser(s Parser) Opt {
	return func(opts *Processor) {
		opts.Parser = s
	}
}

// InitProcessorOptions initializes processor with options.
func InitProcessorOptions(processor *Processor, opts ...Opt) *Processor {
	for _, opt := range opts {
		opt(processor)
	}
	return processor
}

// Load will load a schema by given url.
func (s *Processor) Load(ctx context.Context) (schema []byte, extension string, err error) {
	if s.SchemaLoader == nil {
		return nil, "", errLoaderNotDefined
	}
	return s.SchemaLoader.Load(ctx)
}

// ParseClaim will serialize input data to index and value fields.
func (s *Processor) ParseClaim(ctx context.Context,
	credential verifiable.W3CCredential,
	opts *CoreClaimOptions) (*core.Claim, error) {

	if s.Parser == nil {
		return nil, errParserNotDefined
	}
	return s.Parser.ParseClaim(ctx, credential, opts)
}

// GetFieldSlotIndex returns index of slot for specified field according to schema
// TODO: what to do with this method?
func (s *Processor) GetFieldSlotIndex(field string, schema []byte) (int, error) {
	if s.Parser == nil {
		return 0, errParserNotDefined
	}
	return s.Parser.GetFieldSlotIndex(field, schema)
}

// ValidateData will validate a claim content by given schema.
func (s *Processor) ValidateData(data, schema []byte) error {
	if s.Validator == nil {
		return errValidatorNotDefined
	}
	return s.Validator.ValidateData(data, schema)
}
