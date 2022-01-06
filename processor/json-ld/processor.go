package jsonld

import (
	"github.com/iden3/go-schema-processor/processor"
)

// Processor is set of tool for claim processing
type Processor struct {
	processor.Processor
}

// New an instance of json-ld processor signature suite.
func New(opts ...processor.Opt) *Processor {
	p := &Processor{}
	processor.InitProcessorOptions(&p.Processor, opts...)
	return p
}
