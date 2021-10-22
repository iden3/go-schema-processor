package json

import "github.com/iden3/iden3-claim-processor/pkg/processor"

type Processor struct {
	processor.Processor
}

// New an instance of json processor signature suite.
func New(opts ...processor.Opt) *Processor {
	p := &Processor{}
	processor.InitProcessorOptions(&p.Processor, opts...)
	return p
}
