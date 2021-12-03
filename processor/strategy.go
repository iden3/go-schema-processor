package processor

// ParsingStrategy  is used for parser to know how to fill claim slots
type ParsingStrategy int

const (
	// OneFieldPerSlotStrategy is strategy when one field corresponds exactly to the one slot
	OneFieldPerSlotStrategy ParsingStrategy = iota + 1

	// SlotFullfilmentStrategy is strategy when field putting in the claim slot sequentially
	SlotFullfilmentStrategy
)
