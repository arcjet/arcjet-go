package arcjet

import (
	"context"
	"fmt"
	"sync"
)

// cardNumberEvaluator is the analyzer [DetectCardNumbers] runs. It compiles
// the WebAssembly module on first use and keeps it for the process.
var (
	cardNumberEvaluatorOnce sync.Once
	cardNumberEvaluator     *localEvaluator
)

// DetectCardNumbers finds payment card numbers in text with Arcjet's card
// detection, the same definition the bundled analyzer and the Arcjet server
// use. Offsets are byte offsets into text. A [SensitiveInfoBackend] that
// reports card numbers can call it so its results match the bundled analyzer.
//
// The WebAssembly module is compiled on the first call and reused after that,
// so the first call is slower. A failure, including a trap in the module, is
// returned as an error with no cards.
func DetectCardNumbers(ctx context.Context, text string) (cards []DetectedSensitiveInfoEntity, err error) {
	cardNumberEvaluatorOnce.Do(func() {
		cardNumberEvaluator = newLazyLocalEvaluator(nil)
	})
	inst, release, err := cardNumberEvaluator.instance(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	// The generated bindings panic on a guest trap or a failed allocation.
	// Report that as an error, with no partial result.
	defer func() {
		if rec := recover(); rec != nil {
			cards = nil
			err = fmt.Errorf("arcjet: detect card numbers: %v", rec)
		}
	}()

	result := inst.DetectSensitiveInfo(ctx, text,
		sensitiveInfoConfig(nil, []EntityType{SensitiveInfoCreditCardNumber}, false, 1))
	for _, e := range detectedEntitiesFromWire(result.Denied) {
		if e.IdentifiedType == SensitiveInfoCreditCardNumber {
			cards = append(cards, DetectedSensitiveInfoEntity{
				Start: int(e.Start),
				End:   int(e.End),
				Type:  SensitiveInfoCreditCardNumber,
			})
		}
	}
	return cards, nil
}
