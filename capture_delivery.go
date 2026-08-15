package arcjet

import (
	"context"
	"sync"
	"time"

	decidev2 "github.com/arcjet/arcjet-go/internal/proto/decide/v2"
)

// captureDelivery is bounded, send-once delivery for capture events.
//
// Capture is best-effort telemetry on a request path:
//
//   - Bounded. The queue has a ceiling and drops the newest event when full.
//     Blocking the caller for space would turn telemetry into their latency.
//   - Batched. An event waits briefly for company so a burst costs one request.
//   - Send-once. A failed batch is dropped, never retried.
//   - Never process-holding. The worker is a goroutine that exits when idle.
//     Call Flush when delivery is needed before shutdown.
type captureDelivery struct {
	send       func([]*decidev2.CaptureEvent) error
	diagnose   captureDiagnose
	queueSize  int
	batchSize  int
	batchDelay time.Duration

	mu          sync.Mutex
	cond        *sync.Cond
	queue       []queuedCapture
	nextSeq     uint64
	outstanding int
	flushNow    bool
	worker      bool
}

// queuedCapture is one enqueued event plus the sequence number assigned at
// capture time. Flush uses that sequence as a barrier so an expired flush
// can drop only the events it already owned.
type queuedCapture struct {
	event *decidev2.CaptureEvent
	seq   uint64
}

type captureDeliveryOptions struct {
	send       func([]*decidev2.CaptureEvent) error
	diagnose   captureDiagnose
	queueSize  int
	batchSize  int
	batchDelay time.Duration
	// noBatchDelay disables the batch window so a Flush does not wait for
	// company. Tests use this. Production leaves it false and gets the
	// default delay when batchDelay is unset.
	noBatchDelay bool
}

func newCaptureDelivery(opts captureDeliveryOptions) *captureDelivery {
	d := &captureDelivery{
		send:      opts.send,
		diagnose:  opts.diagnose,
		queueSize: positiveIntOr(opts.queueSize, defaultCaptureQueue),
		batchSize: positiveIntOr(opts.batchSize, defaultCaptureBatch),
	}
	switch {
	case opts.noBatchDelay:
		d.batchDelay = 0
	case opts.batchDelay > 0:
		d.batchDelay = opts.batchDelay
	default:
		d.batchDelay = defaultCaptureDelay
	}
	if d.diagnose == nil {
		d.diagnose = nopCaptureDiagnose
	}
	if d.send == nil {
		d.send = func([]*decidev2.CaptureEvent) error { return nil }
	}
	d.cond = sync.NewCond(&d.mu)
	return d
}

func positiveIntOr(value, fallback int) int {
	if value > 0 {
		return value
	}
	return fallback
}

func eventsFromQueued(items []queuedCapture) []*decidev2.CaptureEvent {
	out := make([]*decidev2.CaptureEvent, len(items))
	for i, item := range items {
		out[i] = item.event
	}
	return out
}

func (d *captureDelivery) capture(event *decidev2.CaptureEvent) {
	if event == nil {
		return
	}
	d.mu.Lock()
	if d.outstanding >= d.queueSize {
		d.mu.Unlock()
		d.diagnose(captureQueueFullCode, 1)
		return
	}
	d.outstanding++
	d.nextSeq++
	d.queue = append(d.queue, queuedCapture{event: event, seq: d.nextSeq})
	d.ensureWorkerLocked()
	d.cond.Signal()
	d.mu.Unlock()
}

func (d *captureDelivery) flush(ctx context.Context) {
	d.mu.Lock()
	if d.outstanding == 0 {
		d.mu.Unlock()
		return
	}
	// Events with seq <= barrier already belonged to this flush. Anything
	// captured after this point is left in the queue if the deadline expires.
	barrier := d.nextSeq
	d.flushNow = true
	d.ensureWorkerLocked()
	d.cond.Broadcast()

	deadline, hasDeadline := ctx.Deadline()
	for d.outstanding > 0 {
		if ctx.Err() != nil {
			d.abandonLocked(barrier)
			d.flushNow = false
			d.mu.Unlock()
			return
		}
		if hasDeadline {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				d.abandonLocked(barrier)
				d.flushNow = false
				d.mu.Unlock()
				return
			}
			timedOut := false
			timer := time.AfterFunc(remaining, func() {
				d.mu.Lock()
				timedOut = true
				d.cond.Broadcast()
				d.mu.Unlock()
			})
			d.cond.Wait()
			timer.Stop()
			if timedOut && d.outstanding > 0 {
				d.abandonLocked(barrier)
				d.flushNow = false
				d.mu.Unlock()
				return
			}
			continue
		}
		d.cond.Wait()
	}
	d.flushNow = false
	d.mu.Unlock()
}

func (d *captureDelivery) abandonLocked(barrier uint64) {
	kept := d.queue[:0]
	dropped := 0
	for _, item := range d.queue {
		if item.seq <= barrier {
			dropped++
			continue
		}
		kept = append(kept, item)
	}
	d.queue = kept
	d.outstanding -= dropped
	if d.outstanding < 0 {
		d.outstanding = 0
	}
	if dropped > 0 {
		d.diagnose(captureFlushExpiredCode, dropped)
	}
	d.cond.Broadcast()
}

func (d *captureDelivery) finish(count int) {
	d.mu.Lock()
	d.outstanding -= count
	if d.outstanding <= 0 {
		d.outstanding = 0
	}
	d.cond.Broadcast()
	d.mu.Unlock()
}

func (d *captureDelivery) ensureWorkerLocked() {
	if d.worker {
		return
	}
	d.worker = true
	go d.run()
}

func (d *captureDelivery) drainAvailable(limit int) []queuedCapture {
	if limit <= 0 || len(d.queue) == 0 {
		return nil
	}
	n := min(limit, len(d.queue))
	taken := d.queue[:n]
	d.queue = d.queue[n:]
	return taken
}

func (d *captureDelivery) collect() []*decidev2.CaptureEvent {
	d.mu.Lock()
	defer d.mu.Unlock()

	if len(d.queue) == 0 {
		if d.flushNow {
			return nil
		}
		timedOut := false
		timer := time.AfterFunc(captureWorkerIdleWait, func() {
			d.mu.Lock()
			timedOut = true
			d.cond.Broadcast()
			d.mu.Unlock()
		})
		for len(d.queue) == 0 && !timedOut && !d.flushNow {
			d.cond.Wait()
		}
		timer.Stop()
		if len(d.queue) == 0 {
			return nil
		}
	}

	first := d.queue[0]
	d.queue = d.queue[1:]
	batch := []queuedCapture{first}
	if d.batchDelay <= 0 || d.flushNow {
		batch = append(batch, d.drainAvailable(d.batchSize-len(batch))...)
		return eventsFromQueued(batch)
	}

	deadline := time.Now().Add(d.batchDelay)
	for len(batch) < d.batchSize {
		if d.flushNow {
			batch = append(batch, d.drainAvailable(d.batchSize-len(batch))...)
			break
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		if len(d.queue) > 0 {
			batch = append(batch, d.queue[0])
			d.queue = d.queue[1:]
			continue
		}
		timedOut := false
		timer := time.AfterFunc(remaining, func() {
			d.mu.Lock()
			timedOut = true
			d.cond.Broadcast()
			d.mu.Unlock()
		})
		for len(d.queue) == 0 && !timedOut && !d.flushNow {
			d.cond.Wait()
		}
		timer.Stop()
		if timedOut && len(d.queue) == 0 && !d.flushNow {
			break
		}
	}
	return eventsFromQueued(batch)
}

func (d *captureDelivery) run() {
	for {
		batch := d.collect()
		if len(batch) == 0 {
			d.mu.Lock()
			if len(d.queue) > 0 {
				d.mu.Unlock()
				continue
			}
			d.worker = false
			d.mu.Unlock()
			return
		}
		if err := d.send(batch); err != nil {
			d.diagnose(captureSendFailedCode, len(batch))
		}
		d.finish(len(batch))
	}
}
