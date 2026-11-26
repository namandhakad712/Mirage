// Package events holds the bounded event queue that sits between adapters
// and Core's persistence (ADAPTER-PROTOCOL section 4). Emission is
// asynchronous and must never block the request path; when the queue is
// full the producer picks a drop policy — evict the oldest entry (Emit) or
// reject the new event (TryEmit) — and a drop counter records every loss.
package events

import (
	"sync"
	"sync/atomic"

	"github.com/mirage-shield/mirage/internal/model"
)

// Queue capacity bounds. The protocol default is 10 000 events.
const (
	MinQueueCapacity     = 100
	MaxQueueCapacity     = 1_000_000
	DefaultQueueCapacity = 10_000
)

// Queue is a bounded FIFO of events backed by a ring buffer guarded by a
// mutex.
//
// Why not a channel: a channel send cannot evict the oldest queued element —
// it either blocks (which the protocol forbids on the hot path) or fails and
// loses the newest event, and draining to make room races with other
// producers. A mutex around a ring buffer expresses drop-oldest exactly;
// at request-volume rates the microsecond critical section is not a
// bottleneck.
type Queue struct {
	mu   sync.Mutex
	buf  []model.Event
	head int // index of the oldest event
	size int
	// dropped is atomic so Dropped stays readable without queueing behind
	// a busy lock (metrics readers must not contend with emitters).
	dropped atomic.Uint64
}

// NewQueue returns a queue with the requested capacity clamped to
// [MinQueueCapacity, MaxQueueCapacity]. An invalid capacity (zero or
// negative) becomes DefaultQueueCapacity, per the protocol default.
// The zero Queue is not usable — always construct through NewQueue.
func NewQueue(capacity int) *Queue {
	switch {
	case capacity <= 0:
		capacity = DefaultQueueCapacity
	case capacity < MinQueueCapacity:
		capacity = MinQueueCapacity
	case capacity > MaxQueueCapacity:
		capacity = MaxQueueCapacity
	}
	return &Queue{buf: make([]model.Event, capacity)}
}

// Emit appends ev without ever blocking. When the queue is full the OLDEST
// entry is evicted to make room and the drop counter increments. It returns
// true when nothing had to be dropped for this event.
func (q *Queue) Emit(ev model.Event) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.size == len(q.buf) {
		// Full: the new event takes the oldest slot, and head advances past
		// it — the overwritten entry is the one that was drained first.
		q.buf[q.head] = ev
		q.head = (q.head + 1) % len(q.buf)
		q.dropped.Add(1)
		return false
	}
	q.buf[(q.head+q.size)%len(q.buf)] = ev
	q.size++
	return true
}

// TryEmit appends ev only when the queue has room; when full it drops the
// NEW event instead (queued history wins) and increments the drop counter.
// Adapters pick whichever policy suits them.
func (q *Queue) TryEmit(ev model.Event) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.size == len(q.buf) {
		q.dropped.Add(1)
		return false
	}
	q.buf[(q.head+q.size)%len(q.buf)] = ev
	q.size++
	return true
}

// Drain removes and returns up to n oldest remaining events, in FIFO order.
// n <= 0 returns nothing.
func (q *Queue) Drain(n int) []model.Event {
	q.mu.Lock()
	defer q.mu.Unlock()
	if n <= 0 || q.size == 0 {
		return nil
	}
	if n > q.size {
		n = q.size
	}
	out := make([]model.Event, n)
	for i := 0; i < n; i++ {
		out[i] = q.buf[q.head]
		// Release the decision graph reference so drained slots do not pin
		// memory until they are overwritten.
		q.buf[q.head] = model.Event{}
		q.head = (q.head + 1) % len(q.buf)
	}
	q.size -= n
	return out
}

// Len reports the number of queued events.
func (q *Queue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.size
}

// Dropped reports how many events have been lost since construction: both
// oldest entries evicted by Emit and newcomers rejected by TryEmit.
func (q *Queue) Dropped() uint64 {
	return q.dropped.Load()
}
