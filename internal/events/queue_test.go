package events

import (
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/mirage-shield/mirage/internal/model"
)

// ev builds a fixture event identified by its timestamp; tests rely on ts
// being unique to verify order, losses and duplicates.
func ev(ts int64) model.Event {
	return model.Event{
		ProtocolVersion: model.ProtocolVersion,
		TsMs:            ts,
		SessionKey:      fmt.Sprintf("sess-%d", ts),
		ClientIP:        "203.0.113.7",
		Method:          "GET",
		Path:            fmt.Sprintf("/p/%d", ts),
	}
}

func TestNewQueueCapacityClamp(t *testing.T) {
	cases := []struct {
		requested, want int
	}{
		{requested: -1, want: DefaultQueueCapacity},
		{requested: 0, want: DefaultQueueCapacity},
		{requested: 1, want: MinQueueCapacity},
		{requested: 99, want: MinQueueCapacity},
		{requested: 100, want: 100},
		{requested: 10_000, want: 10_000},
		{requested: 1_000_000, want: MaxQueueCapacity},
		{requested: 2_000_000, want: MaxQueueCapacity},
	}
	for _, tc := range cases {
		q := NewQueue(tc.requested)
		// White-box: capacity is the backing ring size (this file lives in
		// the package precisely so the clamp can be asserted directly
		// instead of by pushing a million events).
		if got := len(q.buf); got != tc.want {
			t.Errorf("NewQueue(%d) capacity = %d, want %d", tc.requested, got, tc.want)
		}
	}
}

func TestQueueFIFOOrder(t *testing.T) {
	q := NewQueue(100)
	for i := int64(1); i <= 5; i++ {
		if ok := q.Emit(ev(i)); !ok {
			t.Fatalf("Emit(%d) = false on a non-full queue, want true", i)
		}
	}
	got := q.Drain(5)
	if len(got) != 5 {
		t.Fatalf("Drain returned %d events, want 5", len(got))
	}
	for i, e := range got {
		if e.TsMs != int64(i+1) {
			t.Errorf("Drain[%d].TsMs = %d, want %d (FIFO)", i, e.TsMs, i+1)
		}
	}
	if q.Len() != 0 {
		t.Errorf("Len() = %d after draining everything, want 0", q.Len())
	}
	if q.Dropped() != 0 {
		t.Errorf("Dropped() = %d with no overflow, want 0", q.Dropped())
	}
}

func TestQueueDrainPartial(t *testing.T) {
	q := NewQueue(100)
	for i := int64(1); i <= 5; i++ {
		q.Emit(ev(i))
	}
	first := q.Drain(2)
	if len(first) != 2 || first[0].TsMs != 1 || first[1].TsMs != 2 {
		t.Fatalf("Drain(2) = %+v, want ts [1 2]", first)
	}
	if q.Len() != 3 {
		t.Fatalf("Len() = %d after Drain(2) of 5, want 3", q.Len())
	}
	// Asking for more than remains drains exactly what remains.
	rest := q.Drain(100)
	if len(rest) != 3 || rest[0].TsMs != 3 || rest[2].TsMs != 5 {
		t.Fatalf("Drain(100) = %+v, want ts [3 4 5]", rest)
	}
	if got := q.Drain(1); len(got) != 0 {
		t.Fatalf("Drain on empty queue returned %+v, want nothing", got)
	}
}

func TestQueueDrainNonPositive(t *testing.T) {
	q := NewQueue(100)
	for i := int64(1); i <= 3; i++ {
		q.Emit(ev(i))
	}
	for _, n := range []int{0, -7} {
		if got := q.Drain(n); len(got) != 0 {
			t.Errorf("Drain(%d) = %+v, want nothing", n, got)
		}
	}
	if q.Len() != 3 {
		t.Errorf("Len() = %d after non-positive drains, want 3 (nothing removed)", q.Len())
	}
}

func TestEmitDropsOldestWhenFull(t *testing.T) {
	q := NewQueue(100)
	for i := int64(1); i <= 100; i++ {
		if ok := q.Emit(ev(i)); !ok {
			t.Fatalf("Emit(%d) = false before the queue is full, want true", i)
		}
	}
	if ok := q.Emit(ev(101)); ok {
		t.Fatal("Emit on a full queue = true, want false (something was dropped)")
	}
	if q.Dropped() != 1 {
		t.Fatalf("Dropped() = %d, want 1", q.Dropped())
	}
	if q.Len() != 100 {
		t.Fatalf("Len() = %d after overflow, want 100 (still at capacity)", q.Len())
	}
	got := q.Drain(100)
	if len(got) != 100 {
		t.Fatalf("Drain returned %d events, want 100", len(got))
	}
	// The oldest (ts 1) was evicted; the newcomer (ts 101) is kept.
	if got[0].TsMs != 2 {
		t.Errorf("oldest surviving event ts = %d, want 2 (ts 1 was dropped)", got[0].TsMs)
	}
	if got[len(got)-1].TsMs != 101 {
		t.Errorf("newest event ts = %d, want 101 (kept)", got[len(got)-1].TsMs)
	}
	for i := 1; i < len(got); i++ {
		if got[i].TsMs != got[i-1].TsMs+1 {
			t.Fatalf("order broken at %d: %d after %d", i, got[i].TsMs, got[i-1].TsMs)
		}
	}
}

func TestTryEmitDropsNewestWhenFull(t *testing.T) {
	q := NewQueue(100)
	for i := int64(1); i <= 100; i++ {
		q.TryEmit(ev(i))
	}
	if ok := q.TryEmit(ev(999)); ok {
		t.Fatal("TryEmit on a full queue = true, want false (the new event was dropped)")
	}
	if q.Dropped() != 1 {
		t.Fatalf("Dropped() = %d, want 1", q.Dropped())
	}
	if q.Len() != 100 {
		t.Fatalf("Len() = %d after rejected TryEmit, want 100 (queue untouched)", q.Len())
	}
	got := q.Drain(100)
	if len(got) != 100 {
		t.Fatalf("Drain returned %d events, want 100", len(got))
	}
	if got[0].TsMs != 1 || got[99].TsMs != 100 {
		t.Errorf("queued history = [%d .. %d], want [1 .. 100] intact", got[0].TsMs, got[99].TsMs)
	}
	for _, e := range got {
		if e.TsMs == 999 {
			t.Error("rejected event 999 must not appear in the queue")
		}
	}
}

func TestQueueLenConsistency(t *testing.T) {
	q := NewQueue(100)
	calls := 0
	for i := int64(1); i <= 150; i++ {
		// Every Emit call enters exactly one event — appending when there is
		// room, evicting the oldest when there is not. So Len is
		// min(calls, capacity) and Dropped is the overflow, always.
		calls++
		if ok := q.Emit(ev(i)); ok != (calls <= 100) {
			t.Fatalf("Emit call %d = %v, want %v (true only before the queue is full)", calls, ok, calls <= 100)
		}
		if q.Len() != min(calls, 100) {
			t.Fatalf("Len() = %d after %d Emit calls, want %d", q.Len(), calls, min(calls, 100))
		}
		calls++ // negative ts: a second emit per iteration
		if ok := q.Emit(ev(-i)); ok != (calls <= 100) {
			t.Fatalf("Emit call %d = %v, want %v", calls, ok, calls <= 100)
		}
		if q.Len() != min(calls, 100) {
			t.Fatalf("Len() = %d after %d Emit calls, want %d", q.Len(), calls, min(calls, 100))
		}
	}
	if q.Dropped() != uint64(calls-100) {
		t.Fatalf("Dropped() = %d, want %d (every enter beyond capacity evicted one)", q.Dropped(), calls-100)
	}
	remaining := q.Len()
	for remaining > 0 {
		q.Drain(7)
		remaining -= min(7, remaining)
		if q.Len() != remaining {
			t.Fatalf("Len() = %d after draining, want %d", q.Len(), remaining)
		}
	}
}

func TestQueueWrapAround(t *testing.T) {
	q := NewQueue(100)
	// Fill, drain part, then push past the ring's end so head/tail wrap.
	for i := int64(1); i <= 100; i++ {
		q.Emit(ev(i))
	}
	q.Drain(60)
	if q.Len() != 40 {
		t.Fatalf("Len() = %d after draining 60, want 40", q.Len())
	}
	for i := int64(101); i <= 160; i++ {
		q.Emit(ev(i))
	}
	if q.Len() != 100 {
		t.Fatalf("Len() = %d after refill, want 100", q.Len())
	}
	got := q.Drain(110)
	if len(got) != 100 {
		t.Fatalf("Drain returned %d events, want 100", len(got))
	}
	// FIFO across the wrap: the 40 survivors first, then the 60 newcomers.
	if got[0].TsMs != 61 || got[39].TsMs != 100 || got[40].TsMs != 101 || got[99].TsMs != 160 {
		t.Fatalf("wrapped order = [%d .. %d, %d .. %d], want [61 .. 100, 101 .. 160]",
			got[0].TsMs, got[39].TsMs, got[40].TsMs, got[99].TsMs)
	}
	if q.Dropped() != 0 {
		t.Errorf("Dropped() = %d on a wrap without overflow, want 0", q.Dropped())
	}
	if q.Len() != 0 {
		t.Errorf("Len() = %d after draining everything, want 0", q.Len())
	}
}

func TestQueueConcurrentEmitDrain(t *testing.T) {
	q := NewQueue(1000)

	// Unique ts for every event so losses and duplicates are detectable.
	var nextTS atomic.Int64
	var emitCalls, tryCalls, tryOK, drained atomic.Int64

	// Collect everything ever returned so it can be checked at the end.
	var mu sync.Mutex
	var all []model.Event
	record := func(batch []model.Event) {
		mu.Lock()
		all = append(all, batch...)
		mu.Unlock()
	}

	var producers sync.WaitGroup
	for g := 0; g < 8; g++ {
		producers.Add(1)
		go func() {
			defer producers.Done()
			for i := 0; i < 2000; i++ {
				e := ev(nextTS.Add(1))
				q.Emit(e)
				emitCalls.Add(1)
			}
		}()
	}
	for g := 0; g < 4; g++ {
		producers.Add(1)
		go func() {
			defer producers.Done()
			for i := 0; i < 1000; i++ {
				e := ev(nextTS.Add(1))
				if q.TryEmit(e) {
					tryOK.Add(1)
				}
				tryCalls.Add(1)
			}
		}()
	}
	// done closes once every producer has finished; after that an empty
	// drain really means the queue is finished.
	done := make(chan struct{})
	go func() {
		producers.Wait()
		close(done)
	}()

	var drainers sync.WaitGroup
	for g := 0; g < 4; g++ {
		drainers.Add(1)
		go func() {
			defer drainers.Done()
			for {
				batch := q.Drain(64)
				if len(batch) > 0 {
					drained.Add(int64(len(batch)))
					record(batch)
					continue
				}
				select {
				case <-done:
					return
				default:
					runtime.Gosched() // queue empty, producers still running
				}
			}
		}()
	}
	drainers.Wait()

	// Whatever the drainers did not take is still queued; take it too.
	finalLen := int64(q.Len())
	finalBatch := q.Drain(1_000_000)
	record(finalBatch)
	if q.Len() != 0 {
		t.Fatalf("Len() = %d after draining everything, want 0", q.Len())
	}
	if int64(len(finalBatch)) != finalLen {
		t.Fatalf("final drain returned %d events, want %d", len(finalBatch), finalLen)
	}

	// Conservation: entered == drained + still-queued + evicted, where
	// evicted = dropped - TryEmit rejections (those never entered).
	entered := emitCalls.Load() + tryOK.Load()
	tryRejected := tryCalls.Load() - tryOK.Load()
	if q.Dropped() < uint64(tryRejected) {
		t.Fatalf("Dropped() = %d < TryEmit rejections %d: impossible accounting", q.Dropped(), tryRejected)
	}
	evicted := int64(q.Dropped()) - tryRejected
	if got, want := int64(len(all)), entered-evicted; got != want {
		t.Fatalf("returned %d events, want %d (entered %d - evicted %d)", got, want, entered, evicted)
	}
	if drained.Load()+int64(len(finalBatch)) != int64(len(all)) {
		t.Fatalf("drained %d + final %d != collected %d", drained.Load(), len(finalBatch), len(all))
	}

	// No event may be returned twice or lost without being counted.
	seen := make(map[int64]bool, len(all))
	for _, e := range all {
		if seen[e.TsMs] {
			t.Fatalf("event ts %d returned twice", e.TsMs)
		}
		seen[e.TsMs] = true
	}
	if int64(len(seen)) != entered-evicted {
		t.Fatalf("%d unique events returned, want %d", len(seen), entered-evicted)
	}
}
