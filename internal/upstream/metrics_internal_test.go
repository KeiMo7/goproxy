package upstream

import (
	"sync"
	"testing"
)

// TestEventSinkCloseIsRaceFree exercises concurrent emit and close: an event
// emitted after (or during) close must be dropped, never panic on a closed
// channel, and close must never block on a slow observer.
func TestEventSinkCloseIsRaceFree(t *testing.T) {
	var mu sync.Mutex
	delivered := 0
	sink := newEventSink(func(Event) {
		mu.Lock()
		delivered++
		mu.Unlock()
	})
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				sink.emit(Event{Kind: EventNew, Target: "example.com:443"})
			}
		}()
	}
	sink.close()
	wg.Wait()
	sink.emit(Event{Kind: EventNew, Target: "late"})
	sink.close() // idempotent
	<-sink.done
	mu.Lock()
	defer mu.Unlock()
	if delivered > eventBuffer+100 {
		t.Fatalf("delivered %d events, want at most the buffer plus in-flight", delivered)
	}
}

// TestEventSinkSlowObserverDoesNotBlock proves emit never waits for a stuck
// observer once the buffer is full.
func TestEventSinkSlowObserverDoesNotBlock(t *testing.T) {
	release := make(chan struct{})
	sink := newEventSink(func(Event) { <-release })
	defer func() {
		close(release)
		sink.close()
	}()
	for i := 0; i < eventBuffer*4; i++ {
		sink.emit(Event{Kind: EventNew})
	}
}
