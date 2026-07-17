# shadow-tool

Shadow testing for Go. Run a new implementation next to the current one on a slice of real traffic, compare the results
in the background, and log what differs – without ever changing what the caller gets back.

The typical use case is replacing something risky: a backend service, a query, a whole code path. You keep serving
responses from the current implementation while the new one runs "in the shadow" for a configurable percentage of calls.
When the two results diverge, the differing fields are logged, and the actual values can be encrypted first so response
data doesn't leak into your logs.

## Requirements

Go 1.22 or later.

## Installation

```shell
go get github.com/aaukhatov/shadow-tool
```

## How it works

`Compare` calls the current flow synchronously and returns its result – always. Then, for the configured percentage of
calls, it runs the new flow in a background goroutine, diffs the two results, and logs the paths of the fields that
differ. A slow, failing, or even panicking shadow flow never affects the main flow: errors and panics are logged, never
propagated.

Both results are normalised through a JSON round-trip before the diff, so you are free to mutate the returned value
immediately and only differences that survive `encoding/json` are reported - unexported fields and fields tagged
`json:"-"` are never compared. The shadow flow receives a context derived
with `context.WithoutCancel`, so it keeps the request's values (trace IDs) but is not canceled together with the
request; it is bounded by a 10-second default timeout so a hung new flow can't hold its concurrency slot forever, and
that timeout can be changed with `WithShadowTimeout` or removed entirely with `WithoutShadowTimeout`. At most 100
shadow flows run concurrently by default – sampled calls beyond the cap are skipped, never queued – and the cap is
configurable with `WithMaxConcurrentShadows`.

Without an encryption service, only the *names* of the differing fields are logged. If you construct the flow with an
encryption service, the old and new *values* are logged too, encrypted.

**Error-path parity is out of scope.** If the current flow returns an error, the shadow comparison is skipped
entirely – the new flow is never called, so you can't learn whether it would have failed the same way, failed
differently, or succeeded. If the new flow itself returns an error, that's only logged at `Warn` level; it is never
compared against the current flow's (successful) result. This library diffs successful outputs on the happy path –
it is not a substitute for monitoring the new flow's own error rate once it's live.

## Usage

```go
package main

import (
	"context"
	"log"

	shadowflow "github.com/aaukhatov/shadow-tool"
)

// Payload is the response we want to compare across the two implementations.
type Payload struct {
	Id   int    `json:"id"`
	Name string `json:"name"`
	Date string `json:"date"`
}

// LegacyBackend is the implementation currently serving traffic.
type LegacyBackend struct{}

func (s *LegacyBackend) GetPayload(ctx context.Context) (*Payload, error) {
	return &Payload{Id: 1, Name: "John", Date: "2024-01-01"}, nil
}

// NewBackend is the implementation that should eventually replace it.
type NewBackend struct{}

func (s *NewBackend) GetPayload(ctx context.Context) (*Payload, error) {
	return &Payload{Id: 1, Name: "John", Date: "2024-03-01"}, nil
}

func main() {
	// Shadow 1% of the calls. In a real application the percentage usually
	// comes from configuration, so it can be dialed up gradually.
	flow, err := shadowflow.New[Payload]("payload-service", 1)
	if err != nil {
		log.Fatalf("failed to create the shadow flow: %v", err)
	}

	legacy := &LegacyBackend{}
	candidate := &NewBackend{}

	// The caller always gets the legacy result. On sampled calls the new
	// backend also runs in the background and differences are logged.
	payload, err := flow.Compare(context.Background(), legacy.GetPayload, candidate.GetPayload)
	if err != nil {
		log.Fatalf("backend call failed: %v", err)
	}
	log.Printf("got payload: %+v", payload)

	// On shutdown, wait for in-flight shadow comparisons to finish so no
	// diffs are lost. Stop issuing Compare calls first (e.g. shut down the
	// HTTP server), then drain the shadow flows.
	flow.Wait()
}
```

A sampled call with a divergence produces a log line like:

```
time=2024-03-01T12:00:00.000Z level=INFO msg="differences found" component=shadow-flow instance=payload-service properties=date
```

For slice-returning flows there is `CompareSlices`, with the same behavior but flows shaped
`func(context.Context) ([]T, error)`.

### Logging

The shadow flow logs through `log/slog`. By default it uses `slog.Default()`, so the output lands wherever your
application already sends its logs - the library does not impose a destination or a format of its own. The instance name
is attached as an `instance` attribute rather than interpolated into the message, so you can filter on it.

Four levels are used:

| Level   | Logged                                                                                                                                                                     |
|---------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `Debug` | Each sampled call, as the shadow flow starts, and sampled calls skipped because the concurrency cap was reached. Off by default; enable it to confirm sampling is working. |
| `Info`  | The fields that differ, and the encrypted values when an encryption service is configured.                                                                                 |
| `Warn`  | A shadow flow that returned an error or a nil result.                                                                                                                      |
| `Error` | A shadow flow that panicked, failures to diff the two responses, and failures to copy the response for comparison.                                                         |

To send the output somewhere other than `slog.Default()`, pass the `WithLogger` option:

```go
flow, err := shadowflow.New[Payload]("payload-service", 1,
shadowflow.WithLogger(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))),
)
```

Backends other than slog work through their slog bridge - [`zapslog`](https://pkg.go.dev/go.uber.org/zap/exp/zapslog)
for zap, or the [`samber/slog-*`](https://github.com/samber/slog-zerolog) family for zerolog, logrus, and others. No
adapter code of your own is needed.

### Logging the differing values, encrypted

To see *what* changed and not just *which fields*, create the flow with an encryption service:

```go
service := shadowflow.NewNoopEncryptionService()
flow, err := shadowflow.New[Payload]("payload-service", 1, shadowflow.WithEncryptionService(service))
```

Two implementations ship with the package:

* `NewNoopEncryptionService()` - no encryption at all, it only base64-encodes the values. Fine for local development;
  don't use it where the logs matter, since base64 is trivially reversible.
* `NewPublicKeyEncryptionService(publicKey)` - encrypts with RSA-OAEP (SHA-256) using your `*rsa.PublicKey`, so only the
  holder of the private key can read the values. Note that RSA-OAEP caps the message size (about 190 bytes with a
  2048-bit key); if a diff is too large to encrypt, the field names are still logged, but the values are dropped rather
  than logged in plain text.

With an encryption service configured, a divergence produces a log line like:

```
time=2024-03-01T12:00:00.000Z level=INFO msg="differences found" component=shadow-flow instance=payload-service count=1 encrypted_values="mzHJ..."
```

The differing field paths are *not* logged in plain text by default: diff paths include map keys, which may themselves
be sensitive (say, a map keyed by e-mail address). The full paths travel inside the encrypted payload. If your responses
carry no sensitive map keys and you want the paths visible for quick triage, opt back in with
`shadowflow.WithPlaintextProperties()`.

You can also implement the one-method `EncryptionService` interface yourself, for example to use AES-GCM with a key from
your secret manager.

### Other options

* `WithShadowTimeout(d)` - cancels the context passed to the shadow flow after `d`, instead of the 10-second default.
* `WithoutShadowTimeout()` - removes the default timeout, so the shadow flow runs until it returns on its own. A hung
  new flow then holds its concurrency slot indefinitely, so prefer `WithShadowTimeout` unless the new flow is already
  known to be bounded.
* `WithMaxConcurrentShadows(n)` - caps the number of shadow flows running at the same time (default 100). Sampled calls
  beyond the cap are skipped, never queued, so a slow new flow cannot pile up goroutines.
* `WithPlaintextProperties()` - logs the differing field paths in plain text next to the encrypted values (see above).

## Contributing

Run the tests with the race detector - the whole point of this library is doing work concurrently, so `-race` is part of
the baseline:

```shell
go test -race
```

With a coverage report:

```shell
go test -race -cover
```

Or an HTML one:

```shell
go test -coverprofile=coverage.out && go tool cover -html=coverage.out
```
