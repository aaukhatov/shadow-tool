# shadow-tool

Shadow testing for Go. Run a new implementation next to the current one on a slice of real traffic, compare the results in the background, and log what differs — without ever changing what the caller gets back.

The typical use case is replacing something risky: a backend service, a query, a whole code path. You keep serving responses from the current implementation while the new one runs "in the shadow" for a configurable percentage of calls. When the two results diverge, the differing fields are logged, and the actual values can be encrypted first so response data doesn't leak into your logs.

## Requirements

Go 1.22 or later.

## Installation

```shell
go get github.com/aaukhatov/shadow-tool
```

## How it works

`Compare` calls the current flow synchronously and returns its result — always. Then, for the configured percentage of calls, it runs the new flow in a background goroutine, diffs the two results, and logs the paths of the fields that differ. A slow, failing, or even panicking shadow flow never affects the main flow: errors are skipped, panics are recovered and logged.

Without an encryption service only the *names* of the differing fields are logged. If you construct the flow with an encryption service, the old and new *values* are logged too, encrypted.

## Usage

```go
package main

import (
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

func (s *LegacyBackend) GetPayload() (*Payload, error) {
	return &Payload{Id: 1, Name: "John", Date: "2024-01-01"}, nil
}

// NewBackend is the implementation that should eventually replace it.
type NewBackend struct{}

func (s *NewBackend) GetPayload() (*Payload, error) {
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
	payload, err := flow.Compare(legacy.GetPayload, candidate.GetPayload)
	if err != nil {
		log.Fatalf("backend call failed: %v", err)
	}
	log.Printf("got payload: %+v", payload)

	// On shutdown, wait for in-flight shadow comparisons to finish
	// so no diffs are lost.
	flow.Wait()
}
```

A sampled call with a divergence produces log lines like:

```
[shadow-flow] 2024/03/01 12:00:00 shadow_flow.go:90: [payload-service] Calling new flow: true
[shadow-flow] 2024/03/01 12:00:00 shadow_flow.go:141: [payload-service] The following differences were found: date
```

For slices there is `CompareSlices`, with the same behavior.

### Logging the differing values, encrypted

To see *what* changed and not just *which fields*, create the flow with an encryption service:

```go
service := shadowflow.NewNoopEncryptionService()
flow, err := shadowflow.NewWithEncryptionService[Payload]("payload-service", 1, service)
```

Two implementations ship with the package:

* `NewNoopEncryptionService()` — no encryption at all, it only base64-encodes the values. Fine for local development; don't use it where the logs matter, since base64 is trivially reversible.
* `NewPublicKeyEncryptionService(publicKey)` — encrypts with RSA-OAEP (SHA-256) using your `*rsa.PublicKey`, so only the holder of the private key can read the values. Note that RSA-OAEP caps the message size (about 190 bytes with a 2048-bit key); if a diff is too large to encrypt, the field names are still logged but the values are dropped rather than logged in plain text.

You can also implement the one-method `EncryptionService` interface yourself, for example to use AES-GCM with a key from your secret manager.

## Contributing

Run the tests with the race detector — the whole point of this library is doing work concurrently, so `-race` is part of the baseline:

```shell
go test -race ./...
```

With a coverage report:

```shell
go test -race -cover ./...
```

Or an HTML one:

```shell
go test -coverprofile=coverage.out && go tool cover -html=coverage.out
```
