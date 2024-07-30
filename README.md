# Shadow Flow Go (temporary technical name)

Shadow Flow Go is a Go-based project that provides a mechanism to compare the results of two different flows (current
and new) in your application. It's useful for testing new features or changes in your application without affecting the
main flow. It also provides encryption services to encrypt the differences found between the two flows.

## Prerequisites

* Go (version 1.16 or later)

## Features

* Compare the results of two different flows (current and new).
* Log the differences found between the two flows.
* Encrypt the differences using provided encryption services.
* Control the percentage of requests that will be shadowed.
* Support for comparing slices.

## Installation

```shell
go get ssh.dev.azure.com:v3/raboweb/Skunk%20Works/shadow-tool-go
```

## Usage

To use the Shadow Flow in your application, you need to create an instance of `ShadowFlow` using the `New` or
`NewWithEncryptionService` function. Then, you can use the `Compare` or `CompareSlices` functions to compare the results of the
current and new flows. Here is a basic example:

```go
// BackendService it represents an interface for the backend service that will be shadowed
type BackendService interface {
	GetPayload() (Payload, error)
}

// LegacyBackendService it represents a legacy backend service that will be replaced by a new one
type LegacyBackendService struct{}

func (s *LegacyBackendService) GetPayload() (Payload, error) {
	return Payload{Id: 1, Name: "John", Date: "2024-01-01"}, nil
}

// NewBackendService it represents a new backend service that will replace the legacy one
type NewBackendService struct{}

func (s *NewBackendService) GetPayload() (Payload, error) {
	return Payload{Id: 1, Name: "John", Date: "2024-03-01"}, nil
}

// Payload it represents the payload that will be compared to see the differences
type Payload struct {
	Id   int    `json:"id"`
	Name string `json:"name"`
	Date string `json:"date"`
}

func callBackend() (Payload, error) {
	// Create a new ShadowFlow instance with (noop)encryption service
	encryptionService := NewNoopEncryptionService()
	percentage := 1 // 1% of the requests will be shadowed (it might come from a configuration file)
	shadowFlow, err := NewWithEncryptionService("BACKEND_SERVICE_NAME", percentage, encryptionService)
	if err != nil {
		logger.Fatalf("Failed to create ShadowFlow: %v", err)
	}

	legacyService := &LegacyBackendService{}
	newService := &NewBackendService{}

	// run the shadow flow
	response, err := shadowFlow.Compare(
		func() (interface{}, error) { return legacyService.GetPayload() },
		func() (interface{}, error) { return newService.GetPayload() },
	)
	return response.(Payload), err
}
```

### For Contributors Only

```shell
go test
```

### Test with a poor coverage report

```shell
go test -cover
```

### Test with HTML coverage report

```shell
go test -coverprofile=coverage.out && go tool cover -html=coverage.out
```
