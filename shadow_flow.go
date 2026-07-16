package shadowflow

import (
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"strconv"
	"strings"
	"sync"

	"github.com/r3labs/diff/v3"
)

type ShadowFlow[T any] struct {
	percentage        int               // percentage of the requests that will be shadowed
	logger            *slog.Logger      // logger receiving the shadow flow output, slog.Default() unless set; carries the instance name
	encryptionService EncryptionService // encryptionService encrypting data diff, helps to prevent data leak
	waitGroup         sync.WaitGroup    // waitGroup take a control over the goroutines
}

func New[T any](instance string, percentage int, opts ...Option) (*ShadowFlow[T], error) {
	err := checkArgs(instance, percentage)
	if err != nil {
		return nil, err
	}

	var cfg config
	for _, opt := range opts {
		if err := opt(&cfg); err != nil {
			return nil, err
		}
	}

	logger := cfg.logger
	if logger == nil {
		logger = slog.Default()
	}
	// Bind the instance once so every log line carries it as an attribute.
	logger = logger.With(slog.String("component", "shadow-flow"), slog.String("instance", instance))

	shadowFlow := &ShadowFlow[T]{
		percentage:        percentage,
		logger:            logger,
		encryptionService: cfg.encryptionService,
	}

	return shadowFlow, nil
}

// NewWithEncryptionService creates a ShadowFlow that logs the changed values
// encrypted with the given service. Prefer New with the WithEncryptionService
// option.
func NewWithEncryptionService[T any](instance string, percentage int, encryptionService EncryptionService) (*ShadowFlow[T], error) {
	return New[T](instance, percentage, WithEncryptionService(encryptionService))
}

func checkArgs(instance string, percentage int) error {
	if instance == "" {
		return errors.New("instance name must be provided")
	}

	if percentage < 0 || percentage > 100 {
		return errors.New("percentage must be between 0 and 100")
	}
	return nil
}

// Compare runs the current flow and, based on a random percentage, may also run the new flow.
// If the new flow is run, it compares the results of the current and new flows, logs the differences,
// and optionally encrypts and logs the changed values if an encryption service is provided.
// It always returns the result of the current flow.
//
// currentFlow: A function that when called, returns the result of the current flow.
// newFlow: A function that when called, returns the result of the new flow.
//
// Returns: The result of the current flow.
func (s *ShadowFlow[T]) Compare(currentFlow func() (*T, error), newFlow func() (*T, error)) (*T, error) {
	originalResponse, err := currentFlow()

	if err == nil && s.shouldCallNewFlow() {
		s.waitGroup.Add(1)
		s.logger.Debug("calling new flow")
		go func() {
			defer s.waitGroup.Done()
			defer s.recoverPanic()
			shadowResponse, shdErr := newFlow()
			if shadowResponse != nil && shdErr == nil {
				s.diff(originalResponse, shadowResponse)
			}
		}()
	}
	return originalResponse, err
}

func (s *ShadowFlow[T]) CompareSlices(currentFlow func() (*[]T, error), newFlow func() (*[]T, error)) (*[]T, error) {
	originalResponse, err := currentFlow()

	if err == nil && s.shouldCallNewFlow() {
		s.waitGroup.Add(1)
		s.logger.Debug("calling new flow")
		go func() {
			defer s.waitGroup.Done()
			defer s.recoverPanic()
			shadowResponse, shdErr := newFlow()
			if shadowResponse != nil && shdErr == nil {
				s.diff(originalResponse, shadowResponse)
			}
		}()
	}
	return originalResponse, err
}

// Wait blocks until every in-flight shadow comparison has finished.
// Call it on graceful shutdown so pending diffs are not lost when the process exits.
func (s *ShadowFlow[T]) Wait() {
	s.waitGroup.Wait()
}

// recoverPanic keeps a panicking shadow flow from crashing the host application:
// the shadow path must never affect the main flow.
func (s *ShadowFlow[T]) recoverPanic() {
	if r := recover(); r != nil {
		s.logger.Error("recovered from panic in shadow flow", slog.Any("panic", r))
	}
}

func (s *ShadowFlow[T]) diff(originalResponse interface{}, shadowResponse interface{}) {
	changelog, err := diff.Diff(originalResponse, shadowResponse)
	if err != nil {
		s.logger.Error("failed to compare shadow flow responses", slog.Any("error", err))
		return
	}

	if len(changelog) == 0 {
		return
	}

	changedProperties := make([]string, 0)
	changedValues := make([]string, 0)

	for _, change := range changelog {
		fieldPath := toFullPath(change)
		changedProperties = append(changedProperties, fieldPath)
		changedValues = append(changedValues, prettyPrintDiff(fieldPath, change))
	}

	properties := strings.Join(changedProperties, ", ")
	if s.encryptionService == nil {
		s.logger.Info("differences found", slog.String("properties", properties))
		return
	}

	encryptedValues, err := s.encryptionService.Encrypt(strings.Join(changedValues, "\n"))
	if err != nil {
		// Log only the property names on failure — the values stay confidential.
		s.logger.Info("differences found",
			slog.String("properties", properties),
			slog.Any("encrypt_error", err),
		)
		return
	}
	s.logger.Info("differences found",
		slog.String("properties", properties),
		slog.String("encrypted_values", encryptedValues),
	)
}

// shouldCallNewFlow samples the traffic percentage. The top-level math/rand/v2
// functions are safe for concurrent use, unlike a seeded *rand.Rand instance.
func (s *ShadowFlow[T]) shouldCallNewFlow() bool {
	return rand.IntN(100) < s.percentage
}

func prettyPrintDiff(fieldPath string, change diff.Change) string {
	return fmt.Sprintf("'%s' %s: '%s' -> '%s'", fieldPath, change.Type, toString(change.From), toString(change.To))
}

func toFullPath(change diff.Change) string {
	return strings.Join(change.Path, ".")
}

func toString(value interface{}) string {
	switch v := value.(type) {
	case int:
		return strconv.Itoa(v)
	case float64:
		return fmt.Sprintf("%f", v)
	case bool:
		return strconv.FormatBool(v)
	case string:
		return v
	default:
		return fmt.Sprintf("%v", v)
	}
}
