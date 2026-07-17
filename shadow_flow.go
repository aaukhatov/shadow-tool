package shadowflow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/r3labs/diff/v3"
)

// defaultMaxConcurrentShadows caps the number of in-flight shadow flows when
// WithMaxConcurrentShadows is not set, so a slow new flow under high traffic
// cannot accumulate goroutines without bound.
const defaultMaxConcurrentShadows = 100

// defaultShadowTimeout bounds each shadow flow call when neither
// WithShadowTimeout nor WithoutShadowTimeout is set, so a hung new flow
// cannot hold its concurrency slot (and, transitively, all of them) forever.
const defaultShadowTimeout = 10 * time.Second

// ShadowFlow runs a new code path alongside an existing one on a sample of
// traffic, diffs their results, and logs what changed.
type ShadowFlow[T any] struct {
	percentage          int               // percentage of the requests that will be shadowed
	logger              *slog.Logger      // logger receiving the shadow flow output, slog.Default() unless set; carries the instance name
	encryptionService   EncryptionService // encryptionService encrypting data diff, helps to prevent data leak
	shadowTimeout       time.Duration     // shadowTimeout bounds each shadow flow call; defaultShadowTimeout unless overridden, 0 if WithoutShadowTimeout was set
	plaintextProperties bool              // plaintextProperties keeps the differing field paths in plain text next to the encrypted values
	semaphore           chan struct{}     // semaphore caps the number of concurrent shadow flows
	waitGroup           sync.WaitGroup    // waitGroup tracks in-flight shadow goroutines for Wait
}

// New creates a ShadowFlow for the given instance name, sampling percentage
// (0-100), and options.
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

	if cfg.shadowTimeout > 0 && cfg.noShadowTimeout {
		return nil, errors.New("cannot combine WithShadowTimeout and WithoutShadowTimeout")
	}

	logger := cfg.logger
	if logger == nil {
		logger = slog.Default()
	}
	// Bind the instance once so every log line carries it as an attribute.
	logger = logger.With(slog.String("component", "shadow-flow"), slog.String("instance", instance))

	maxConcurrentShadows := cfg.maxConcurrentShadows
	if maxConcurrentShadows == 0 {
		maxConcurrentShadows = defaultMaxConcurrentShadows
	}

	shadowTimeout := cfg.shadowTimeout
	if shadowTimeout == 0 && !cfg.noShadowTimeout {
		shadowTimeout = defaultShadowTimeout
	}

	shadowFlow := &ShadowFlow[T]{
		percentage:          percentage,
		logger:              logger,
		encryptionService:   cfg.encryptionService,
		shadowTimeout:       shadowTimeout,
		plaintextProperties: cfg.plaintextProperties,
		semaphore:           make(chan struct{}, maxConcurrentShadows),
	}

	return shadowFlow, nil
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
// The context is passed to currentFlow as-is. The new flow runs in the
// background on a context derived with context.WithoutCancel, so it keeps the
// request's values (trace IDs) but is not cancelled together with the
// request; it is instead bounded by a default timeout of 10 seconds unless
// overridden with WithShadowTimeout, or left unbounded with
// WithoutShadowTimeout.
//
// Both results are normalised through a JSON round-trip before comparison, so
// the caller may mutate the returned value right away and only differences
// that survive encoding/json are reported: unexported fields and fields
// tagged `json:"-"` are never compared.
//
// currentFlow: A function that when called with ctx, returns the result of the current flow.
// newFlow: A function that when called with ctx, returns the result of the new flow.
//
// If currentFlow returns a nil result with a nil error, the shadow comparison
// is skipped entirely (newFlow is not called) since there is nothing
// meaningful to diff against; this is logged at debug level.
//
// Returns: The result of the current flow.
func (s *ShadowFlow[T]) Compare(ctx context.Context, currentFlow, newFlow func(context.Context) (*T, error)) (*T, error) {
	return compareFlows(ctx, s, currentFlow, newFlow)
}

// CompareSlices is the slice-returning counterpart to Compare: it runs
// currentFlow, samples the traffic percentage to decide whether to also run
// newFlow, and logs the differences between the two slice results.
func (s *ShadowFlow[T]) CompareSlices(ctx context.Context, currentFlow, newFlow func(context.Context) ([]T, error)) ([]T, error) {
	toPointerFlow := func(flow func(context.Context) ([]T, error)) func(context.Context) (*[]T, error) {
		return func(ctx context.Context) (*[]T, error) {
			result, err := flow(ctx)
			return &result, err
		}
	}

	result, err := compareFlows(ctx, s, toPointerFlow(currentFlow), toPointerFlow(newFlow))
	if result == nil {
		return nil, err
	}
	return *result, err
}

// compareFlows carries the shared Compare/CompareSlices implementation; it is
// a package-level function because methods cannot introduce the extra type
// parameter for the response.
func compareFlows[T, R any](ctx context.Context, s *ShadowFlow[T], currentFlow, newFlow func(context.Context) (*R, error)) (*R, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	originalResponse, err := currentFlow(ctx)
	if err == nil && originalResponse == nil {
		s.logger.Debug("shadow flow skipped: current flow returned a nil result")
		return originalResponse, nil
	}
	if err != nil || !s.shouldCallNewFlow() {
		return originalResponse, err
	}

	select {
	case s.semaphore <- struct{}{}:
	default:
		s.logger.Debug("shadow flow skipped: concurrency limit reached")
		return originalResponse, nil
	}

	// Snapshot the response so the caller may mutate it after Compare returns
	// while the shadow comparison is still running. Only the Marshal half must
	// happen synchronously, before that mutation can occur; the matching
	// Unmarshal only reads these already-snapshotted bytes, so it moves into
	// the goroutine to keep it off the caller's request path.
	originalData, marshalErr := json.Marshal(originalResponse)
	if marshalErr != nil {
		<-s.semaphore
		s.logger.Error("failed to copy response for shadow comparison", slog.Any("error", marshalErr))
		return originalResponse, nil
	}

	// The shadow flow keeps the request's values (trace IDs) but must not be
	// cancelled together with the request.
	shadowCtx := context.WithoutCancel(ctx)

	s.waitGroup.Add(1)
	s.logger.Debug("calling new flow")
	go func() {
		defer s.waitGroup.Done()
		defer func() { <-s.semaphore }()
		defer s.recoverPanic()

		ctx := shadowCtx
		if s.shadowTimeout > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, s.shadowTimeout)
			defer cancel()
		}

		shadowResponse, shdErr := newFlow(ctx)
		if shdErr != nil {
			s.logger.Warn("shadow flow returned an error", slog.Any("error", shdErr))
			return
		}
		if shadowResponse == nil {
			s.logger.Warn("shadow flow returned a nil result")
			return
		}
		// Normalise the shadow response through the same JSON round-trip as the
		// original copy; diffing one normalised and one raw value reports false
		// positives whenever the round-trip is lossy (json:"-" fields, numbers
		// in `any` decoding as float64, custom marshalers).
		shadowCopy, copyErr := deepCopy(shadowResponse)
		if copyErr != nil {
			s.logger.Error("failed to copy shadow response for comparison", slog.Any("error", copyErr))
			return
		}

		originalCopy := new(R)
		if err := json.Unmarshal(originalData, originalCopy); err != nil {
			s.logger.Error("failed to copy response for shadow comparison", slog.Any("error", err))
			return
		}
		s.diff(originalCopy, shadowCopy)
	}()
	return originalResponse, nil
}

// deepCopy clones src through a JSON round-trip. Only fields visible to
// encoding/json survive, which matches what ends up in the diff logs anyway.
func deepCopy[R any](src *R) (*R, error) {
	if src == nil {
		return nil, nil
	}

	data, err := json.Marshal(src)
	if err != nil {
		return nil, err
	}

	dst := new(R)
	if err := json.Unmarshal(data, dst); err != nil {
		return nil, err
	}
	return dst, nil
}

// Wait blocks until every in-flight shadow comparison has finished.
// Call it on graceful shutdown so pending diffs are not lost when the process exits.
//
// Stop issuing Compare calls before calling Wait: sync.WaitGroup requires that
// an Add starting from a zero counter happens before Wait, so shut down the
// traffic source (e.g. the HTTP server) first and drain the shadow flows last.
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

func (s *ShadowFlow[T]) diff(originalResponse, shadowResponse any) {
	changelog, err := diff.Diff(originalResponse, shadowResponse)
	if err != nil {
		s.logger.Error("failed to compare shadow flow responses", slog.Any("error", err))
		return
	}

	if len(changelog) == 0 {
		return
	}

	changedProperties := make([]string, 0, len(changelog))
	for _, change := range changelog {
		changedProperties = append(changedProperties, toFullPath(change))
	}

	properties := strings.Join(changedProperties, ", ")
	if s.encryptionService == nil {
		s.logger.Info("differences found", slog.String("properties", properties))
		return
	}

	// With encryption configured the field paths stay out of the plain-text
	// attributes by default: diff paths include map keys, which may themselves
	// be sensitive. The full paths travel inside the encrypted payload.
	attrs := []any{slog.Int("count", len(changelog))}
	if s.plaintextProperties {
		attrs = append(attrs, slog.String("properties", properties))
	}

	// changedValues (with its pretty-printed diff text) is only ever read
	// below, so it is built here rather than unconditionally above.
	changedValues := make([]string, 0, len(changelog))
	for i, change := range changelog {
		changedValues = append(changedValues, prettyPrintDiff(changedProperties[i], change))
	}

	encryptedValues, err := s.encryptionService.Encrypt(strings.Join(changedValues, "\n"))
	if err != nil {
		// Fail closed: on encryption failure the values are dropped, never
		// logged in plain text. The error itself is untrusted too: EncryptionService
		// is implemented by callers, and an implementation's error could embed the
		// plaintext or key material (e.g. a wrapped "failed to encrypt %q with key
		// %x" style message). Only the error's type is logged, never its message.
		attrs = append(attrs, slog.String("encrypt_error_type", fmt.Sprintf("%T", err)))
		s.logger.Info("differences found", attrs...)
		return
	}

	attrs = append(attrs, slog.String("encrypted_values", encryptedValues))
	if fingerprinter, ok := s.encryptionService.(KeyFingerprinter); ok {
		attrs = append(attrs, slog.String("key_fingerprint", fingerprinter.KeyFingerprint()))
	}
	s.logger.Info("differences found", attrs...)
}

// shouldCallNewFlow samples the traffic percentage. The top-level math/rand/v2
// functions are safe for concurrent use, unlike a seeded *rand.Rand instance.
func (s *ShadowFlow[T]) shouldCallNewFlow() bool {
	return rand.IntN(100) < s.percentage //nolint:gosec // sampling traffic percentage, not security-sensitive
}

func prettyPrintDiff(fieldPath string, change diff.Change) string {
	return fmt.Sprintf("'%s' %s: '%s' -> '%s'", fieldPath, change.Type, toString(change.From), toString(change.To))
}

func toFullPath(change diff.Change) string {
	return strings.Join(change.Path, ".")
}

func toString(value any) string {
	switch v := value.(type) {
	case int:
		return strconv.Itoa(v)
	case int64:
		return strconv.FormatInt(v, 10)
	case uint64:
		return strconv.FormatUint(v, 10)
	case float64:
		return strconv.FormatFloat(v, 'g', -1, 64)
	case bool:
		return strconv.FormatBool(v)
	case string:
		return v
	default:
		return fmt.Sprintf("%v", v)
	}
}
