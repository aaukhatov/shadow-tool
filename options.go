package shadowflow

import (
	"errors"
	"log/slog"
	"time"
)

// Option configures optional ShadowFlow settings. Pass options to New.
type Option func(*config) error

// config is deliberately not generic: none of the optional settings depend
// on the response type, and this keeps call sites free of type annotations
// like WithLogger[T](...).
type config struct {
	logger               *slog.Logger
	encryptionService    EncryptionService
	shadowTimeout        time.Duration
	noShadowTimeout      bool
	maxConcurrentShadows int
	plaintextProperties  bool
}

// WithLogger routes the shadow flow logs to the given logger instead of
// slog.Default().
func WithLogger(logger *slog.Logger) Option {
	return func(c *config) error {
		if logger == nil {
			return errors.New("logger cannot be nil")
		}
		c.logger = logger
		return nil
	}
}

// WithEncryptionService enables logging of the changed values, encrypted with
// the given service. Without it only the names of the differing fields are
// logged.
func WithEncryptionService(encryptionService EncryptionService) Option {
	return func(c *config) error {
		if encryptionService == nil {
			return errors.New("encryptionService cannot be nil")
		}
		c.encryptionService = encryptionService
		return nil
	}
}

// WithShadowTimeout bounds each shadow flow call: the context passed to the
// new flow is cancelled after the given duration. Without it, shadow flows
// get a default timeout of defaultShadowTimeout; use WithoutShadowTimeout to
// run them unbounded instead.
func WithShadowTimeout(timeout time.Duration) Option {
	return func(c *config) error {
		if timeout <= 0 {
			return errors.New("shadow timeout must be positive")
		}
		c.shadowTimeout = timeout
		return nil
	}
}

// WithoutShadowTimeout disables the default shadow timeout, so the shadow
// flow runs until it returns on its own. A hung new flow then holds its
// concurrency slot indefinitely; prefer WithShadowTimeout unless the new flow
// is already known to be bounded.
func WithoutShadowTimeout() Option {
	return func(c *config) error {
		c.noShadowTimeout = true
		return nil
	}
}

// WithMaxConcurrentShadows caps the number of shadow flows running at the same
// time; sampled calls beyond the cap are skipped, never queued, so a slow new
// flow cannot pile up goroutines. Defaults to 100.
func WithMaxConcurrentShadows(n int) Option {
	return func(c *config) error {
		if n < 1 {
			return errors.New("max concurrent shadows must be at least 1")
		}
		c.maxConcurrentShadows = n
		return nil
	}
}

// WithPlaintextProperties logs the differing field paths in plain text next to
// the encrypted values. By default an encryption service suppresses them,
// because diff paths include map keys, which may themselves be sensitive.
func WithPlaintextProperties() Option {
	return func(c *config) error {
		c.plaintextProperties = true
		return nil
	}
}
