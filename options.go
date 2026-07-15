package shadowflow

import (
	"errors"
	"log/slog"
)

// Option configures optional ShadowFlow settings. Pass options to New.
type Option func(*config) error

// config is deliberately not generic: none of the optional settings depend
// on the response type, and this keeps call sites free of type annotations
// like WithLogger[T](...).
type config struct {
	logger            *slog.Logger
	encryptionService EncryptionService
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
