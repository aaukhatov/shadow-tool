package shadowflow

import (
	"errors"
	"fmt"
	"github.com/r3labs/diff/v3"
	"log"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var logger *log.Logger

func init() {
	logger = log.New(os.Stdout, "[shadow-flow] ", log.Ldate|log.Ltime|log.Lshortfile)
}

type ShadowFlow[T any] struct {
	instance          string // name of the instance
	percentage        int    // percentage of the requests that will be shadowed
	rand              *rand.Rand
	encryptionService EncryptionService // encryptionService encrypting data diff, helps to prevent data leak
	waitGroup         sync.WaitGroup    // waitGroup take a control over the goroutines
}

func New[T any](instance string, percentage int) (*ShadowFlow[T], error) {
	err := checkArgs(instance, percentage)
	if err != nil {
		return nil, err
	}

	shadowFlow := &ShadowFlow[T]{
		instance:   instance,
		percentage: percentage,
		rand:       rand.New(rand.NewSource(time.Now().UnixNano())),
	}

	return shadowFlow, nil
}

func NewWithEncryptionService[T any](instance string, percentage int, encryptionService EncryptionService) (*ShadowFlow[T], error) {
	err := checkArgs(instance, percentage)
	if err != nil {
		return nil, err
	}

	if encryptionService == nil {
		return nil, errors.New("encryptionService cannot be nil")
	}

	shadowFlow := &ShadowFlow[T]{
		instance:          instance,
		percentage:        percentage,
		encryptionService: encryptionService,
		rand:              rand.New(rand.NewSource(time.Now().UnixNano())),
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
// currentFlow: A function that when called, returns the result of the current flow.
// newFlow: A function that when called, returns the result of the new flow.
//
// Returns: The result of the current flow.
func (s *ShadowFlow[T]) Compare(currentFlow func() (T, error), newFlow func() (T, error)) (T, error) {
	var originalResponse T
	originalResponse, err := currentFlow()

	if s.shouldCallNewFlow() && err == nil {
		s.waitGroup.Add(1)
		logger.Printf("[%s] Calling new flow: true", s.instance)
		go func() {
			defer s.waitGroup.Done()
			shadowResponse, shdErr := newFlow()
			if &shadowResponse != nil && shdErr == nil {
				s.diff(originalResponse, shadowResponse)
			}
		}()
	}
	return originalResponse, err
}

func (s *ShadowFlow[T]) CompareSlices(currentFlow func() ([]T, error), newFlow func() ([]T, error)) ([]T, error) {
	var originalResponse []T

	originalResponse, err := currentFlow()

	if s.shouldCallNewFlow() && err == nil {
		s.waitGroup.Add(1)
		logger.Printf("[%s] Calling new flow: true", s.instance)
		go func() {
			defer s.waitGroup.Done()
			shadowResponse, shdErr := newFlow()
			if shadowResponse != nil && shdErr == nil {
				s.diff(originalResponse, shadowResponse)
			}
		}()
	}
	return originalResponse, err
}

func (s *ShadowFlow[T]) diff(originalResponse interface{}, shadowResponse interface{}) {
	changelog, err := diff.Diff(originalResponse, shadowResponse)

	if err != nil {
		logger.Printf("[%s] Failed to compare the shadow flow responses, %s", s.instance, err)
	}

	changedProperties := make([]string, 0)
	changedValues := make([]string, 0)

	for _, change := range changelog {
		fieldPath := toFullPath(change)
		changedProperties = append(changedProperties, fieldPath)
		changedValues = append(changedValues, prettyPrintDiff(fieldPath, change))
	}

	properties := strings.Join(changedProperties, ", ")
	if s.encryptionService != nil {
		encryptedValues, _ := s.encryptionService.Encrypt(strings.Join(changedValues, "\n"))
		logger.Printf("[%s] The following differences were found: %s. Encrypted values: %s", s.instance, properties, encryptedValues)
	} else {
		logger.Printf("[%s] The following differences were found: %s", s.instance, properties)
	}
}

func (s *ShadowFlow[T]) shouldCallNewFlow() bool {
	return s.rand.Intn(100) < s.percentage
}

func prettyPrintDiff(fieldPath string, change diff.Change) string {
	return fmt.Sprintf("'%s' %s: '%s' -> '%s'", fieldPath, change.Type, toString(change.From), toString(change.To))
}

func toFullPath(change diff.Change) string {
	return strings.Join(change.Path[:], ".")
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
