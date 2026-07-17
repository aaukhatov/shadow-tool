package shadowflow

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// testLogger returns a logger writing into buf, so tests can assert on the log
// output of a single ShadowFlow instance. Debug is enabled so that lines logged
// below the default level stay visible to the assertions.
func testLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// assertLogged fails the test unless every substring appears in the log output.
func assertLogged(t *testing.T, output string, substrs ...string) {
	t.Helper()
	for _, substr := range substrs {
		if !strings.Contains(output, substr) {
			t.Errorf("Expected %q in the log output, got:\n%s", substr, output)
		}
	}
}

// assertNotLogged fails the test if any of the substrings appears in the log output.
func assertNotLogged(t *testing.T, output string, substrs ...string) {
	t.Helper()
	for _, substr := range substrs {
		if strings.Contains(output, substr) {
			t.Errorf("Expected %q to be absent from the log output, got:\n%s", substr, output)
		}
	}
}

type dummyResponse struct {
	Name      string `diff:"name"`
	BirthDate string `diff:"birth-date"`
	Address   address
}

type address struct {
	Street string `diff:"street"`
	Number int    `diff:"number"`
}

func TestShouldDetectDifferences(t *testing.T) {
	buf := new(bytes.Buffer)
	shadowFlow, _ := New[dummyResponse]("HUB_NAME", 100, WithLogger(testLogger(buf)))

	currentFlow := func(context.Context) (*dummyResponse, error) {
		return &dummyResponse{Name: "John", BirthDate: "2024-01-01", Address: address{Number: 18, Street: "Croeselaan"}}, nil
	}
	newFlow := func(context.Context) (*dummyResponse, error) {
		return &dummyResponse{Name: "Doe", BirthDate: "2024-01-02", Address: address{Number: 20, Street: "Croeselaan"}}, nil
	}

	_, _ = shadowFlow.Compare(context.Background(), currentFlow, newFlow)
	shadowFlow.Wait()

	assertLogged(t, buf.String(),
		`msg="differences found"`,
		"instance=HUB_NAME",
		`properties="name, birth-date, Address.number"`,
	)
}

func TestCurrentFlowCalledOnce(t *testing.T) {
	callCount := 0
	currentFlow := func(context.Context) (*dummyResponse, error) {
		callCount++
		return &dummyResponse{Name: "John", BirthDate: "2024-01-01", Address: address{Number: 18, Street: "Croeselaan"}}, nil
	}
	newFlow := func(context.Context) (*dummyResponse, error) {
		return &dummyResponse{Name: "Doe", BirthDate: "2024-01-02", Address: address{Number: 20, Street: "Croeselaan"}}, nil
	}

	shadowFlow, _ := New[dummyResponse]("HUB_NAME", 100, WithLogger(testLogger(new(bytes.Buffer))))
	_, _ = shadowFlow.Compare(context.Background(), currentFlow, newFlow)
	shadowFlow.Wait()

	if callCount != 1 {
		t.Errorf("Expected currentFlow to be called once, but it was called %d times", callCount)
	}
}

func TestNewFlowNotCalled(t *testing.T) {
	callCount := 0
	currentFlow := func(context.Context) (*dummyResponse, error) {
		return &dummyResponse{Name: "John", BirthDate: "2024-01-01", Address: address{Number: 18, Street: "Croeselaan"}}, nil
	}
	newFlow := func(context.Context) (*dummyResponse, error) {
		callCount++
		return &dummyResponse{Name: "Doe", BirthDate: "2024-01-02", Address: address{Number: 20, Street: "Croeselaan"}}, nil
	}

	// Set percentage to 0 to ensure newFlow is not called
	shadowFlow, _ := New[dummyResponse]("HUB_NAME", 0, WithLogger(testLogger(new(bytes.Buffer))))
	_, _ = shadowFlow.Compare(context.Background(), currentFlow, newFlow)

	if callCount != 0 {
		t.Errorf("Expected newFlow not to be called, but it was called %d times", callCount)
	}
}

func TestCompareWithNoopEncryptionService(t *testing.T) {
	buf := new(bytes.Buffer)
	encryptionService := NewNoopEncryptionService()
	shadowFlow, _ := New[dummyResponse](
		"HUB_NAME",
		100,
		WithLogger(testLogger(buf)),
		WithEncryptionService(encryptionService),
	)

	currentFlow := func(context.Context) (*dummyResponse, error) {
		return &dummyResponse{Name: "John", BirthDate: "2024-01-01", Address: address{Number: 18, Street: "Croeselaan"}}, nil
	}
	newFlow := func(context.Context) (*dummyResponse, error) {
		return &dummyResponse{Name: "Doe", BirthDate: "2024-01-02", Address: address{Number: 20, Street: "Croeselaan"}}, nil
	}

	_, _ = shadowFlow.Compare(context.Background(), currentFlow, newFlow)
	shadowFlow.Wait()

	expectedEncryptedValues, _ := encryptionService.Encrypt("'name' update: 'John' -> 'Doe'\n'birth-date' update: '2024-01-01' -> '2024-01-02'\n'Address.number' update: '18' -> '20'")

	assertLogged(t, buf.String(),
		`msg="differences found"`,
		"count=3",
		// TextHandler quotes the value: base64 contains '=' and '+'.
		fmt.Sprintf("encrypted_values=%q", expectedEncryptedValues),
	)
	// With encryption configured, the field paths stay out of the plain-text
	// attributes by default — they may contain sensitive map keys.
	assertNotLogged(t, buf.String(), "properties=")
}

func TestPlaintextPropertiesLoggedWhenOptedIn(t *testing.T) {
	buf := new(bytes.Buffer)
	shadowFlow, _ := New[dummyResponse](
		"HUB_NAME",
		100,
		WithLogger(testLogger(buf)),
		WithEncryptionService(NewNoopEncryptionService()),
		WithPlaintextProperties(),
	)

	currentFlow := func(context.Context) (*dummyResponse, error) {
		return &dummyResponse{Name: "John", BirthDate: "2024-01-01", Address: address{Number: 18, Street: "Croeselaan"}}, nil
	}
	newFlow := func(context.Context) (*dummyResponse, error) {
		return &dummyResponse{Name: "Doe", BirthDate: "2024-01-01", Address: address{Number: 18, Street: "Croeselaan"}}, nil
	}

	_, _ = shadowFlow.Compare(context.Background(), currentFlow, newFlow)
	shadowFlow.Wait()

	assertLogged(t, buf.String(),
		`msg="differences found"`,
		"count=1",
		"properties=name",
		"encrypted_values=",
	)
}

// lossyResponse round-trips through JSON lossily: Internal is dropped by
// encoding/json and Payload decodes numbers as float64. Both sides of the
// diff must be normalised identically or equal results report differences.
type lossyResponse struct {
	Name     string
	Internal string `json:"-"`
	Payload  any
}

func TestEqualResultsWithLossyJSONRoundTripReportNoDifferences(t *testing.T) {
	buf := new(bytes.Buffer)
	shadowFlow, _ := New[lossyResponse]("HUB_NAME", 100, WithLogger(testLogger(buf)))

	makeResponse := func(context.Context) (*lossyResponse, error) {
		return &lossyResponse{Name: "John", Internal: "not-serialised", Payload: map[string]any{"count": 42}}, nil
	}

	_, _ = shadowFlow.Compare(context.Background(), makeResponse, makeResponse)
	shadowFlow.Wait()

	// Diffing a normalised copy against a raw response used to report the
	// json:"-" field as changed and to fail outright on int vs float64.
	assertNotLogged(t, buf.String(),
		`msg="differences found"`,
		`msg="failed to compare shadow flow responses"`,
	)
}

func TestNotAllowedToCreateShadowFlowWithInvalidPercentage(t *testing.T) {
	_, err := New[dummyResponse]("HUB_NAME", 101)
	if err == nil {
		t.Errorf("Expected error when creating ShadowFlow with percentage > 100")
	}

	_, err = New[dummyResponse]("HUB_NAME", -1)
	if err == nil {
		t.Errorf("Expected error when creating ShadowFlow with percentage < 0")
	}
}

func TestInstanceNameMustBeSpecified(t *testing.T) {
	_, err := New[dummyResponse]("", 100)
	if err == nil {
		t.Errorf("Expected error when creating ShadowFlow without instance name")
	}

	_, err = New[dummyResponse]("", 100, WithEncryptionService(NewNoopEncryptionService()))
	if err == nil {
		t.Errorf("Expected error when creating ShadowFlow without instance name")
	}
}

func TestEncryptionServiceCannotBeNil(t *testing.T) {
	_, err := New[dummyResponse]("HUB_NAME", 100, WithEncryptionService(nil))
	if err == nil {
		t.Errorf("Expected error when creating ShadowFlow with nil encryption service")
	}
}

func TestMainFlowShouldNotWaitShadowFlow(t *testing.T) {
	buf := new(bytes.Buffer)
	shadowFlow, _ := New[dummyResponse]("HUB_NAME", 100, WithLogger(testLogger(buf)))

	currentFlow := func(context.Context) (*dummyResponse, error) {
		return &dummyResponse{Name: "John", BirthDate: "2024-01-01", Address: address{Number: 18, Street: "Croeselaan"}}, nil
	}
	newFlow := func(context.Context) (*dummyResponse, error) {
		time.Sleep(1000 * time.Millisecond) // simulate a long running shadow flow
		return &dummyResponse{Name: "Doe", BirthDate: "2024-01-02", Address: address{Number: 20, Street: "Croeselaan"}}, nil
	}

	start := time.Now()
	_, _ = shadowFlow.Compare(context.Background(), currentFlow, newFlow)
	elapsed := time.Since(start)

	// The shadow flow sleeps for 1s; Compare must return well before that.
	if elapsed > 200*time.Millisecond {
		t.Errorf("Expected Compare to return without waiting for the shadow flow, but it took %v", elapsed)
	}

	shadowFlow.Wait()

	assertLogged(t, buf.String(),
		`msg="differences found"`,
		`properties="name, birth-date, Address.number"`,
	)
}

func TestConcurrentCompare(t *testing.T) {
	buf := new(bytes.Buffer)
	shadowFlow, _ := New[dummyResponse]("HUB_NAME", 50, WithLogger(testLogger(buf)))

	currentFlow := func(context.Context) (*dummyResponse, error) {
		return &dummyResponse{Name: "John", BirthDate: "2024-01-01", Address: address{Number: 18, Street: "Croeselaan"}}, nil
	}
	newFlow := func(context.Context) (*dummyResponse, error) {
		return &dummyResponse{Name: "Doe", BirthDate: "2024-01-02", Address: address{Number: 20, Street: "Croeselaan"}}, nil
	}

	var callers sync.WaitGroup
	for range 100 {
		callers.Add(1)
		go func() {
			defer callers.Done()
			response, err := shadowFlow.Compare(context.Background(), currentFlow, newFlow)
			if err != nil {
				t.Errorf("Expected no error from Compare, got %v", err)
			}
			if response == nil || response.Name != "John" {
				t.Errorf("Expected the current flow response, got %v", response)
			}
		}()
	}
	callers.Wait()
	shadowFlow.Wait()
}

func TestShadowFlowPanicDoesNotCrashMainFlow(t *testing.T) {
	buf := new(bytes.Buffer)
	shadowFlow, _ := New[dummyResponse]("HUB_NAME", 100, WithLogger(testLogger(buf)))

	currentFlow := func(context.Context) (*dummyResponse, error) {
		return &dummyResponse{Name: "John", BirthDate: "2024-01-01", Address: address{Number: 18, Street: "Croeselaan"}}, nil
	}
	newFlow := func(context.Context) (*dummyResponse, error) {
		panic("shadow flow blew up")
	}

	response, err := shadowFlow.Compare(context.Background(), currentFlow, newFlow)
	shadowFlow.Wait()

	if err != nil || response == nil || response.Name != "John" {
		t.Errorf("Expected the current flow response despite the shadow flow panic, got %v, %v", response, err)
	}

	assertLogged(t, buf.String(),
		"level=ERROR",
		`msg="recovered from panic in shadow flow"`,
		`panic="shadow flow blew up"`,
	)
}

func TestWaitDrainsShadowFlows(t *testing.T) {
	buf := new(bytes.Buffer)
	shadowFlow, _ := New[dummyResponse]("HUB_NAME", 100, WithLogger(testLogger(buf)))

	var shadowFinished atomic.Bool
	currentFlow := func(context.Context) (*dummyResponse, error) {
		return &dummyResponse{Name: "John", BirthDate: "2024-01-01", Address: address{Number: 18, Street: "Croeselaan"}}, nil
	}
	newFlow := func(context.Context) (*dummyResponse, error) {
		time.Sleep(100 * time.Millisecond)
		shadowFinished.Store(true)
		return &dummyResponse{Name: "Doe", BirthDate: "2024-01-01", Address: address{Number: 18, Street: "Croeselaan"}}, nil
	}

	_, _ = shadowFlow.Compare(context.Background(), currentFlow, newFlow)
	shadowFlow.Wait()

	if !shadowFinished.Load() {
		t.Errorf("Expected Wait to block until the shadow flow finished")
	}

	assertLogged(t, buf.String(), `msg="differences found"`, "properties=name")
}

func TestShouldDetectDifferencesForSlices(t *testing.T) {
	buf := new(bytes.Buffer)
	shadowFlow, _ := New[dummyResponse]("HUB_NAME", 100, WithLogger(testLogger(buf)))

	currentFlow := func(context.Context) ([]dummyResponse, error) {
		return []dummyResponse{
			{Name: "Cristiano Ronaldo", BirthDate: "1985-02-05", Address: address{Number: 7, Street: "Funchal"}},
			{Name: "Lionel Messi", BirthDate: "1987-06-24", Address: address{Number: 10, Street: "La Bajada"}},
		}, nil
	}
	newFlow := func(context.Context) ([]dummyResponse, error) {
		return []dummyResponse{
			{Name: "Cristiano Ronaldo", BirthDate: "1985-02-05", Address: address{Number: 19, Street: "Funchal"}},
			{Name: "Lionel Mesi", BirthDate: "1997-06-24", Address: address{Number: 10, Street: "La Bajada"}},
		}, nil
	}

	_, _ = shadowFlow.CompareSlices(context.Background(), currentFlow, newFlow)
	shadowFlow.Wait()

	assertLogged(t, buf.String(),
		`msg="differences found"`,
		`properties="0.Address.number, 1.name, 1.birth-date"`,
	)
}

// capturingHandler records every log record it receives, so tests can assert on
// structured output rather than on a rendered line. Handlers derived via
// WithAttrs share the parent's store — ShadowFlow binds attributes with
// logger.With, so the records would otherwise land somewhere the test cannot see.
type capturingHandler struct {
	store *recordStore
	attrs []slog.Attr
}

type recordStore struct {
	mu      sync.Mutex
	records []slog.Record
}

func newCapturingHandler() *capturingHandler {
	return &capturingHandler{store: &recordStore{}}
}

func (h *capturingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *capturingHandler) Handle(_ context.Context, record slog.Record) error {
	// Fold in the attrs bound via WithAttrs so the caller sees one flat record.
	record.AddAttrs(h.attrs...)

	h.store.mu.Lock()
	defer h.store.mu.Unlock()
	h.store.records = append(h.store.records, record)
	return nil
}

func (h *capturingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &capturingHandler{store: h.store, attrs: append(slices.Clip(h.attrs), attrs...)}
}

func (h *capturingHandler) WithGroup(string) slog.Handler { return h }

// attr returns the value of the named attribute on the first record whose
// message matches, and whether it was found.
func (h *capturingHandler) attr(msg, key string) (string, bool) {
	h.store.mu.Lock()
	defer h.store.mu.Unlock()
	for _, record := range h.store.records {
		if record.Message != msg {
			continue
		}
		var value string
		var found bool
		record.Attrs(func(a slog.Attr) bool {
			if a.Key == key {
				value, found = a.Value.String(), true
				return false
			}
			return true
		})
		if found {
			return value, true
		}
	}
	return "", false
}

func TestWithLoggerReceivesShadowFlowOutput(t *testing.T) {
	handler := newCapturingHandler()
	shadowFlow, err := New[dummyResponse]("HUB_NAME", 100, WithLogger(slog.New(handler)))
	if err != nil {
		t.Fatalf("Expected no error from New with WithLogger, got %v", err)
	}

	currentFlow := func(context.Context) (*dummyResponse, error) {
		return &dummyResponse{Name: "John", BirthDate: "2024-01-01", Address: address{Number: 18, Street: "Croeselaan"}}, nil
	}
	newFlow := func(context.Context) (*dummyResponse, error) {
		return &dummyResponse{Name: "Doe", BirthDate: "2024-01-01", Address: address{Number: 18, Street: "Croeselaan"}}, nil
	}

	_, _ = shadowFlow.Compare(context.Background(), currentFlow, newFlow)
	shadowFlow.Wait()

	properties, found := handler.attr("differences found", "properties")
	if !found {
		t.Fatalf("Expected the diff to be logged to the custom logger")
	}
	if properties != "name" {
		t.Errorf("Expected properties=name, got %q", properties)
	}

	// The instance belongs in an attribute, not interpolated into the message.
	if instance, _ := handler.attr("differences found", "instance"); instance != "HUB_NAME" {
		t.Errorf("Expected instance=HUB_NAME as an attribute, got %q", instance)
	}
}

func TestDefaultLoggerUsedWithoutOption(t *testing.T) {
	shadowFlow, err := New[dummyResponse]("HUB_NAME", 100)
	if err != nil {
		t.Fatalf("Expected no error from New without options, got %v", err)
	}

	if shadowFlow.logger == nil {
		t.Errorf("Expected the default logger to be set when WithLogger is not used")
	}
}

func TestWithLoggerCannotBeNil(t *testing.T) {
	_, err := New[dummyResponse]("HUB_NAME", 100, WithLogger(nil))
	if err == nil {
		t.Errorf("Expected error when creating ShadowFlow with a nil logger")
	}
}

func TestWithEncryptionServiceCannotBeNil(t *testing.T) {
	_, err := New[dummyResponse]("HUB_NAME", 100, WithEncryptionService(nil))
	if err == nil {
		t.Errorf("Expected error when creating ShadowFlow with a nil encryption service")
	}
}

func TestFirstFailingOptionIsReported(t *testing.T) {
	_, err := New[dummyResponse]("HUB_NAME", 100, WithLogger(nil), WithEncryptionService(nil))
	if err == nil {
		t.Fatalf("Expected error when creating ShadowFlow with two invalid options")
	}

	if !strings.Contains(err.Error(), "logger cannot be nil") {
		t.Errorf("Expected the first failing option to be reported, got %v", err)
	}
}

func TestCallerMayMutateReturnedResponse(t *testing.T) {
	buf := new(bytes.Buffer)
	encryptionService := NewNoopEncryptionService()
	shadowFlow, _ := New[dummyResponse](
		"HUB_NAME",
		100,
		WithLogger(testLogger(buf)),
		WithEncryptionService(encryptionService),
	)

	// The shadow flow finishes only after the caller has mutated the returned
	// response, so the diff must run on a copy taken before the mutation.
	mutated := make(chan struct{})
	currentFlow := func(context.Context) (*dummyResponse, error) {
		return &dummyResponse{Name: "John", BirthDate: "2024-01-01", Address: address{Number: 18, Street: "Croeselaan"}}, nil
	}
	newFlow := func(context.Context) (*dummyResponse, error) {
		<-mutated
		return &dummyResponse{Name: "Doe", BirthDate: "2024-01-02", Address: address{Number: 20, Street: "Croeselaan"}}, nil
	}

	response, _ := shadowFlow.Compare(context.Background(), currentFlow, newFlow)
	response.Name = "MUTATED"
	response.Address.Number = 99
	close(mutated)
	shadowFlow.Wait()

	expectedEncryptedValues, _ := encryptionService.Encrypt("'name' update: 'John' -> 'Doe'\n'birth-date' update: '2024-01-01' -> '2024-01-02'\n'Address.number' update: '18' -> '20'")

	assertLogged(t, buf.String(),
		`msg="differences found"`,
		fmt.Sprintf("encrypted_values=%q", expectedEncryptedValues),
	)
}

func TestShadowFlowErrorIsLogged(t *testing.T) {
	buf := new(bytes.Buffer)
	shadowFlow, _ := New[dummyResponse]("HUB_NAME", 100, WithLogger(testLogger(buf)))

	currentFlow := func(context.Context) (*dummyResponse, error) {
		return &dummyResponse{Name: "John"}, nil
	}
	newFlow := func(context.Context) (*dummyResponse, error) {
		return nil, errors.New("new backend unavailable")
	}

	response, err := shadowFlow.Compare(context.Background(), currentFlow, newFlow)
	shadowFlow.Wait()

	if err != nil || response == nil || response.Name != "John" {
		t.Errorf("Expected the current flow response despite the shadow flow error, got %v, %v", response, err)
	}

	assertLogged(t, buf.String(),
		"level=WARN",
		`msg="shadow flow returned an error"`,
		`error="new backend unavailable"`,
	)
}

func TestShadowFlowNilResultIsLogged(t *testing.T) {
	buf := new(bytes.Buffer)
	shadowFlow, _ := New[dummyResponse]("HUB_NAME", 100, WithLogger(testLogger(buf)))

	currentFlow := func(context.Context) (*dummyResponse, error) {
		return &dummyResponse{Name: "John"}, nil
	}
	newFlow := func(context.Context) (*dummyResponse, error) {
		return nil, nil //nolint:nilnil // a nil result without an error is exactly the case under test
	}

	_, _ = shadowFlow.Compare(context.Background(), currentFlow, newFlow)
	shadowFlow.Wait()

	assertLogged(t, buf.String(),
		"level=WARN",
		`msg="shadow flow returned a nil result"`,
	)
}

func TestConcurrencyLimitSkipsShadow(t *testing.T) {
	buf := new(bytes.Buffer)
	shadowFlow, _ := New[dummyResponse](
		"HUB_NAME",
		100,
		WithLogger(testLogger(buf)),
		WithMaxConcurrentShadows(1),
	)

	release := make(chan struct{})
	var newFlowCalls atomic.Int32
	currentFlow := func(context.Context) (*dummyResponse, error) {
		return &dummyResponse{Name: "John"}, nil
	}
	newFlow := func(context.Context) (*dummyResponse, error) {
		newFlowCalls.Add(1)
		<-release
		return &dummyResponse{Name: "Doe"}, nil
	}

	// The first call occupies the only slot; the second must be skipped.
	_, _ = shadowFlow.Compare(context.Background(), currentFlow, newFlow)
	_, err := shadowFlow.Compare(context.Background(), currentFlow, newFlow)
	if err != nil {
		t.Errorf("Expected no error from the skipped Compare, got %v", err)
	}
	close(release)
	shadowFlow.Wait()

	if calls := newFlowCalls.Load(); calls != 1 {
		t.Errorf("Expected the second shadow flow to be skipped, but newFlow was called %d times", calls)
	}
	assertLogged(t, buf.String(), `msg="shadow flow skipped: concurrency limit reached"`)
}

func TestNilCurrentResultSkipsShadow(t *testing.T) {
	buf := new(bytes.Buffer)
	shadowFlow, _ := New[dummyResponse]("HUB_NAME", 100, WithLogger(testLogger(buf)))

	var newFlowCalls atomic.Int32
	currentFlow := func(context.Context) (*dummyResponse, error) {
		return nil, nil //nolint:nilnil // a nil result without an error is exactly the case under test
	}
	newFlow := func(context.Context) (*dummyResponse, error) {
		newFlowCalls.Add(1)
		return &dummyResponse{Name: "Doe"}, nil
	}

	result, err := shadowFlow.Compare(context.Background(), currentFlow, newFlow)
	shadowFlow.Wait()

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if result != nil {
		t.Errorf("Expected a nil result, got %v", result)
	}
	if calls := newFlowCalls.Load(); calls != 0 {
		t.Errorf("Expected newFlow not to be called, but it was called %d times", calls)
	}
	assertLogged(t, buf.String(), `msg="shadow flow skipped: current flow returned a nil result"`)
	assertNotLogged(t, buf.String(), `msg="calling new flow"`)
}

func TestShadowFlowSurvivesRequestCancellation(t *testing.T) {
	buf := new(bytes.Buffer)
	shadowFlow, _ := New[dummyResponse]("HUB_NAME", 100, WithLogger(testLogger(buf)))

	// The request context is already cancelled; the shadow flow must still run
	// on an uncancelled context derived from it.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	currentFlow := func(context.Context) (*dummyResponse, error) {
		return &dummyResponse{Name: "John"}, nil
	}
	newFlow := func(ctx context.Context) (*dummyResponse, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return &dummyResponse{Name: "Doe"}, nil
	}

	_, _ = shadowFlow.Compare(ctx, currentFlow, newFlow)
	shadowFlow.Wait()

	assertLogged(t, buf.String(), `msg="differences found"`, "properties=name")
}

func TestShadowTimeoutBoundsShadowFlow(t *testing.T) {
	buf := new(bytes.Buffer)
	shadowFlow, _ := New[dummyResponse](
		"HUB_NAME",
		100,
		WithLogger(testLogger(buf)),
		WithShadowTimeout(10*time.Millisecond),
	)

	currentFlow := func(context.Context) (*dummyResponse, error) {
		return &dummyResponse{Name: "John"}, nil
	}
	newFlow := func(ctx context.Context) (*dummyResponse, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}

	_, _ = shadowFlow.Compare(context.Background(), currentFlow, newFlow)
	shadowFlow.Wait()

	assertLogged(t, buf.String(),
		`msg="shadow flow returned an error"`,
		"context deadline exceeded",
	)
}

func TestWithShadowTimeoutMustBePositive(t *testing.T) {
	_, err := New[dummyResponse]("HUB_NAME", 100, WithShadowTimeout(0))
	if err == nil {
		t.Errorf("Expected error when creating ShadowFlow with a non-positive shadow timeout")
	}
}

func TestDefaultShadowTimeoutIsApplied(t *testing.T) {
	shadowFlow, _ := New[dummyResponse]("HUB_NAME", 100)

	currentFlow := func(context.Context) (*dummyResponse, error) {
		return &dummyResponse{Name: "John"}, nil
	}
	var sawDeadline bool
	newFlow := func(ctx context.Context) (*dummyResponse, error) {
		_, sawDeadline = ctx.Deadline()
		return &dummyResponse{Name: "Doe"}, nil
	}

	_, _ = shadowFlow.Compare(context.Background(), currentFlow, newFlow)
	shadowFlow.Wait()

	if !sawDeadline {
		t.Errorf("Expected the shadow context to carry a default deadline")
	}
}

func TestWithoutShadowTimeoutDisablesDefault(t *testing.T) {
	shadowFlow, _ := New[dummyResponse]("HUB_NAME", 100, WithoutShadowTimeout())

	currentFlow := func(context.Context) (*dummyResponse, error) {
		return &dummyResponse{Name: "John"}, nil
	}
	sawDeadline := true
	newFlow := func(ctx context.Context) (*dummyResponse, error) {
		_, sawDeadline = ctx.Deadline()
		return &dummyResponse{Name: "Doe"}, nil
	}

	_, _ = shadowFlow.Compare(context.Background(), currentFlow, newFlow)
	shadowFlow.Wait()

	if sawDeadline {
		t.Errorf("Expected no deadline on the shadow context when WithoutShadowTimeout is set")
	}
}

func TestShadowTimeoutOptionsConflict(t *testing.T) {
	_, err := New[dummyResponse]("HUB_NAME", 100, WithShadowTimeout(time.Second), WithoutShadowTimeout())
	if err == nil {
		t.Errorf("Expected error when combining WithShadowTimeout and WithoutShadowTimeout")
	}
}

func TestWithMaxConcurrentShadowsMustBePositive(t *testing.T) {
	_, err := New[dummyResponse]("HUB_NAME", 100, WithMaxConcurrentShadows(0))
	if err == nil {
		t.Errorf("Expected error when creating ShadowFlow with a non-positive concurrency limit")
	}
}
