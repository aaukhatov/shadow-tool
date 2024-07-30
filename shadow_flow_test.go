package shadowflow

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"
)

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
	logger.SetOutput(buf)

	shadowFlow, _ := New("HUB_NAME", 100)

	currentFlow := func() (interface{}, error) {
		return &dummyResponse{Name: "John", BirthDate: "2024-01-01", Address: address{Number: 18, Street: "Croeselaan"}}, nil
	}
	newFlow := func() (interface{}, error) {
		return &dummyResponse{Name: "Doe", BirthDate: "2024-01-02", Address: address{Number: 20, Street: "Croeselaan"}}, nil
	}

	shadowFlow.Compare(currentFlow, newFlow)
	shadowFlow.waitGroup.Wait()

	if !strings.Contains(buf.String(), "[HUB_NAME] The following differences were found: name, birth-date, Address.number") {
		t.Errorf("Expected error message not found in log output")
	}
}

func TestCurrentFlowCalledOnce(t *testing.T) {
	callCount := 0
	currentFlow := func() (interface{}, error) {
		callCount++
		return &dummyResponse{Name: "John", BirthDate: "2024-01-01", Address: address{Number: 18, Street: "Croeselaan"}}, nil
	}
	newFlow := func() (interface{}, error) {
		return &dummyResponse{Name: "Doe", BirthDate: "2024-01-02", Address: address{Number: 20, Street: "Croeselaan"}}, nil
	}

	shadowFlow, _ := New("HUB_NAME", 100)
	shadowFlow.Compare(currentFlow, newFlow)
	shadowFlow.waitGroup.Wait()

	if callCount != 1 {
		t.Errorf("Expected currentFlow to be called once, but it was called %d times", callCount)
	}
}

func TestNewFlowNotCalled(t *testing.T) {
	callCount := 0
	currentFlow := func() (interface{}, error) {
		return &dummyResponse{Name: "John", BirthDate: "2024-01-01", Address: address{Number: 18, Street: "Croeselaan"}}, nil
	}
	newFlow := func() (interface{}, error) {
		callCount++
		return &dummyResponse{Name: "Doe", BirthDate: "2024-01-02", Address: address{Number: 20, Street: "Croeselaan"}}, nil
	}

	shadowFlow, _ := New("HUB_NAME", 0) // Set percentage to 0 to ensure newFlow is not called
	shadowFlow.Compare(currentFlow, newFlow)

	if callCount != 0 {
		t.Errorf("Expected newFlow not to be called, but it was called %d times", callCount)
	}
}

func TestCompareWithNoopEncryptionService(t *testing.T) {
	buf := new(bytes.Buffer)
	logger.SetOutput(buf)

	encryptionService := NewNoopEncryptionService()
	shadowFlow, _ := NewWithEncryptionService("HUB_NAME", 100, encryptionService)

	currentFlow := func() (interface{}, error) {
		return &dummyResponse{Name: "John", BirthDate: "2024-01-01", Address: address{Number: 18, Street: "Croeselaan"}}, nil
	}
	newFlow := func() (interface{}, error) {
		return &dummyResponse{Name: "Doe", BirthDate: "2024-01-02", Address: address{Number: 20, Street: "Croeselaan"}}, nil
	}

	shadowFlow.Compare(currentFlow, newFlow)
	shadowFlow.waitGroup.Wait()

	expectedEncryptedValues, _ := encryptionService.Encrypt("'name' update: 'John' -> 'Doe'\n'birth-date' update: '2024-01-01' -> '2024-01-02'\n'Address.number' update: '18' -> '20'")
	expectedLogOutput := fmt.Sprintf("[HUB_NAME] The following differences were found: name, birth-date, Address.number. Encrypted values: %s", expectedEncryptedValues)

	if !strings.Contains(buf.String(), expectedLogOutput) {
		t.Errorf("Expected log output not found")
	}
}

func TestNotAllowedToCreateShadowFlowWithInvalidPercentage(t *testing.T) {
	_, err := New("HUB_NAME", 101)
	if err == nil {
		t.Errorf("Expected error when creating ShadowFlow with percentage > 100")
	}

	_, err = New("HUB_NAME", -1)
	if err == nil {
		t.Errorf("Expected error when creating ShadowFlow with percentage < 0")
	}
}

func TestInstanceNameMustBeSpecified(t *testing.T) {
	_, err := New("", 100)
	if err == nil {
		t.Errorf("Expected error when creating ShadowFlow without instance name")
	}

	_, err = NewWithEncryptionService("", 100, NewNoopEncryptionService())
	if err == nil {
		t.Errorf("Expected error when creating ShadowFlow without instance name")
	}
}

func TestEncryptionServiceCannotBeNil(t *testing.T) {
	_, err := NewWithEncryptionService("HUB_NAME", 100, nil)
	if err == nil {
		t.Errorf("Expected error when creating ShadowFlow with nil encryption service")
	}
}

func TestMainFlowShouldNotWaitShadowFlow(t *testing.T) {
	buf := new(bytes.Buffer)
	logger.SetOutput(buf)

	shadowFlow, _ := New("HUB_NAME", 100)

	currentFlow := func() (interface{}, error) {
		return &dummyResponse{Name: "John", BirthDate: "2024-01-01", Address: address{Number: 18, Street: "Croeselaan"}}, nil
	}
	newFlow := func() (interface{}, error) {
		time.Sleep(1000 * time.Millisecond) // simulate a long running shadow flow
		return &dummyResponse{Name: "Doe", BirthDate: "2024-01-02", Address: address{Number: 20, Street: "Croeselaan"}}, nil
	}

	shadowFlow.Compare(currentFlow, newFlow)
	shadowFlow.waitGroup.Wait()

	if !strings.Contains(buf.String(), "[HUB_NAME] The following differences were found: name, birth-date, Address.number") {
		t.Errorf("Expected error message not found in log output")
	}
}

func TestShouldDetectDifferencesForSlices(t *testing.T) {
	buf := new(bytes.Buffer)
	logger.SetOutput(buf)

	shadowFlow, _ := New("HUB_NAME", 100)

	currentFlow := func() ([]interface{}, error) {
		return []interface{}{
			&dummyResponse{Name: "Cristiano Ronaldo", BirthDate: "1985-02-05", Address: address{Number: 7, Street: "Funchal"}},
			&dummyResponse{Name: "Lionel Messi", BirthDate: "1987-06-24", Address: address{Number: 10, Street: "La Bajada"}},
		}, nil
	}
	newFlow := func() ([]interface{}, error) {
		return []interface{}{
			&dummyResponse{Name: "Cristiano Ronaldo", BirthDate: "1985-02-05", Address: address{Number: 19, Street: "Funchal"}},
			&dummyResponse{Name: "Lionel Mesi", BirthDate: "1997-06-24", Address: address{Number: 10, Street: "La Bajada"}},
		}, nil
	}

	shadowFlow.CompareSlices(currentFlow, newFlow)
	shadowFlow.waitGroup.Wait()

	if !strings.Contains(buf.String(), "[HUB_NAME] The following differences were found: 0.Address.number, 1.name, 1.birth-date") {
		t.Errorf("Expected error message not found in log output")
	}
}
