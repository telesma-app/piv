package card

import (
	"reflect"
	"testing"

	"github.com/telesma-app/piv/protocol"
)

func applicationFixture() protocol.ApplicationPropertyTemplate {
	return protocol.ApplicationPropertyTemplate{
		AID: []byte{1, 2}, TagAllocationAuthorityAID: []byte{3, 4},
		ApplicationLabel: "PIV", ApplicationURL: "url", Algorithms: []protocol.Algorithm{0xee, protocol.RSA3072},
	}
}

type propertyTransport struct {
	*scriptTransport
	application protocol.ApplicationPropertyTemplate
	reads       int
}

func (t *propertyTransport) ApplicationProperties() protocol.ApplicationPropertyTemplate {
	t.reads++
	return t.application
}

func TestNewRetainsProvidedApplicationPropertiesWithoutIO(t *testing.T) {
	raw := &propertyTransport{scriptTransport: &scriptTransport{t: t}, application: applicationFixture()}
	device := New(raw)

	t.Cleanup(func() { _ = device.Close() })

	for range 2 {
		got, ok := device.ApplicationProperties()
		if !ok || !reflect.DeepEqual(got, applicationFixture()) {
			t.Fatalf("properties = %+v, %v", got, ok)
		}
	}

	if raw.reads != 1 || raw.calls != 0 || raw.closeCalls != 0 {
		t.Fatalf("metadata/APDU/close calls = %d/%d/%d", raw.reads, raw.calls, raw.closeCalls)
	}

	if err := device.Close(); err != nil {
		t.Fatal(err)
	}

	got, ok := device.ApplicationProperties()
	if !ok || !reflect.DeepEqual(got, applicationFixture()) {
		t.Fatalf("properties after Close = %+v, %v", got, ok)
	}
}

func TestApplicationPropertiesUnavailableWithoutSelectionSnapshot(t *testing.T) {
	device, raw := newDevice(t)

	got, ok := device.ApplicationProperties()
	if ok || !reflect.DeepEqual(got, protocol.ApplicationPropertyTemplate{}) || raw.calls != 0 {
		t.Fatalf("properties = %+v, %v; APDU calls=%d", got, ok, raw.calls)
	}
}

func TestNewWithApplicationPropertiesSnapshotsExplicitSelection(t *testing.T) {
	raw := &scriptTransport{t: t}
	application := applicationFixture()
	device := NewWithApplicationProperties(raw, application)

	t.Cleanup(func() { _ = device.Close() })
	clear(application.AID)
	clear(application.TagAllocationAuthorityAID)
	clear(application.Algorithms)

	got, ok := device.ApplicationProperties()
	if !ok || !reflect.DeepEqual(got, applicationFixture()) || raw.calls != 0 {
		t.Fatalf("explicit snapshot = %+v, %v; APDU calls=%d", got, ok, raw.calls)
	}
}

func TestExplicitApplicationPropertiesOverrideTransportMetadata(t *testing.T) {
	raw := &propertyTransport{scriptTransport: &scriptTransport{t: t}, application: applicationFixture()}
	application := applicationFixture()
	application.ApplicationLabel = "explicit selection"
	device := NewWithApplicationProperties(raw, application)

	t.Cleanup(func() { _ = device.Close() })

	got, ok := device.ApplicationProperties()
	if !ok || !reflect.DeepEqual(got, application) || raw.calls != 0 {
		t.Fatalf("explicit properties = %+v, %v; APDU calls=%d", got, ok, raw.calls)
	}
}
