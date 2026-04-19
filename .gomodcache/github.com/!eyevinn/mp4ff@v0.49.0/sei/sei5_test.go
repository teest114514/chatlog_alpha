package sei

import (
	"testing"
)

func TestSEI5_UnregisteredType(t *testing.T) {
	raw := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x40, 0x40, 0x40, 0x40}

	us, err := DecodeUserDataUnregisteredSEI(&SEIData{payloadType: SEIUserDataUnregisteredType,
		payload: raw})
	if err != nil {
		t.Error("Error decoding SEIUserDataUnregisteredType")
	}
	if us.Type() != SEIUserDataUnregisteredType {
		t.Error("Expected SEIUserDataUnregisteredType")
	}
	if us.Size() != 20 {
		t.Errorf("Expected size 20, got %d", us.Size())
	}
	if string(us.Payload()) != string(raw) {
		t.Errorf("Unexpected payload %v, expected %v", us.Payload(), raw)
	}
	wantedString := "SEI type 5, size=20, uuid=\"000102030405060708090a0b0c0d0e0f\", payload=\"@@@@\""
	if wantedString != us.String() {
		t.Errorf("Unexpected string %q, expected %q", us.String(), wantedString)
	}

}
