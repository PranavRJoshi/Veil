package network

import (
	"testing"

	"github.com/PranavRJoshi/Veil/internal/events"
)

// ---------------------------------------------------------------------------
// ParseFilterConfig
// ---------------------------------------------------------------------------

func TestParseFilterConfig_SinglePID(t *testing.T) {
	cfg, err := ParseFilterConfig(map[string]string{"pid": "1234"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.PIDs) != 1 || cfg.PIDs[0] != 1234 {
		t.Errorf("expected [1234], got %v", cfg.PIDs)
	}
}

func TestParseFilterConfig_MultiplePorts(t *testing.T) {
	cfg, err := ParseFilterConfig(map[string]string{"port": "80,443,8080"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Ports) != 3 {
		t.Fatalf("expected 3 ports, got %d", len(cfg.Ports))
	}
	if cfg.Ports[0] != 80 || cfg.Ports[1] != 443 || cfg.Ports[2] != 8080 {
		t.Errorf("expected [80 443 8080], got %v", cfg.Ports)
	}
}

func TestParseFilterConfig_PortWithSpaces(t *testing.T) {
	cfg, err := ParseFilterConfig(map[string]string{"port": " 80 , 443 "})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Ports) != 2 || cfg.Ports[0] != 80 || cfg.Ports[1] != 443 {
		t.Errorf("spaces not trimmed: got %v", cfg.Ports)
	}
}

func TestParseFilterConfig_InvalidPort(t *testing.T) {
	_, err := ParseFilterConfig(map[string]string{"port": "http"})
	if err == nil {
		t.Fatal("expected error for non-numeric port")
	}
}

func TestParseFilterConfig_PortOverflow(t *testing.T) {
	_, err := ParseFilterConfig(map[string]string{"port": "65536"})
	if err == nil {
		t.Fatal("expected error for port exceeding uint16 max")
	}
}

func TestParseFilterConfig_NegativePort(t *testing.T) {
	_, err := ParseFilterConfig(map[string]string{"port": "-1"})
	if err == nil {
		t.Fatal("expected error for negative port")
	}
}

func TestParseFilterConfig_UIDs(t *testing.T) {
	cfg, err := ParseFilterConfig(map[string]string{"uid": "0,1000"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.UIDs) != 2 || cfg.UIDs[0] != 0 || cfg.UIDs[1] != 1000 {
		t.Errorf("expected [0 1000], got %v", cfg.UIDs)
	}
}

func TestParseFilterConfig_CommName(t *testing.T) {
	cfg, err := ParseFilterConfig(map[string]string{"name": "curl"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.CommName != "curl" {
		t.Errorf("expected CommName 'curl', got %q", cfg.CommName)
	}
}

func TestParseFilterConfig_EmptyFlags(t *testing.T) {
	cfg, err := ParseFilterConfig(map[string]string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.PIDs) != 0 || len(cfg.UIDs) != 0 || len(cfg.Ports) != 0 || cfg.CommName != "" {
		t.Errorf("expected empty config, got %+v", cfg)
	}
}

func TestParseFilterConfig_InvalidPID(t *testing.T) {
	_, err := ParseFilterConfig(map[string]string{"pid": "xyz"})
	if err == nil {
		t.Fatal("expected error for non-numeric PID")
	}
}

func TestParseFilterConfig_Combined(t *testing.T) {
	cfg, err := ParseFilterConfig(map[string]string{
		"pid":  "42",
		"uid":  "0",
		"port": "443",
		"name": "curl",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.PIDs[0] != 42 {
		t.Errorf("PID: %v", cfg.PIDs)
	}
	if cfg.UIDs[0] != 0 {
		t.Errorf("UID: %v", cfg.UIDs)
	}
	if cfg.Ports[0] != 443 {
		t.Errorf("Port: %v", cfg.Ports)
	}
	if cfg.CommName != "curl" {
		t.Errorf("CommName: %q", cfg.CommName)
	}
}

// ---------------------------------------------------------------------------
// matchesFilter
// ---------------------------------------------------------------------------

func makeNetEvent(comm string) events.NetworkEvent {
	var e events.NetworkEvent
	copy(e.Comm[:], comm)
	return e
}

func TestMatchesFilter_NoFilter(t *testing.T) {
	mod := &NetworkModule{filter: FilterConfig{}}
	if !mod.matchesFilter(makeNetEvent("anything")) {
		t.Error("empty filter should match all events")
	}
}

func TestMatchesFilter_CommMatch(t *testing.T) {
	mod := &NetworkModule{filter: FilterConfig{CommName: "curl"}}
	if !mod.matchesFilter(makeNetEvent("curl")) {
		t.Error("exact match should pass")
	}
}

func TestMatchesFilter_CommSubstring(t *testing.T) {
	mod := &NetworkModule{filter: FilterConfig{CommName: "ssh"}}
	if !mod.matchesFilter(makeNetEvent("sshd")) {
		t.Error("substring match should pass")
	}
}

func TestMatchesFilter_CommNoMatch(t *testing.T) {
	mod := &NetworkModule{filter: FilterConfig{CommName: "nginx"}}
	if mod.matchesFilter(makeNetEvent("curl")) {
		t.Error("non-matching comm should be filtered out")
	}
}

// ---------------------------------------------------------------------------
// networkToFields
// ---------------------------------------------------------------------------

func TestNetworkToFields_AllFieldsPresent(t *testing.T) {
	e := events.NetworkEvent{
		Event: events.Event{
			Kind:      events.KindNetwork,
			PID:       1234,
			UID:       1000,
			Timestamp: 99999,
		},
		SrcAddr:  0x0100007F, /* 127.0.0.1 */
		DstAddr:  0x00000000,
		SrcPort:  54268,
		DstPort:  80,
		EvtType:  EvtConnect,
		OldState: 7,
		NewState: 2,
	}
	copy(e.Comm[:], "curl")

	f := networkToFields(e)

	requiredKeys := []string{
		"kind", "pid", "uid", "timestamp", "comm",
		"evt_type", "saddr", "sport", "daddr", "dport",
		"oldstate", "newstate",
	}
	for _, k := range requiredKeys {
		if _, ok := f[k]; !ok {
			t.Errorf("missing key %q in networkToFields output", k)
		}
	}

	if f["pid"] != uint32(1234) {
		t.Errorf("pid = %v, want 1234", f["pid"])
	}
	if f["comm"] != "curl" {
		t.Errorf("comm = %v, want 'curl'", f["comm"])
	}
	if f["evt_type"] != "CONNECT" {
		t.Errorf("evt_type = %v, want 'CONNECT'", f["evt_type"])
	}
	if f["sport"] != uint16(54268) {
		t.Errorf("sport = %v, want 54268", f["sport"])
	}
	if f["dport"] != uint16(80) {
		t.Errorf("dport = %v, want 80", f["dport"])
	}
	if f["saddr"] != "127.0.0.1" {
		t.Errorf("saddr = %v, want '127.0.0.1'", f["saddr"])
	}
	if f["oldstate"] != "CLOSE" {
		t.Errorf("oldstate = %v, want 'CLOSE'", f["oldstate"])
	}
	if f["newstate"] != "SYN_SENT" {
		t.Errorf("newstate = %v, want 'SYN_SENT'", f["newstate"])
	}
	if f["kind"] != "network" {
		t.Errorf("kind = %v, want 'network'", f["kind"])
	}
}
