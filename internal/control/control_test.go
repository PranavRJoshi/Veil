package control

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// fakeUpdater: in-memory MapUpdater for testing
// ---------------------------------------------------------------------------

type fakeUpdater struct {
	mu   sync.Mutex
	maps map[string]map[uint64]bool
}

func newFakeUpdater() *fakeUpdater {
	return &fakeUpdater{
		maps: map[string]map[uint64]bool{
			"pid":     {},
			"uid":     {},
			"port":    {},
			"syscall": {},
		},
	}
}

func (u *fakeUpdater) AddFilter(mapName string, key uint64) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	m, ok := u.maps[mapName]
	if !ok {
		return fmt.Errorf("unknown map: %s", mapName)
	}
	m[key] = true
	return nil
}

func (u *fakeUpdater) DelFilter(mapName string, key uint64) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	m, ok := u.maps[mapName]
	if !ok {
		return fmt.Errorf("unknown map: %s", mapName)
	}
	delete(m, key)
	return nil
}

func (u *fakeUpdater) ListFilters(mapName string) ([]uint64, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	m, ok := u.maps[mapName]
	if !ok {
		return nil, fmt.Errorf("unknown map: %s", mapName)
	}
	keys := make([]uint64, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys, nil
}

func (u *fakeUpdater) ClearFilters(mapName string) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	m, ok := u.maps[mapName]
	if !ok {
		return fmt.Errorf("unknown map: %s", mapName)
	}
	for k := range m {
		delete(m, k)
	}
	return nil
}

func (u *fakeUpdater) Status() string {
	return "test-status: ok"
}

// ---------------------------------------------------------------------------
// helper: connect and send/recv
// ---------------------------------------------------------------------------

func sendCommand(t *testing.T, sockPath, cmd string) string {
	t.Helper()
	conn, err := net.DialTimeout("unix", sockPath, time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))

	fmt.Fprintln(conn, cmd)
	scanner := bufio.NewScanner(conn)
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
		// For single-line responses, break after first line.
		// Multi-line: read until timeout or EOF.
		break
	}
	return strings.Join(lines, "\n")
}

// sendSession sends multiple commands over a single connection.
func sendSession(t *testing.T, sockPath string, cmds []string) []string {
	t.Helper()
	conn, err := net.DialTimeout("unix", sockPath, time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))

	scanner := bufio.NewScanner(conn)
	var responses []string
	for _, cmd := range cmds {
		fmt.Fprintln(conn, cmd)
		if scanner.Scan() {
			responses = append(responses, scanner.Text())
		}
	}
	return responses
}

func tempSockPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(os.TempDir(), fmt.Sprintf("veil-test-%d.sock", os.Getpid()))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestServer_StartStop(t *testing.T) {
	sock := tempSockPath(t)
	defer os.Remove(sock)

	srv := NewServer(sock, NewHandler(newFakeUpdater()))
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := srv.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	// Socket file should be cleaned up.
	if _, err := os.Stat(sock); !os.IsNotExist(err) {
		t.Error("socket file not cleaned up")
	}
}

func TestServer_Help(t *testing.T) {
	sock := tempSockPath(t)
	defer os.Remove(sock)

	srv := NewServer(sock, NewHandler(newFakeUpdater()))
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Stop()

	resp := sendCommand(t, sock, "help")
	if !strings.Contains(resp, "Veil control socket") {
		t.Errorf("unexpected help response: %q", resp)
	}
}

func TestServer_Status(t *testing.T) {
	sock := tempSockPath(t)
	defer os.Remove(sock)

	srv := NewServer(sock, NewHandler(newFakeUpdater()))
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Stop()

	resp := sendCommand(t, sock, "status")
	if resp != "test-status: ok" {
		t.Errorf("status = %q, want %q", resp, "test-status: ok")
	}
}

func TestServer_AddListClear(t *testing.T) {
	sock := tempSockPath(t)
	defer os.Remove(sock)

	updater := newFakeUpdater()
	srv := NewServer(sock, NewHandler(updater))
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Stop()

	responses := sendSession(t, sock, []string{
		"add pid 1234",
		"add pid 5678",
	})
	for i, r := range responses {
		if r != "OK" {
			t.Errorf("command %d: got %q, want OK", i, r)
		}
	}

	// Verify via the updater directly.
	updater.mu.Lock()
	if len(updater.maps["pid"]) != 2 {
		t.Errorf("expected 2 pid entries, got %d", len(updater.maps["pid"]))
	}
	updater.mu.Unlock()

	// Clear
	resp := sendCommand(t, sock, "clear pid")
	if resp != "OK" {
		t.Errorf("clear: got %q, want OK", resp)
	}

	updater.mu.Lock()
	if len(updater.maps["pid"]) != 0 {
		t.Errorf("expected 0 pid entries after clear, got %d", len(updater.maps["pid"]))
	}
	updater.mu.Unlock()
}

func TestServer_UnknownMap(t *testing.T) {
	sock := tempSockPath(t)
	defer os.Remove(sock)

	srv := NewServer(sock, NewHandler(newFakeUpdater()))
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Stop()

	resp := sendCommand(t, sock, "add bogus 123")
	if !strings.HasPrefix(resp, "ERR") {
		t.Errorf("expected ERR for unknown map, got %q", resp)
	}
}

func TestServer_UnknownCommand(t *testing.T) {
	sock := tempSockPath(t)
	defer os.Remove(sock)

	srv := NewServer(sock, NewHandler(newFakeUpdater()))
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Stop()

	resp := sendCommand(t, sock, "unknowncomm")
	if !strings.HasPrefix(resp, "ERR") {
		t.Errorf("expected ERR for unknown command, got %q", resp)
	}
}

func TestServer_InvalidKey(t *testing.T) {
	sock := tempSockPath(t)
	defer os.Remove(sock)

	srv := NewServer(sock, NewHandler(newFakeUpdater()))
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Stop()

	resp := sendCommand(t, sock, "add pid notanumber")
	if !strings.HasPrefix(resp, "ERR") {
		t.Errorf("expected ERR for invalid key, got %q", resp)
	}
}

func TestServer_Del(t *testing.T) {
	sock := tempSockPath(t)
	defer os.Remove(sock)

	updater := newFakeUpdater()
	srv := NewServer(sock, NewHandler(updater))
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Stop()

	responses := sendSession(t, sock, []string{
		"add pid 42",
		"del pid 42",
	})
	for _, r := range responses {
		if r != "OK" {
			t.Errorf("got %q, want OK", r)
		}
	}

	updater.mu.Lock()
	if len(updater.maps["pid"]) != 0 {
		t.Error("pid 42 should have been deleted")
	}
	updater.mu.Unlock()
}

func TestServer_ListPopulated(t *testing.T) {
	sock := tempSockPath(t)
	defer os.Remove(sock)
 
	updater := newFakeUpdater()
	srv := NewServer(sock, NewHandler(updater))
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Stop()
 
	/*
		Add two entries, then list. The list response is multi-line,
		one key per line. We use a raw connection to read all lines.
	*/
	conn, err := net.DialTimeout("unix", sock, time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
 
	scanner := bufio.NewScanner(conn)
 
	/* Add two PIDs */
	fmt.Fprintln(conn, "add pid 100")
	if !scanner.Scan() {
		t.Fatal("no response for add 100")
	}
	if scanner.Text() != "OK" {
		t.Fatalf("add 100: got %q", scanner.Text())
	}
 
	fmt.Fprintln(conn, "add pid 200")
	if !scanner.Scan() {
		t.Fatal("no response for add 200")
	}
	if scanner.Text() != "OK" {
		t.Fatalf("add 200: got %q", scanner.Text())
	}
 
	/* List: response is "100\n200" (two lines, order may vary) */
	fmt.Fprintln(conn, "list pid")
 
	var listed []string
	for scanner.Scan() {
		line := scanner.Text()
		listed = append(listed, line)
		/*
			The list response has exactly two entries; after reading
			both, there's no more data until we send another command.
			Use a short timeout via the deadline we set above.
		*/
		if len(listed) >= 2 {
			break
		}
	}
 
	if len(listed) != 2 {
		t.Fatalf("expected 2 list entries, got %d: %v", len(listed), listed)
	}
 
	/* Verify both keys are present (order not guaranteed from map iteration) */
	seen := map[string]bool{}
	for _, l := range listed {
		seen[l] = true
	}
	if !seen["100"] || !seen["200"] {
		t.Errorf("expected 100 and 200 in list, got %v", listed)
	}
}

func TestServer_ListEmpty(t *testing.T) {
	sock := tempSockPath(t)
	defer os.Remove(sock)
 
	srv := NewServer(sock, NewHandler(newFakeUpdater()))
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Stop()
 
	resp := sendCommand(t, sock, "list pid")
	if resp != "(empty)" {
		t.Errorf("expected '(empty)' for empty list, got %q", resp)
	}
}

// ---------------------------------------------------------------------------
// Handler direct tests
// ---------------------------------------------------------------------------
 
func TestHandler_AddAndList(t *testing.T) {
	updater := newFakeUpdater()
	h := NewHandler(updater)
 
	resp := h.HandleCommand("add pid 42")
	if resp != "OK" {
		t.Errorf("add: got %q, want OK", resp)
	}
 
	resp = h.HandleCommand("list pid")
	if resp != "42" {
		t.Errorf("list: got %q, want '42'", resp)
	}
}

func TestHandler_ResumeQuit(t *testing.T) {
	h := NewHandler(newFakeUpdater())
 
	if got := h.HandleCommand("resume"); got != "CMD:resume" {
		t.Errorf("resume: got %q, want CMD:resume", got)
	}
	if got := h.HandleCommand("quit"); got != "CMD:quit" {
		t.Errorf("quit: got %q, want CMD:quit", got)
	}
	if got := h.HandleCommand("exit"); got != "CMD:exit" {
		t.Errorf("exit: got %q, want CMD:exit", got)
	}
}
 
func TestHandler_EmptyCommand(t *testing.T) {
	h := NewHandler(newFakeUpdater())
	if got := h.HandleCommand(""); got != "" {
		t.Errorf("empty: got %q, want empty", got)
	}
	if got := h.HandleCommand("   "); got != "" {
		t.Errorf("spaces: got %q, want empty", got)
	}
}

// ---------------------------------------------------------------------------
// Interactive tests
// ---------------------------------------------------------------------------
 
func TestInteractive_Resume(t *testing.T) {
	h := NewHandler(newFakeUpdater())
	input := strings.NewReader("add pid 100\nresume\n")
	var out strings.Builder
 
	result := Interactive(h, input, &out)
	if result != ResultResume {
		t.Errorf("expected ResultResume, got %d", result)
	}
}
 
func TestInteractive_Quit(t *testing.T) {
	h := NewHandler(newFakeUpdater())
	input := strings.NewReader("quit\n")
	var out strings.Builder
 
	result := Interactive(h, input, &out)
	if result != ResultQuit {
		t.Errorf("expected ResultQuit, got %d", result)
	}
}

func TestInteractive_EOF(t *testing.T) {
	h := NewHandler(newFakeUpdater())
	input := strings.NewReader("") // EOF immediately
	var out strings.Builder
 
	result := Interactive(h, input, &out)
	if result != ResultQuit {
		t.Errorf("expected ResultQuit on EOF, got %d", result)
	}
}
 
func TestInteractive_CommandOutput(t *testing.T) {
	h := NewHandler(newFakeUpdater())
	input := strings.NewReader("add pid 42\nstatus\nquit\n")
	var out strings.Builder
 
	Interactive(h, input, &out)
 
	output := out.String()
	if !strings.Contains(output, "OK") {
		t.Errorf("output should contain 'OK' from add: %q", output)
	}
	if !strings.Contains(output, "test-status: ok") {
		t.Errorf("output should contain status: %q", output)
	}
}

// ---------------------------------------------------------------------------
// Handler: additional command coverage
// ---------------------------------------------------------------------------
 
func TestHandler_Del(t *testing.T) {
	updater := newFakeUpdater()
	h := NewHandler(updater)
 
	h.HandleCommand("add pid 42")
	resp := h.HandleCommand("del pid 42")
	if resp != "OK" {
		t.Errorf("del: got %q, want OK", resp)
	}
	resp = h.HandleCommand("list pid")
	if resp != "(empty)" {
		t.Errorf("list after del: got %q, want (empty)", resp)
	}
}
 
func TestHandler_Clear(t *testing.T) {
	updater := newFakeUpdater()
	h := NewHandler(updater)
 
	h.HandleCommand("add uid 0")
	h.HandleCommand("add uid 1000")
	resp := h.HandleCommand("clear uid")
	if resp != "OK" {
		t.Errorf("clear: got %q, want OK", resp)
	}
	resp = h.HandleCommand("list uid")
	if resp != "(empty)" {
		t.Errorf("list after clear: got %q, want (empty)", resp)
	}
}

func TestHandler_Status(t *testing.T) {
	h := NewHandler(newFakeUpdater())
	resp := h.HandleCommand("status")
	if resp != "test-status: ok" {
		t.Errorf("status: got %q, want 'test-status: ok'", resp)
	}
}
 
func TestHandler_Help(t *testing.T) {
	h := NewHandler(newFakeUpdater())
	resp := h.HandleCommand("help")
	if !strings.Contains(resp, "Veil control socket commands") {
		t.Errorf("help should contain header, got %q", resp)
	}
}
 
func TestHandler_UnknownCommand(t *testing.T) {
	h := NewHandler(newFakeUpdater())
	resp := h.HandleCommand("frobnicate")
	if !strings.HasPrefix(resp, "ERR") {
		t.Errorf("expected ERR for unknown command, got %q", resp)
	}
}


func TestHandler_UnknownMap(t *testing.T) {
	h := NewHandler(newFakeUpdater())
	resp := h.HandleCommand("add bogus 123")
	if !strings.HasPrefix(resp, "ERR") {
		t.Errorf("expected ERR for unknown map, got %q", resp)
	}
}
 
func TestHandler_InvalidKey(t *testing.T) {
	h := NewHandler(newFakeUpdater())
	resp := h.HandleCommand("add pid notanumber")
	if !strings.HasPrefix(resp, "ERR") {
		t.Errorf("expected ERR for invalid key, got %q", resp)
	}
}


func TestHandler_BadArgCount(t *testing.T) {
	h := NewHandler(newFakeUpdater())
 
	if resp := h.HandleCommand("add pid"); !strings.HasPrefix(resp, "ERR") {
		t.Errorf("add with 1 arg: got %q", resp)
	}
	if resp := h.HandleCommand("del"); !strings.HasPrefix(resp, "ERR") {
		t.Errorf("del with 0 args: got %q", resp)
	}
	if resp := h.HandleCommand("list"); !strings.HasPrefix(resp, "ERR") {
		t.Errorf("list with 0 args: got %q", resp)
	}
	if resp := h.HandleCommand("clear"); !strings.HasPrefix(resp, "ERR") {
		t.Errorf("clear with 0 args: got %q", resp)
	}
}

// ---------------------------------------------------------------------------
// Interactive: exit command
// ---------------------------------------------------------------------------
 
func TestInteractive_Exit(t *testing.T) {
	h := NewHandler(newFakeUpdater())
	input := strings.NewReader("exit\n")
	var out strings.Builder
 
	result := Interactive(h, input, &out)
	if result != ResultQuit {
		t.Errorf("expected ResultQuit for 'exit', got %d", result)
	}
}
 
func TestInteractive_EmptyLines(t *testing.T) {
	h := NewHandler(newFakeUpdater())
	input := strings.NewReader("\n\n\nquit\n")
	var out strings.Builder
 
	result := Interactive(h, input, &out)
	if result != ResultQuit {
		t.Errorf("expected ResultQuit, got %d", result)
	}
}

// ---------------------------------------------------------------------------
// Server: resume/quit commands should not be forwarded over socket
// ---------------------------------------------------------------------------
 
func TestServer_SocketIgnoresResumeQuit(t *testing.T) {
	sock := tempSockPath(t)
	defer os.Remove(sock)
 
	updater := newFakeUpdater()
	srv := NewServer(sock, NewHandler(updater))
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Stop()
 
	// Send "resume" over the socket; it should be silently ignored
	// (no response), not crash or close the connection.
	conn, err := net.DialTimeout("unix", sock, time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Second))
 
	scanner := bufio.NewScanner(conn)
 
	// Send resume; should produce no response
	fmt.Fprintln(conn, "resume")
 
	// Send a real command after to prove the connection is still alive
	fmt.Fprintln(conn, "status")
	if !scanner.Scan() {
		t.Fatal("no response after resume+status")
	}
	resp := scanner.Text()
	if resp != "test-status: ok" {
		t.Errorf("expected status response, got %q", resp)
	}
}
