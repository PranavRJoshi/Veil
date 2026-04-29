// Package control provides runtime modification of BPF filter maps
// via an interactive terminal prompt or a Unix socket server.
package control

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
)

// MapUpdater bridges control commands to BPF map operations.
type MapUpdater interface {
	AddFilter(mapName string, key uint64) error
	DelFilter(mapName string, key uint64) error
	ListFilters(mapName string) ([]uint64, error)
	ClearFilters(mapName string) error
	Status() string
}

// Handler processes control commands against a MapUpdater.
// It is shared by both the interactive prompt and the socket server.
type Handler struct {
	updater MapUpdater
}
 
func NewHandler(updater MapUpdater) *Handler {
	return &Handler{updater: updater}
}

// HandleCommand parses and executes a single command line, returning
// the response string. Safe to call from any goroutine.
func (h *Handler) HandleCommand(line string) string {
	parts := strings.Fields(strings.TrimSpace(line))
	if len(parts) == 0 {
		return ""
	}
 
	switch strings.ToLower(parts[0]) {
		case "help":
			return helpText
		case "status":
			return h.updater.Status()
		case "add":
			if len(parts) != 3 {
				return "ERR usage: add <map> <key>"
			}
			return h.doAdd(parts[1], parts[2])
		case "del":
			if len(parts) != 3 {
				return "ERR usage: del <map> <key>"
			}
			return h.doDel(parts[1], parts[2])
		case "list":
			if len(parts) != 2 {
				return "ERR usage: list <map>"
			}
			return h.doList(parts[1])
		case "clear":
			if len(parts) != 2 {
				return "ERR usage: clear <map>"
			}
			return h.doClear(parts[1])
		case "resume", "quit", "exit":
			/*
				These are handled by the caller (interactive or main loop),
				not by the handler itself. Return them as-is so the caller
				can detect them.
			*/
			return "CMD:" + strings.ToLower(parts[0])
		default:
			return fmt.Sprintf("ERR unknown command: %s (try 'help')", parts[0])
	}
}

func (h *Handler) doAdd(mapName, keyStr string) string {
	key, err := strconv.ParseUint(keyStr, 10, 64)
	if err != nil {
		return fmt.Sprintf("ERR invalid key %q: %v", keyStr, err)
	}
	if err := h.updater.AddFilter(mapName, key); err != nil {
		return fmt.Sprintf("ERR %v", err)
	}
	return "OK"
}

func (h *Handler) doDel(mapName, keyStr string) string {
	key, err := strconv.ParseUint(keyStr, 10, 64)
	if err != nil {
		return fmt.Sprintf("ERR invalid key %q: %v", keyStr, err)
	}
	if err := h.updater.DelFilter(mapName, key); err != nil {
		return fmt.Sprintf("ERR %v", err)
	}
	return "OK"
}

func (h *Handler) doList(mapName string) string {
	keys, err := h.updater.ListFilters(mapName)
	if err != nil {
		return fmt.Sprintf("ERR %v", err)
	}
	if len(keys) == 0 {
		return "(empty)"
	}
	lines := make([]string, len(keys))
	for i, k := range keys {
		lines[i] = strconv.FormatUint(k, 10)
	}
	return strings.Join(lines, "\n")
}
 
func (h *Handler) doClear(mapName string) string {
	if err := h.updater.ClearFilters(mapName); err != nil {
		return fmt.Sprintf("ERR %v", err)
	}
	return "OK"
}

// --- Interactive mode (stdin/stdout) ---
 
// InteractiveResult indicates how the interactive session ended.
type InteractiveResult int
 
const (
	ResultResume InteractiveResult = iota // user typed "resume"
	ResultQuit                            // user typed "quit"/"exit" or Ctrl+C/Ctrl+D
)
 
// Interactive runs a blocking command loop on the given reader/writer
// (typically os.Stdin/os.Stderr). It returns when the user types
// "resume", "quit", "exit", or the reader reaches EOF.
func Interactive(h *Handler, r io.Reader, w io.Writer) InteractiveResult {
	fmt.Fprintln(w, "\nVeil interactive control (type 'help' for commands, 'resume' to continue tracing, 'quit' to exit)")
	fmt.Fprint(w, "veil $ ")
 
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			fmt.Fprint(w, "veil $ ")
			continue
		}
 
		resp := h.HandleCommand(line)
 
		switch resp {
			case "CMD:resume":
				return ResultResume
			case "CMD:quit", "CMD:exit":
				return ResultQuit
			default:
				if resp != "" {
					fmt.Fprintln(w, resp)
				}
		}
 
		fmt.Fprint(w, "veil $ ")
	}
 
	// EOF (CRTL-D), treat it as quit
	return ResultQuit
}

// --- Unix socket server ---

// Server listens on a Unix domain socket and processes filter commands.
type Server struct {
	handler *Handler
	path    string
	ln      net.Listener
	done    chan struct{}
	wg      sync.WaitGroup
}

// NewServer creates a control server at the given socket path.
func NewServer(path string, handler *Handler) *Server {
	return &Server{
		handler: handler,
		path:    path,
		done:    make(chan struct{}),
	}
}

func (s *Server) Start() error {
	os.Remove(s.path)

	ln, err := net.Listen("unix", s.path)
	if err != nil {
		return fmt.Errorf("control: listen %s: %w", s.path, err)
	}
	s.ln = ln

	// Make socket world-readable so non-root users can connect
	// (the tracing process runs as root, but the control client may not).
	os.Chmod(s.path, 0666)

	s.wg.Add(1)
	go s.acceptLoop()
	return nil
}

// Stop shuts down the server and removes the socket file.
func (s *Server) Stop() error {
	close(s.done)
	if s.ln != nil {
		s.ln.Close()
	}
	s.wg.Wait()
	os.Remove(s.path)
	return nil
}

// SocketPath returns the path to the Unix socket.
func (s *Server) SocketPath() string {
	return s.path
}

func (s *Server) acceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			select {
				case <-s.done:
					return
				default:
					continue
			}
		}
		s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		select {
			case <-s.done:
				return
			default:
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		resp := s.handler.HandleCommand(line)
		/*
			Don't send CMD: prefixed responses over socket, they're interactive
			mode signals
		*/
		if strings.HasPrefix(resp, "CMD:") {
			continue
		}
		fmt.Fprintln(conn, resp)
	}
}

const helpText = `Veil control socket commands:
  add <map> <key>    Add a filter key (e.g. add pid 1234)
  del <map> <key>    Remove a filter key
  list <map>         List all keys in a filter map
  clear <map>        Remove all keys from a filter map
  status             Show active filters and module state
  resume             Resume tracing (interactive mode only)
  quit/exit          Stop Veil and exit
  help               Show this help

Map names: pid, uid, port, syscall
Keys: decimal integers`
