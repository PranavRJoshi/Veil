// Package control provides runtime modification of BPF filter maps
// via an interactive terminal prompt or a Unix socket server.
package control

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/chzyer/readline"
)

/*
MapUpdater bridges control commands to BPF map operations.
*/
type MapUpdater interface {
	AddFilter(mapName string, key uint64) error
	DelFilter(mapName string, key uint64) error
	ListFilters(mapName string) ([]uint64, error)
	ClearFilters(mapName string) error
	Status() string
}

/*
Handler processes control commands against a MapUpdater.
It is shared by both the interactive prompt and the socket server.
*/
type Handler struct {
	updater MapUpdater
}

func NewHandler(updater MapUpdater) *Handler {
	return &Handler{updater: updater}
}

/*
HandleCommand parses and executes a single command line, returning
the response string. Safe to call from any goroutine.

Map names can be plain ("pid") or module-qualified ("network.port"). Plain
names route through the MapUpdater's dispatch logic (e.g., compositeUpdater
routes by ownership). Module-qualified names are passed through as-is; the
MapUpdater implementation decides how to handle the prefix.
*/
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
		if len(parts) == 3 {
			return h.doAdd(parts[1], parts[2])
		}
		if len(parts) == 4 {
			/*
				4-part form: add <module> <map> <keys>
				Combine module and map into "module.map" so the
				compositeUpdater can dispatch by module name.
			*/
			qualifiedMap := parts[1] + "." + parts[2]
			return h.doAdd(qualifiedMap, parts[3])
		}
		return "ERR usage: add [<module>] <map> <key>"
	case "del":
		if len(parts) == 3 {
			return h.doDel(parts[1], parts[2])
		}
		if len(parts) == 4 {
			qualifiedMap := parts[1] + "." + parts[2]
			return h.doDel(qualifiedMap, parts[3])
		}
		return "ERR usage: del [<module>] <map> <key>"
	case "list":
		if len(parts) == 2 {
			return h.doList(parts[1])
		}
		if len(parts) == 3 {
			qualifiedMap := parts[1] + "." + parts[2]
			return h.doList(qualifiedMap)
		}
		return "ERR usage: list [<module>] <map>"
	case "clear":
		if len(parts) == 2 {
			return h.doClear(parts[1])
		}
		if len(parts) == 3 {
			qualifiedMap := parts[1] + "." + parts[2]
			return h.doClear(qualifiedMap)
		}
		return "ERR usage: clear [<module>] <map>"
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
	warn := h.findExisting(mapName, key)
	if err := h.updater.AddFilter(mapName, key); err != nil {
		return fmt.Sprintf("ERR %v", err)
	}
	if warn != "" {
		return "WARN " + warn
	}
	return "OK"
}

func (h *Handler) findExisting(mapName string, key uint64) string {
	if dl, ok := h.updater.(DetailedLister); ok {
		result, err := dl.ListFiltersDetailed(mapName)
		if err != nil {
			return ""
		}
		var found []string
		for mod, keys := range result {
			for _, k := range keys {
				if k == key {
					found = append(found, mod)
					break
				}
			}
		}
		if len(found) > 0 {
			sort.Strings(found)
			return fmt.Sprintf("key %d already present in %s (%s)", key, mapName, strings.Join(found, ", "))
		}
		return ""
	}
	keys, err := h.updater.ListFilters(mapName)
	if err != nil {
		return ""
	}
	for _, k := range keys {
		if k == key {
			return fmt.Sprintf("key %d already present in %s", key, mapName)
		}
	}
	return ""
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
	if dl, ok := h.updater.(DetailedLister); ok {
		return h.doListDetailed(dl, mapName)
	}
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

/*
	DetailedLister is an optional extension of MapUpdater. compositeUpdater
	implements it so that list commands in multi-module mode show results
	per module rather than only from the first matching module.
*/
type DetailedLister interface {
	ListFiltersDetailed(mapName string) (map[string][]uint64, error)
}

func (h *Handler) doListDetailed(dl DetailedLister, mapName string) string {
	result, err := dl.ListFiltersDetailed(mapName)
	if err != nil {
		return fmt.Sprintf("ERR %v", err)
	}

	modules := make([]string, 0, len(result))
	for mod := range result {
		modules = append(modules, mod)
	}
	sort.Strings(modules)

	maxLen := 0
	for _, mod := range modules {
		if len(mod) > maxLen {
			maxLen = len(mod)
		}
	}

	lines := make([]string, 0, len(modules))
	for _, mod := range modules {
		keys := result[mod]
		var keyStr string
		if len(keys) == 0 {
			keyStr = "(none)"
		} else {
			parts := make([]string, len(keys))
			for i, k := range keys {
				parts[i] = strconv.FormatUint(k, 10)
			}
			keyStr = "[" + strings.Join(parts, ", ") + "]"
		}
		lines = append(lines, fmt.Sprintf("%-*s  %s", maxLen+1, mod+":", keyStr))
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

/*
bellingCompleter wraps an AutoCompleter and writes BEL (\a) to w when Tab
finds no completions, giving audible feedback for unrecognised input.
*/
type bellingCompleter struct {
	inner readline.AutoCompleter
	w     io.Writer
}

func (b *bellingCompleter) Do(line []rune, pos int) ([][]rune, int) {
	newLine, length := b.inner.Do(line, pos)
	if len(newLine) == 0 {
		fmt.Fprint(b.w, "\a")
	}
	return newLine, length
}

/*
InteractiveResult indicates how the interactive session ended.
*/
type InteractiveResult int

const (
	ResultResume InteractiveResult = iota // user typed "resume"
	ResultQuit                            // user typed "quit"/"exit" or Ctrl+C/Ctrl+D
)

/*
Interactive runs a readline-backed command loop writing responses to w.
It returns when the user types "resume", "quit", "exit", CTRL-C, CTRL-D,
or cancel is closed (used by the caller to unblock on external signals).

In raw terminal mode readline intercepts CTRL-C itself (returning
ErrInterrupt) so SIGINT does not reach the process signal channel while
this function is running.
*/
func Interactive(h *Handler, w io.Writer, cancel <-chan struct{}) InteractiveResult {
	fmt.Fprintln(w, "\nVeil interactive control (type 'help' for commands, 'resume' to continue tracing, 'quit' to exit)")

	mapItems := []readline.PrefixCompleterInterface{
		readline.PcItem("pid"),
		readline.PcItem("uid"),
		readline.PcItem("port"),
		readline.PcItem("syscall"),
		readline.PcItem("pid_deny"),
		readline.PcItem("uid_deny"),
		readline.PcItem("port_deny"),
		readline.PcItem("cpu"),
		readline.PcItem("cpu_deny"),
		readline.PcItem("fault"),
		readline.PcItem("fault_deny"),
	}

	completer := readline.NewPrefixCompleter(
		readline.PcItem("add",   mapItems...),
		readline.PcItem("del",   mapItems...),
		readline.PcItem("list",  mapItems...),
		readline.PcItem("clear", mapItems...),
		readline.PcItem("status"),
		readline.PcItem("resume"),
		readline.PcItem("quit"),
		readline.PcItem("exit"),
		readline.PcItem("help"),
	)

	rl, err := readline.NewEx(&readline.Config{
		Prompt:          "veil $ ",
		AutoComplete:    &bellingCompleter{inner: completer, w: w},
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
		Stdout:          w,
	})
	if err != nil {
		/* readline unavailable (non-terminal or init error); use plain scanner */
		return interactiveScanner(h, os.Stdin, w)
	}

	var once sync.Once
	closeRL := func() { once.Do(func() { rl.Close() }) }
	defer closeRL()

	innerDone := make(chan struct{})
	defer close(innerDone)
	go func() {
		select {
		case <-cancel:
			closeRL()
		case <-innerDone:
		}
	}()

	for {
		line, err := rl.Readline()
		if err == readline.ErrInterrupt || err == io.EOF {
			return ResultQuit
		}
		if err != nil {
			return ResultQuit
		}

		line = strings.TrimSpace(line)
		if line == "" {
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
	}
}

/*
interactiveScanner is the plain bufio.Scanner fallback used when readline
cannot initialise (e.g. stdout is not a terminal).
*/
func interactiveScanner(h *Handler, r io.Reader, w io.Writer) InteractiveResult {
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
	return ResultQuit
}

// --- Unix socket server ---

/*
Server listens on a Unix domain socket and processes filter commands.
*/
type Server struct {
	handler *Handler
	path    string
	ln      net.Listener
	done    chan struct{}
	wg      sync.WaitGroup
}

/*
NewServer creates a control server at the given socket path.
*/
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

/*
Stop shuts down the server and removes the socket file.
*/
func (s *Server) Stop() error {
	close(s.done)
	if s.ln != nil {
		s.ln.Close()
	}
	s.wg.Wait()
	os.Remove(s.path)
	return nil
}

/*
SocketPath returns the path to the Unix socket.
*/
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

const helpText = `Veil control commands:
  add <map> <key>             Add a filter key (e.g. add pid 1234)
  add <module> <map> <key>    Add to a specific module
  del <map> <key>             Remove a filter key
  del <module> <map> <key>    Remove from a specific module
  list <map>                  List all keys in a filter map
  list <module> <map>         List from a specific module
  clear <map>                 Remove all keys from a filter map
  clear <module> <map>        Clear a specific module's map
  status                      Show active filters and module state
  resume                      Resume tracing (interactive mode only)
  quit/exit                   Stop Veil and exit
  help                        Show this help

Module: syscall, files, network
General Map Names: pid, uid
Syscall Module Map Names: syscall
Network Module Map Names: port
Keys: decimal`
