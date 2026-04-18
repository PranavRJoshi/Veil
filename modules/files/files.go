package files

//go:generate bpf2go -cc clang -cflags "-O2 -g -Wall -target bpf -D__TARGET_ARCH_arm64" FileAccess ../../bpf/file_access.bpf.c

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/PranavRJoshi/Veil/internal/exterrs"
	"github.com/PranavRJoshi/Veil/internal/events"
	"github.com/PranavRJoshi/Veil/internal/loader"
)

/*
	FilterConfig holds the parsed filter values from the CLI flags.
	These control both kernel-side BPF map filters (PID, UID) and
	userspace filters (comm name, filename substring, operation type).
*/
type FilterConfig struct {
	PIDs		[]uint32  /* -p flag: filter by PID (kernel-side) */
	UIDs		[]uint32  /* -u flag: filter by UID (kernel-side) */
	CommName	string    /* -n flag: filter by process name (userspace) */
	FileName	string    /* --file flag: filter by filename substring (userspace) */
	Ops			[]string  /* --op flag: filter by operation type (selective kprobe attachment) */
}

/*
	validOps is the set of recognized operation names.
*/
var validOps = map[string]bool{
	"open":  true,
	"read":  true,
	"write": true,
}

/*
	ParseFilterConfig interprets the raw CLI flags map into a typed
	FilterConfig. Returns an error for invalid values.
*/
func ParseFilterConfig(flags map[string]string) (FilterConfig, error) {
	var cfg FilterConfig
 
	/* parse the filtered PIDs for this module, and must be comma-separated */
	if raw, ok := flags["pid"]; ok {
		for _, s := range strings.Split(raw, ",") {
			v, err := strconv.ParseUint(strings.TrimSpace(s), 10, 32)
			if err != nil {
				return cfg, fmt.Errorf("invalid PID %q: %w", s, err)
			}
			cfg.PIDs = append(cfg.PIDs, uint32(v))
		}
	}
 
	/* parse the filtered UIDs for this module, and must be comma-separated */
	if raw, ok := flags["uid"]; ok {
		for _, s := range strings.Split(raw, ",") {
			v, err := strconv.ParseUint(strings.TrimSpace(s), 10, 32)
			if err != nil {
				return cfg, fmt.Errorf("invalid UID %q: %w", s, err)
			}
			cfg.UIDs = append(cfg.UIDs, uint32(v))
		}
	}
 
	/* filter for command name (process name), if present */
	if raw, ok := flags["name"]; ok {
		cfg.CommName = raw
	}
 
	/* filter for filename, if present */
	if raw, ok := flags["file"]; ok {
		cfg.FileName = raw
	}
 
	/* filter for file-related opcode, must be open, read, or write, or combination */
	if raw, ok := flags["op"]; ok {
		for _, s := range strings.Split(raw, ",") {
			op := strings.TrimSpace(s)
			if !validOps[op] {
				return cfg, fmt.Errorf("unknown operation %q (valid: open, read, write)", op)
			}
			cfg.Ops = append(cfg.Ops, op)
		}
	}
 
	return cfg, nil
}

/*
	wantOp returns true if the given operation should be traced.
	If no --op filter is set, all operations are traced.
*/
func (cfg *FilterConfig) wantOp(op string) bool {
	if len(cfg.Ops) == 0 {
		return true
	}
	for _, o := range cfg.Ops {
		if o == op {
			return true
		}
	}
	return false
}

/*
	The semantics is similar to that of syscall tracer except that we use
	kernel probes instead of tracepoints. Since kernel probes are not static
	and may change between kernel version, some extra care is done, not in
	the userspace side, but in the kernel side.
*/
type FilesModule struct {
	*loader.BaseProgram
	objs		FileAccessObjects
	kprobeOpen	link.Link
	kprobeRead	link.Link
	kprobeWrite	link.Link
	reader		*ringbuf.Reader
	Events		chan events.FileEvent
	filter      FilterConfig
}

/*
	Create an instance of object of type 'FilesModule'.
*/
func New(filter FilterConfig) *FilesModule {
	return &FilesModule{
		BaseProgram:	loader.NewBaseProgram("file_access"),
		Events:			make(chan events.FileEvent, 256),
		filter:			filter,
	}
}

/*
	populateFilters writes the filter values into the BPF maps after
	the objects have been loaded. Same bitmask convention as the
	syscall module:
	  bit 0 = pid_filter active
	  bit 1 = uid_filter active
*/
func (f *FilesModule) populateFilters() error {
	var mask uint32
	placeholder := uint8(1)

	/*
		The implementation detail for populating the filters are described in
		the syscall tracing module. The semantic is identical with the syscall
		module.
	*/
 
	if len(f.filter.PIDs) > 0 {
		mask |= 1
		for _, pid := range f.filter.PIDs {
			if err := f.objs.PidFilter.Update(pid, placeholder, ebpf.UpdateAny); err != nil {
				return fmt.Errorf("files: set pid filter %d: %w", pid, err)
			}
		}
	}
 
	if len(f.filter.UIDs) > 0 {
		mask |= 2
		for _, uid := range f.filter.UIDs {
			if err := f.objs.UidFilter.Update(uid, placeholder, ebpf.UpdateAny); err != nil {
				return fmt.Errorf("files: set uid filter %d: %w", uid, err)
			}
		}
	}
 
	if mask != 0 {
		cfgKey := uint32(0)
		if err := f.objs.FilterCfg.Update(cfgKey, mask, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("files: set filter config: %w", err)
		}
	}
 
	return nil
}

/*
	Load() method that is called by LoadAll method of BaseProgram.
	Recall that we embed BaseProgram onto FilesModule.

	When --op is specified, only the kprobes for the requested operations
	are attached. This is a Level 1 optimization: if the user only cares
	about reads, we never attach vfs_open or vfs_write, so the BPF
	program never fires for those operations at all.
*/
func (f *FilesModule) Load() error {
	/*
		Load the eBPF program and its associated maps into the kernel.
		This is similar to the one described in syscall tracing module.
	*/
	if err := LoadFileAccessObjects(&f.objs, nil); err != nil {
		return fmt.Errorf("files: load objects: %w", err)
	}

	/*
		Before we start executing the eBPF program that was loaded above,
		we need to update the map to enable early-filtering of events
		that was requested by the user.
	*/
	if err := f.populateFilters(); err != nil {
		return err
	}

	var err error
	/*
		The function Kprobe and Kretprobe are both defined in 
		cilium/ebpf/link/kprobe.go and both of these functions
		calls package-internal function named 'kprobe' defined
		in the same file.
 
		Selective attachment: only attach hooks for operations
		the user wants to trace. Only upon successful call to
		these functions will the kernel start emitting data
		into ring buffer.
	*/
	if f.filter.wantOp("open") {
		f.kprobeOpen, err = link.Kprobe("vfs_open", f.objs.KprobeVfsOpen, nil)
		if err != nil {
			return fmt.Errorf("files: attach vfs_open: %w", err)
		}
	}

	if f.filter.wantOp("read") {
		f.kprobeRead, err = link.Kprobe("vfs_read", f.objs.KprobeVfsRead, nil)
		if err != nil {
			return fmt.Errorf("files: attach vfs_read: %w", err)
		}
	}

	if f.filter.wantOp("write") {
		f.kprobeWrite, err = link.Kprobe("vfs_write", f.objs.KprobeVfsWrite, nil)
		if err != nil {
			return fmt.Errorf("files: attach vfs_write: %w", err)
		}
	}

	/*
		Create a new reader for the ring buffer. Already described in syscall
		tracer.
	*/
	rd, err := ringbuf.NewReader(f.objs.FileEvents)
	if err != nil {
		return fmt.Errorf("files: open ringbuf: %w", err)
	}
	f.reader = rd

	if err := f.MarkLoaded(); err != nil {
		return err
	}

	go f.poll()
	return nil
}

func (f *FilesModule) Close() error {
	var closeErrs []error

	if f.reader != nil {
		closeErrs = append(closeErrs, f.reader.Close())
	}
	if f.kprobeOpen != nil {
		closeErrs = append(closeErrs, f.kprobeOpen.Close())
	}
	if f.kprobeRead != nil {
		closeErrs = append(closeErrs, f.kprobeRead.Close())
	}
	if f.kprobeWrite != nil {
		closeErrs = append(closeErrs, f.kprobeWrite.Close())
	}

	f.objs.Close()
	close(f.Events)

	if err := f.MarkClosed(); err != nil {
		closeErrs = append(closeErrs, err)
	}

	return exterrs.Join(closeErrs)
}

/*
	Run consumes events from the Events channel and prints formatted
	output to stdout. It blocks until the done channel is closed (or
	the Events channel is closed). This method is intended to be called
	as a goroutine from the CLI layer.
*/
func (f *FilesModule) Run(done <-chan struct{}) {
	for {
		select {
		case e, ok := <-f.Events:
			if !ok {
				return
			}
			fmt.Printf("[%s] pid=%-6d uid=%-5d comm=%-16s op=%-6s filename=%s\n",
				e.Kind,
				e.PID,
				e.UID,
				e.ProcessName(),
				e.Op,
				e.FileName,
			)
		case <-done:
			return
		}
	}
}

func (f *FilesModule) poll() {
	for {
		record, err := f.reader.Read()
		if err != nil {
			return
		}

		e, err := parseEvent(record.RawSample)
		if err != nil {
			continue
		}

		/* Userspace filter: comm name (substring match) */
		if f.filter.CommName != "" && !strings.Contains(e.ProcessName(), f.filter.CommName) {
			continue
		}
 
		/* Userspace filter: filename substring */
		if f.filter.FileName != "" && !strings.Contains(e.FileName, f.filter.FileName) {
			continue
		}

		f.Events <- e
	}
}
