package files

//go:generate bpf2go -cc clang -cflags "-O2 -g -Wall -target bpf -D__TARGET_ARCH_arm64" FileAccess ../../bpf/file_access.bpf.c

import (
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/PranavRJoshi/Veil/internal/exterrs"
	"github.com/PranavRJoshi/Veil/internal/events"
	"github.com/PranavRJoshi/Veil/internal/loader"
)

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
}

/*
	Create an instance of object of type 'FilesModule'.
*/
func New() *FilesModule {
	return &FilesModule{
		BaseProgram:	loader.NewBaseProgram("file_access"),
		Events:			make(chan events.FileEvent, 256),
	}
}

/*
	Load() method that is called by LoadAll method of BaseProgram.
	Recall that we embed BaseProgram onto FilesModule.
*/
func (f *FilesModule) Load() error {
	if err := LoadFileAccessObjects(&f.objs, nil); err != nil {
		return fmt.Errorf("files: load objects: %w", err)
	}

	var err error
	/*
		The function Kprobe and Kretprobe are both defined in 
		cilium/ebpf/link/kprobe.go and both of these functions
		calls package-internal function named 'kprobe' defined
		in the same file.
	*/
	f.kprobeOpen, err = link.Kprobe("vfs_open", f.objs.KprobeVfsOpen, nil)
	if err != nil {
		return fmt.Errorf("files: attach vfs_open: %w", err)
	}

	f.kprobeRead, err = link.Kprobe("vfs_read", f.objs.KprobeVfsRead, nil)
	if err != nil {
		return fmt.Errorf("files: attach vfs_read: %w", err)
	}

	f.kprobeWrite, err = link.Kprobe("vfs_write", f.objs.KprobeVfsWrite, nil)
	if err != nil {
		return fmt.Errorf("files: attach vfs_write: %w", err)
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

		f.Events <- e
	}
}
