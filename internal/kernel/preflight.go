// Package kernel probes the running kernel for the capabilities every Veil
// module requires, so an unsupported environment fails with a clear message
// instead of a cryptic map-creation or CO-RE relocation error at load time.
package kernel

import (
	"errors"
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
)

// btfPath is where the kernel exposes its own BTF, needed for CO-RE.
const btfPath = "/sys/kernel/btf/vmlinux"

/*
	Preflight verifies the kernel supports what every module needs: BTF for
	CO-RE relocation, and ring buffer maps for event delivery. It returns a
	descriptive error naming the missing capability, or nil when the kernel
	is usable.
*/
func Preflight() error {
	if _, err := os.Stat(btfPath); err != nil {
		return fmt.Errorf("kernel BTF not found at %s: Veil needs a kernel built with CONFIG_DEBUG_INFO_BTF (5.8+ typically)", btfPath)
	}

	if err := features.HaveMapType(ebpf.RingBuf); err != nil {
		if errors.Is(err, ebpf.ErrNotSupported) {
			return fmt.Errorf("kernel lacks ring buffer map support: Veil requires kernel 5.8+")
		}
		return fmt.Errorf("probing ring buffer support: %w", err)
	}

	return nil
}
