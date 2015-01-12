// +build linux,cgo,seccomp

package seccomp

import (
	"fmt"
	"log"
	"syscall"

	libseccomp "github.com/mheon/golang-seccomp"
)

var (
	// Match action: deny a syscall with -EPERM return code
	actDeny libseccomp.ScmpAction = libseccomp.ActErrno.SetReturnCode(int16(syscall.EPERM))
)

// Filters given syscalls in a container, preventing them from being used
// Started in the container init process, and carried over to all child processes
func InitSeccomp(blockedCalls []BlockedSyscall, additionalArches []string) error {
	if len(blockedCalls) == 0 {
		return nil
	}

	archNative, err := libseccomp.GetNativeArch()
	if err != nil {
		return fmt.Errorf("Error getting native architecture: %s", err)
	}

	filter, err := libseccomp.NewFilter(libseccomp.ActAllow)
	if err != nil {
		return fmt.Errorf("Error creating filter: %s", err)
	}

	// Unset no new privs bit
	if err = filter.SetNoNewPrivsBit(false); err != nil {
		return fmt.Errorf("Error setting no new privileges: %s", err)
	}

	// Add all additional architectures to the filter
	for _, arch := range additionalArches {
		archConst, err := libseccomp.GetArchFromString(arch)
		if err != nil {
			return fmt.Errorf("Error adding architecture to filter: %s", err)
		}

		if err = filter.AddArch(archConst); err != nil {
			return fmt.Errorf("Error adding architecture %s to filter: %s", arch, err)
		}
	}

	// If native arch is AMD64, add X86 to filter
	if archNative == libseccomp.ArchAMD64 {
		if err = filter.AddArch(libseccomp.ArchX86); err != nil {
			return fmt.Errorf("Error adding x86 arch to filter: %s", err)
		}
	}

	for _, call := range blockedCalls {
		if len(call.Syscall) == 0 {
			return fmt.Errorf("Empty string is not a valid syscall!")
		}

		callNum, err := libseccomp.GetSyscallFromName(call.Syscall)
		if err != nil {
			log.Printf("Could not resolve syscall name %s: %s. Ignoring syscall.", call.Syscall, err)
			continue
		}

		if call.Conditional {
			err = filter.AddRuleConditional(callNum, actDeny, call.Conditions)
		} else {
			err = filter.AddRule(callNum, actDeny)
		}
		if err != nil {
			return fmt.Errorf("Error adding rule to filter for syscall %s: %s", call.Syscall, err)
		}
	}

	if err != nil {
		return fmt.Errorf("Error initializing filter: %s", err)
	}

	if err = filter.Load(); err != nil {
		return fmt.Errorf("Error loading seccomp filter into kernel: %s", err)
	}

	return nil
}
