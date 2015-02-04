// +build !linux !cgo !seccomp

package seccomp

func InitSeccomp(blockedCalls []BlockedSyscall) error {
	return nil
}
