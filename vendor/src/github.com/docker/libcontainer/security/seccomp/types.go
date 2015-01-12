package seccomp

import (
	libseccomp "github.com/mheon/golang-seccomp"
)

type BlockedSyscall struct {
	Syscall     string `json:"syscall,omitempty"`
	Conditional bool `json:"conditional,omitempty"`
	Conditions  []libseccomp.ScmpCondition `json:"conditions,omitempty"`
}

func MakeBlockedSyscall(name string) BlockedSyscall {
	var blockedCall BlockedSyscall
	blockedCall.Syscall = name
	blockedCall.Conditional = false
	blockedCall.Conditions = nil

	return blockedCall
}

func MakeConditionallyBlockedSyscall(name string, conditions []libseccomp.ScmpCondition) BlockedSyscall {
	var blockedCall BlockedSyscall
	blockedCall.Syscall = name
	blockedCall.Conditional = true
	blockedCall.Conditions = conditions

	return blockedCall
}
