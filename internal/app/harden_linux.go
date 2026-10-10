//go:build linux

package app

import (
	"syscall"
)

// Harden stops the process from being a source of key material: no core dump, no ptrace or
// /proc/PID/mem read by other processes of the same user (PR_SET_DUMPABLE=0), and the secrets
// never reach swap-visible argv or logs. Best effort: failures are ignored.
func Harden() {
	syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: 0, Max: 0})
	const prSetDumpable = 4
	syscall.RawSyscall(syscall.SYS_PRCTL, prSetDumpable, 0, 0)
}
