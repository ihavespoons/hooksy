//go:build !windows

package daemon

import (
	"os"
	"os/exec"
	"syscall"
)

// setSysProcAttr detaches the child process from the parent session.
func setSysProcAttr(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true,
	}
}

// signalProcess sends a signal to a process. Signal 0 checks if alive.
func signalProcess(process *os.Process, sig os.Signal) error {
	return process.Signal(sig)
}

// termSignal returns the signal used for graceful shutdown.
func termSignal() os.Signal {
	return syscall.SIGTERM
}

// checkAlive returns the signal used to probe whether a process is alive.
func checkAlive() os.Signal {
	return syscall.Signal(0)
}
