//go:build windows

package daemon

import (
	"os"
	"os/exec"
)

// setSysProcAttr is a no-op on Windows (Setsid not available).
func setSysProcAttr(_ *exec.Cmd) {}

// signalProcess sends a signal to a process.
func signalProcess(process *os.Process, sig os.Signal) error {
	return process.Signal(sig)
}

// termSignal returns the signal used for graceful shutdown.
// On Windows, os.Kill is the only reliable signal.
func termSignal() os.Signal {
	return os.Kill
}

// checkAlive returns the signal used to probe whether a process is alive.
// On Windows, Signal(0) is not supported, so we use os.FindProcess behavior.
func checkAlive() os.Signal {
	return os.Kill
}
