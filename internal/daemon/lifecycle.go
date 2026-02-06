package daemon

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/ihavespoons/hooksy/internal/config"
)

// Lifecycle manages the daemon's lifecycle (start, stop, health checks)
type Lifecycle struct {
	settings config.DaemonSettings
	pidFile  string
}

// NewLifecycle creates a new lifecycle manager
func NewLifecycle(settings config.DaemonSettings) *Lifecycle {
	homeDir, _ := os.UserHomeDir()
	pidFile := filepath.Join(homeDir, ".hooksy", "daemon.pid")

	return &Lifecycle{
		settings: settings,
		pidFile:  pidFile,
	}
}

// PIDFile returns the path to the PID file
func (l *Lifecycle) PIDFile() string {
	return l.pidFile
}

// IsRunning checks if the daemon is running
func (l *Lifecycle) IsRunning() bool {
	pid, err := l.readPID()
	if err != nil {
		return false
	}

	// Check if process exists
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}

	// On Unix, FindProcess always succeeds, so we need to send signal 0 to check
	err = process.Signal(syscall.Signal(0))
	if err != nil {
		// Process doesn't exist, clean up stale PID file
		_ = os.Remove(l.pidFile)
		return false
	}

	// Also verify the health endpoint responds
	return l.healthCheck()
}

// GetPID returns the daemon's PID if running
func (l *Lifecycle) GetPID() (int, error) {
	if !l.IsRunning() {
		return 0, fmt.Errorf("daemon is not running")
	}
	return l.readPID()
}

// StartInBackground starts the daemon in the background
func (l *Lifecycle) StartInBackground() error {
	if l.IsRunning() {
		return fmt.Errorf("daemon is already running")
	}

	// Find the hooksy executable
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to find executable: %w", err)
	}

	// Start the daemon as a background process
	cmd := exec.Command(executable, "daemon", "start", "--background-child")
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.Stdin = nil

	// Detach from parent process
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true,
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start daemon: %w", err)
	}

	// Wait briefly for the daemon to start
	time.Sleep(500 * time.Millisecond)

	// Verify it started
	if !l.IsRunning() {
		return fmt.Errorf("daemon failed to start")
	}

	return nil
}

// Stop stops the running daemon
func (l *Lifecycle) Stop() error {
	pid, err := l.readPID()
	if err != nil {
		return fmt.Errorf("daemon is not running: %w", err)
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("failed to find process: %w", err)
	}

	// Send SIGTERM for graceful shutdown
	if err := process.Signal(syscall.SIGTERM); err != nil {
		return fmt.Errorf("failed to stop daemon: %w", err)
	}

	// Wait for process to exit (with timeout)
	for range 30 {
		time.Sleep(100 * time.Millisecond)
		if err := process.Signal(syscall.Signal(0)); err != nil {
			// Process has exited
			_ = os.Remove(l.pidFile)
			return nil
		}
	}

	// Force kill if still running
	_ = process.Kill()
	_ = os.Remove(l.pidFile)
	return nil
}

// WritePID writes the current process PID to the PID file
func (l *Lifecycle) WritePID() error {
	// Ensure directory exists
	dir := filepath.Dir(l.pidFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	pid := os.Getpid()
	return os.WriteFile(l.pidFile, []byte(strconv.Itoa(pid)), 0644)
}

// RemovePID removes the PID file
func (l *Lifecycle) RemovePID() error {
	return os.Remove(l.pidFile)
}

func (l *Lifecycle) readPID() (int, error) {
	data, err := os.ReadFile(l.pidFile)
	if err != nil {
		return 0, err
	}

	pid, err := strconv.Atoi(string(data))
	if err != nil {
		return 0, fmt.Errorf("invalid PID file content: %w", err)
	}

	return pid, nil
}

func (l *Lifecycle) healthCheck() bool {
	url := fmt.Sprintf("http://127.0.0.1:%d/health", l.settings.Port)
	client := &http.Client{
		Timeout: 2 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()

	return resp.StatusCode == http.StatusOK
}

// Port returns the configured port
func (l *Lifecycle) Port() int {
	return l.settings.Port
}
