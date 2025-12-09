package logger

import (
	"io"
	"os"
	"time"

	"github.com/rs/zerolog"
)

var log zerolog.Logger

// Init initializes the global logger
func Init(level string, logFile string) error {
	// Parse log level
	lvl, err := zerolog.ParseLevel(level)
	if err != nil {
		lvl = zerolog.InfoLevel
	}

	// Determine output writers
	var writers []io.Writer

	// Always write to stderr (not stdout, as stdout is for hook output)
	consoleWriter := zerolog.ConsoleWriter{
		Out:        os.Stderr,
		TimeFormat: time.RFC3339,
		NoColor:    false,
	}
	writers = append(writers, consoleWriter)

	// Optionally write to file
	if logFile != "" {
		file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return err
		}
		writers = append(writers, file)
	}

	// Create multi-writer
	multi := zerolog.MultiLevelWriter(writers...)

	log = zerolog.New(multi).
		Level(lvl).
		With().
		Timestamp().
		Logger()

	return nil
}

// InitQuiet initializes the logger in quiet mode (discard all output)
func InitQuiet() {
	log = zerolog.New(io.Discard)
}

// Debug logs a debug message
func Debug() *zerolog.Event {
	return log.Debug()
}

// Info logs an info message
func Info() *zerolog.Event {
	return log.Info()
}

// Warn logs a warning message
func Warn() *zerolog.Event {
	return log.Warn()
}

// Error logs an error message
func Error() *zerolog.Event {
	return log.Error()
}

// Fatal logs a fatal message and exits
func Fatal() *zerolog.Event {
	return log.Fatal()
}

// WithField returns a logger with a field attached
func WithField(key string, value interface{}) zerolog.Logger {
	return log.With().Interface(key, value).Logger()
}
