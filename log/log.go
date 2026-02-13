package log

import (
	"context"
	"fmt"
	"os"
	"sync"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	sugar  *zap.SugaredLogger
	level  zap.AtomicLevel
	once   sync.Once
	inited bool
)

func init() {
	once.Do(func() {
		level = zap.NewAtomicLevelAt(zapcore.DebugLevel)
		// Note: Logger is not initialized here (lazy initialization)
		// It will be created on first use via sugar
	})
}

func initLogger() {
	if sugar != nil {
		return
	}

	consoleEncoder := zapcore.NewConsoleEncoder(zapcore.EncoderConfig{
		LevelKey:       "level",
		NameKey:        "logger",
		MessageKey:     "msg",
		TimeKey:        "time",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.CapitalColorLevelEncoder,
		EncodeTime:     zapcore.TimeEncoderOfLayout("2006-01-02 15:04:05"),
		EncodeDuration: zapcore.SecondsDurationEncoder,
	})

	core := zapcore.NewCore(
		consoleEncoder,
		zapcore.Lock(os.Stderr),
		level,
	)

	sugar = zap.New(core).Sugar()
}

// SetLevel sets the minimum log level (debug, info, warn, error, fatal, panic)
// SetLevel sets minimum log level (debug, info, warn, error, fatal, panic)
// Returns an error if the level is invalid
func SetLevel(l string) error {
	switch l {
	case "debug":
		level.SetLevel(zapcore.DebugLevel)
	case "info":
		level.SetLevel(zapcore.InfoLevel)
	case "warn":
		level.SetLevel(zapcore.WarnLevel)
	case "error":
		level.SetLevel(zapcore.ErrorLevel)
	case "fatal":
		level.SetLevel(zapcore.FatalLevel)
	case "panic":
		level.SetLevel(zapcore.PanicLevel)
	default:
		return fmt.Errorf("invalid log level: %s", l)
	}
	return nil
}

func Info(args ...any)                       { initLogger(); sugar.Info(args...) }
func Infoln(args ...any)                     { initLogger(); sugar.Infoln(args...) }
func Infof(format string, args ...any)       { initLogger(); sugar.Infof(format, args...) }
func Infow(msg string, keysAndValues ...any) { sugar.Infow(msg, keysAndValues...) }

func Debug(args ...any)                       { initLogger(); sugar.Debug(args...) }
func Debugln(args ...any)                     { initLogger(); sugar.Debugln(args...) }
func Debugf(format string, args ...any)       { initLogger(); sugar.Debugf(format, args...) }
func Debugw(msg string, keysAndValues ...any) { sugar.Debugw(msg, keysAndValues...) }

func Warn(args ...any)                       { initLogger(); sugar.Warn(args...) }
func Warnln(args ...any)                     { initLogger(); sugar.Warnln(args...) }
func Warnf(format string, args ...any)       { initLogger(); sugar.Warnf(format, args...) }
func Warnw(msg string, keysAndValues ...any) { sugar.Warnw(msg, keysAndValues...) }

func Error(args ...any)                       { initLogger(); sugar.Error(args...) }
func Errorln(args ...any)                     { initLogger(); sugar.Errorln(args...) }
func Errorf(format string, args ...any)       { initLogger(); sugar.Errorf(format, args...) }
func Errorw(msg string, keysAndValues ...any) { sugar.Errorw(msg, keysAndValues...) }

func Fatal(args ...any)                       { initLogger(); sugar.Fatal(args...) }
func Fatalln(args ...any)                     { initLogger(); sugar.Fatalln(args...) }
func Fatalf(format string, args ...any)       { initLogger(); sugar.Fatalf(format, args...) }
func Fatalw(msg string, keysAndValues ...any) { sugar.Fatalw(msg, keysAndValues...) }

func Panic(args ...any)                       { initLogger(); sugar.Panic(args...) }
func Panicln(args ...any)                     { initLogger(); sugar.Panicln(args...) }
func Panicf(format string, args ...any)       { initLogger(); sugar.Panicf(format, args...) }
func Panicw(msg string, keysAndValues ...any) { sugar.Panicw(msg, keysAndValues...) }

// Sync flushes the log buffer and returns any error
func Sync() error {
	if sugar != nil {
		return sugar.Sync()
	}
	return nil
}

// ContextLogger provides context-aware logging with request tracing
type ContextLogger struct {
	*zap.SugaredLogger
	ctx context.Context
}

// WithContext creates a new logger with context for request tracing
// The context can contain trace_id, span_id, or other debugging information
func WithContext(ctx context.Context) *ContextLogger {
	return &ContextLogger{
		SugaredLogger: sugar,
		ctx:           ctx,
	}
}

// With wraps logging with context fields
func (l *ContextLogger) With(args ...any) *ContextLogger {
	return &ContextLogger{
		SugaredLogger: l.SugaredLogger.With(args...),
		ctx:           l.ctx,
	}
}

// ErrorWithOp logs an error with operation context
func (l *ContextLogger) ErrorWithOp(op string, err error) {
	initLogger()
	l.SugaredLogger.Errorw("operation failed",
		"operation", op,
		"error", err,
		"trace_id", l.ctx.Value("trace_id"),
	)
}

// InfoWithKey logs info with a specific key
func (l *ContextLogger) InfoWithKey(key string, value any) {
	l.SugaredLogger.Infow("info", key, value, "trace_id", l.ctx.Value("trace_id"))
}
