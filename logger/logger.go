package logger

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"

	"github.com/sirupsen/logrus"
)

type writerHook struct {
	Writer    []io.Writer
	LogLevels []logrus.Level
}

func (hook *writerHook) Fire(entry *logrus.Entry) error {
	line, err := entry.String()
	if err != nil {
		return err
	}
	for _, w := range hook.Writer {
		_, err = w.Write([]byte(line))
	}
	return err
}

func (hook *writerHook) Levels() []logrus.Level {
	return hook.LogLevels
}

type Logger struct {
	*logrus.Logger
}

func (l *Logger) WithRestApiErrorFields(r *http.Request, err error) *logrus.Entry {
	// Получаем фрейм функции из которой был произведен вызов метода WithRestApiErrorFields
	// Для того, чтобы получить нужный нам фрейм, необходимо пропустить два первых фрейма,
	// Это связано с тем, что первый фрейм это вызов runtime.Callers,
	// А второй фрейм принадлежит вызову logger.WithRestApiErrorFields
	pc := make([]uintptr, 15)
	n := runtime.Callers(2, pc)
	frames := runtime.CallersFrames(pc[:n])
	frame, _ := frames.Next()

	return l.WithFields(logrus.Fields{
		"Method":     r.Method,
		"Proto":      r.Proto,
		"RemoteAddr": r.RemoteAddr,
		"RequestURI": r.RequestURI,
		"UserAgent":  r.UserAgent(),
		"Referer":    r.Referer(),
		"file":       fmt.Sprintf("%s:%d", frame.File, frame.Line),
		"func":       frame.Function,
		"Error":      err,
	})
}

func (l *Logger) WhithErrorFields(err error) *logrus.Entry {
	pc := make([]uintptr, 15)
	n := runtime.Callers(2, pc)
	frames := runtime.CallersFrames(pc[:n])
	frame, _ := frames.Next()

	return l.WithFields(logrus.Fields{
		"file":  fmt.Sprintf("%s:%d", frame.File, frame.Line),
		"func":  frame.Function,
		"Error": err,
	})
}

func GetLogger() *Logger {
	log := logrus.New()

	log.SetFormatter(&logrus.JSONFormatter{})

	// Уровень логирования нужно будет в будущем получать из конфига
	log.SetLevel(logrus.InfoLevel)

	if _, err := os.Stat("logs"); os.IsNotExist(err) {
		err = os.MkdirAll("logs", 0755)
		if err != nil {
			log.Fatal(err)
		}
	}

	accessFile, err := os.OpenFile("logs/access.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0660)
	if err != nil {
		log.Fatal("Failed to open log file: ", err)
	}

	errorFile, err := os.OpenFile("logs/error.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0660)
	if err != nil {
		log.Fatal("Failed to open log file: ", err)
	}

	log.SetOutput(io.Discard)

	log.AddHook(&writerHook{
		Writer:    []io.Writer{accessFile},
		LogLevels: []logrus.Level{logrus.InfoLevel},
	})

	log.AddHook(&writerHook{
		Writer:    []io.Writer{errorFile},
		LogLevels: []logrus.Level{logrus.WarnLevel, logrus.ErrorLevel, logrus.FatalLevel},
	})

	log.AddHook(&writerHook{
		Writer:    []io.Writer{os.Stdout},
		LogLevels: []logrus.Level{logrus.FatalLevel, logrus.DebugLevel},
	})

	return &Logger{log}
}
