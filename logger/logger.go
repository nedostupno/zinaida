package logger

import (
	"io"
	"net/http"
	"os"

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

func (l *Logger) WithErrorFields(r *http.Request, err error) *logrus.Entry {
	return l.WithFields(logrus.Fields{
		"Method":     r.Method,
		"Proto":      r.Proto,
		"RemoteAddr": r.RemoteAddr,
		"RequestURI": r.RequestURI,
		"UserAgent":  r.UserAgent(),
		"Referer":    r.Referer(),
		"Error":      err,
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

	return &Logger{log}
}
