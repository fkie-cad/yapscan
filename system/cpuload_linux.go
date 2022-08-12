package system

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
)

var numCores int

func init() {
	numCores = runtime.NumCPU()
}

func cpuLoad() (oneMinuteAvg, fiveMinuteAvg, fifteenMinuteAvg float64) {
	f, err := os.Open("/proc/loadavg")
	if err != nil {
		logrus.WithError(err).Error("could not determine load average")
		return
	}
	text, err := io.ReadAll(f)
	if err != nil {
		logrus.WithError(err).Error("could not determine load average")
		return
	}
	parts := strings.Split(string(text), " ")
	if len(parts) < 3 {
		logrus.
			WithError(fmt.Errorf("expected at least 3 parts, got %d", len(parts))).
			Error("could not determine load average")
		return
	}

	avg1, err := strconv.ParseFloat(parts[0], 64)
	if err != nil {
		logrus.WithError(err).Error("could not determine load average")
		return
	}
	avg5, err := strconv.ParseFloat(parts[1], 64)
	if err != nil {
		logrus.WithError(err).Error("could not determine load average")
		return
	}
	avg15, err := strconv.ParseFloat(parts[2], 64)
	if err != nil {
		logrus.WithError(err).Error("could not determine load average")
		return
	}

	return avg1 / float64(numCores), avg5 / float64(numCores), avg15 / float64(numCores)
}
