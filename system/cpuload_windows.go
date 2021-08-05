package system

import (
	"sync"
	"time"

	"github.com/fkie-cad/yapscan/win32"

	"github.com/sirupsen/logrus"
)

const fifteenMinutes = 15
const valuesPerMinute = 5 // 1 / 0.2 = 5

type cpuLoadTracker struct {
	mux               *sync.Mutex
	minuteAvgBuffer   []float64
	bufferInitialized bool
}

func newCpuLoadTracker() *cpuLoadTracker {
	return &cpuLoadTracker{
		mux:               new(sync.Mutex),
		minuteAvgBuffer:   make([]float64, fifteenMinutes*valuesPerMinute),
		bufferInitialized: false,
	}
}

func (t *cpuLoadTracker) addValue(value float64) {
	t.mux.Lock()
	defer t.mux.Unlock()

	if t.bufferInitialized {
		t.minuteAvgBuffer = append(t.minuteAvgBuffer[1:], value)
	} else {
		for i := range t.minuteAvgBuffer {
			t.minuteAvgBuffer[i] = value
		}
		t.bufferInitialized = true
	}
}

func (t *cpuLoadTracker) average(numValues int) float64 {
	t.mux.Lock()
	defer t.mux.Unlock()

	last := len(t.minuteAvgBuffer) - 1

	var sum float64
	for i := 0; i < numValues; i++ {
		sum += t.minuteAvgBuffer[last-i]
	}

	return sum / float64(numValues)
}

func (t *cpuLoadTracker) oneMinuteAvg() float64 {
	return t.average(valuesPerMinute)
}

func (t *cpuLoadTracker) fiveMinutesAvg() float64 {
	return t.average(valuesPerMinute * 5)
}

func (t *cpuLoadTracker) fifteenMinutesAvg() float64 {
	return t.average(valuesPerMinute * 15)
}

func (t *cpuLoadTracker) track() {
	// This function will never stop, sorry mom
	lastIdleTicks, kernelTicks, userTicks, err := win32.GetSystemTimes()
	lastLoadTicks := kernelTicks + userTicks
	if err != nil {
		logrus.WithError(err).Error("could not query system load")
	}

	for range time.Tick(loadPollIntervalWindows) {
		idleTicks, kernelTicks, userTicks, err := win32.GetSystemTimes()
		if err != nil {
			logrus.WithError(err).Error("could not query system load")
			continue
		}
		loadTicks := kernelTicks + userTicks

		idleDelta := lastIdleTicks - idleTicks
		loadDelta := lastLoadTicks - kernelTicks - userTicks
		totalDelta := idleDelta + loadDelta
		loadPercentInLastInterval := float64(loadDelta) / float64(totalDelta)

		// There can be some drift when computing averages if the ticker is not precise.
		// This should be fine for our purposes though.
		t.addValue(loadPercentInLastInterval)

		lastIdleTicks, lastLoadTicks = idleTicks, loadTicks
	}
}

var loadTracker *cpuLoadTracker

func init() {
	loadTracker = newCpuLoadTracker()
	go loadTracker.track()
}

func cpuLoad() (oneMinuteAvg, fiveMinuteAvg, fifteenMinuteAvg float64) {
	return loadTracker.oneMinuteAvg(), loadTracker.fiveMinutesAvg(), loadTracker.fifteenMinutesAvg()
}
