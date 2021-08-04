package system

// #include<stdint.h>
// #include<windows.h>
// int myGetSystemTimes(int64_t* idleTime, int64_t* kernelTime, int64_t* userTime) {
//     FILETIME fIdle, fKernel, fUser;
//     int res = GetSystemTimes(&fIdle, &fKernel, &fUser);
//     *idleTime = ((int64_t)fIdle.dwHighDateTime << 32) | fIdle.dwLowDateTime;
//     *kernelTime = ((int64_t)fKernel.dwHighDateTime << 32) | fKernel.dwLowDateTime;
//     *userTime = ((int64_t)fUser.dwHighDateTime << 32) | fUser.dwLowDateTime;
//     return res;
// }
import "C"
import (
	"sync"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
)

func getSystemTimes() (idleTicks int64, kernelTicks int64, userTicks int64, err error) {
	// in ticks; one tick = 100 ns
	result := C.myGetSystemTimes((*C.int64_t)(&idleTicks), (*C.int64_t)(&kernelTicks), (*C.int64_t)(&userTicks))
	if result == 0 {
		err = syscall.GetLastError()
	}
	return
}

const fifteenMinutes = 15
const valuesPerMinute = 5 // 1 / 0.2 = 5

type cpuLoadTracker struct {
	mux             *sync.Mutex
	minuteAvgBuffer []float64
}

func newCpuLoadTracker() *cpuLoadTracker {
	return &cpuLoadTracker{
		mux:             new(sync.Mutex),
		minuteAvgBuffer: make([]float64, fifteenMinutes*valuesPerMinute),
	}
}

func (t *cpuLoadTracker) addValue(value float64) {
	t.mux.Lock()
	defer t.mux.Unlock()

	t.minuteAvgBuffer = append(t.minuteAvgBuffer[1:], value)
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
	lastIdleTicks, kernelTicks, userTicks, err := getSystemTimes()
	lastLoadTicks := kernelTicks + userTicks
	if err != nil {
		logrus.WithError(err).Error("could not query system load")
	}

	for range time.Tick(loadPollIntervalWindows) {
		idleTicks, kernelTicks, userTicks, err := getSystemTimes()
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
