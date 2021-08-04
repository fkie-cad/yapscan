package system

import "time"

const loadPollIntervalWindows = 200 * time.Millisecond

// MaxCPULoadResolution is the maximum guaranteed temporal resolution of the CPU load average.
// Calling CPULoad more often than MaxCPULoadResolution may yield duplicate results.
const MaxCPULoadResolution = loadPollIntervalWindows

// CPULoad retrieves the normalized 1-, 5-, and 15-minute averages of the CPU load percentage.
func CPULoad() (oneMinuteAvg, fiveMinuteAvg, fifteenMinuteAvg float64) {
	return cpuLoad()
}
