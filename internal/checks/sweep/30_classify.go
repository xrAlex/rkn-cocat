package sweep

import (
	"fmt"
	"strings"
)

func (s *sizeSweepService) classifySweepStatus(rawStatus string, breakKB int) string {
	switch {
	case breakKB >= s.cfg.SweepMinKB && breakKB <= s.cfg.SweepMaxKB:
		return statusSweepBlock
	case breakKB > 0:
		return statusSweepOutside
	case rawStatus == statusSweepPass || rawStatus == statusSweepShort:
		return statusSweepPass
	case strings.Contains(rawStatus, statusDNSFail):
		return statusDNSFail
	case rawStatus == "":
		return statusSweepErr
	default:
		return rawStatus
	}
}

func formatSweepBreakText(breakKB int) string {
	if breakKB > 0 {
		return fmt.Sprintf("%dKB", breakKB)
	}
	return "—"
}
