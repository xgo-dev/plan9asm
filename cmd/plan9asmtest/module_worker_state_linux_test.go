//go:build linux

package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Independent kernel assertion, not the production membership parser. kill(0)
// also succeeds for zombies; they have exited even if PID1 has not reaped them.
func moduleWorkerKernelTerminal(pid int) (string, bool) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if os.IsNotExist(err) {
		return "process disappeared during its terminal observation", true
	}
	text := string(data)
	end := strings.LastIndex(text, ") ")
	if err != nil || !strings.HasPrefix(text, strconv.Itoa(pid)+" (") || end < 0 {
		return fmt.Sprint("unavailable kernel process identity: ", err), false
	}
	fields := strings.Fields(text[end+2:])
	if len(fields) < 20 {
		return "incomplete kernel process state", false
	}
	parent, parentErr := strconv.Atoi(fields[1])
	group, groupErr := strconv.Atoi(fields[2])
	born, bornErr := strconv.ParseUint(fields[19], 10, 64)
	evidence := fmt.Sprintf("PID=%d PPID=%d PGID=%d state=%s starttime=%d", pid, parent, group, fields[0], born)
	return evidence, parentErr == nil && parent > 0 && groupErr == nil && group > 1 && bornErr == nil && fields[0] == "Z"
}
