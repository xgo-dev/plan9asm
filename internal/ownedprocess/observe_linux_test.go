//go:build linux

package ownedprocess

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func procStatFixture(pid, pgid int, state string, born uint64) []byte {
	fields := strings.Fields(state + " 100 " + strconv.Itoa(pgid) + strings.Repeat(" 0", 16) + " " + strconv.FormatUint(born, 10))
	return []byte(fmt.Sprintf("%d (name with ) and spaces) %s\n", pid, strings.Join(fields, " ")))
}

func TestLinuxProcStatIdentityAndStates(t *testing.T) {
	for _, state := range []string{"R", "S", "D", "T", "t", "Z", "I", "X"} {
		member, err := decodeProcStat(procStatFixture(4124, 4123, state, 1007))
		want := groupMember{PID: 4124, PGID: 4123, State: state, Born: 1007}
		if err != nil || member != want {
			t.Fatal("actual proc field indices or parenthesized command changed", member, err)
		}
	}
	for name, data := range map[string][]byte{
		"truncated":          []byte("4124 (x) Z 100 4123"),
		"unknown state":      procStatFixture(4124, 4123, "?", 1007),
		"Darwin-only state":  procStatFixture(4124, 4123, "U", 1007),
		"state modifier":     procStatFixture(4124, 4123, "Z+", 1007),
		"negative pid":       procStatFixture(-1, 4123, "Z", 1007),
		"negative group":     procStatFixture(4124, -1, "Z", 1007),
		"missing command":    []byte("4124 Z 100 4123"),
		"starttime overflow": []byte(strings.Replace(string(procStatFixture(4124, 4123, "Z", 1007)), "1007", "18446744073709551616", 1)),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeProcStat(data); err == nil {
				t.Fatal("unknown or incomplete kernel identity accepted")
			}
		})
	}
}

func TestLinuxProcMembershipRequiresCompleteVisibleView(t *testing.T) {
	for _, mutation := range []string{"none", "hidden", "wrong filesystem", "missing mount", "missing process", "wrong pid", "unknown state", "absent"} {
		t.Run(mutation, func(t *testing.T) {
			root := t.TempDir()
			for _, pid := range []int{100, 4124} {
				if err := os.Mkdir(filepath.Join(root, strconv.Itoa(pid)), 0700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Symlink("100", filepath.Join(root, "self")); err != nil {
				t.Fatal(err)
			}
			write := func(name string, data []byte) {
				if err := os.WriteFile(filepath.Join(root, name), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			write("100/stat", procStatFixture(100, 99, "S", 1000))
			write("4124/stat", procStatFixture(4124, 4123, "Z", 1007))
			mount := fmt.Sprintf("20 1 0:5 / %s rw - proc proc rw\n", root)
			switch mutation {
			case "hidden":
				mount = strings.TrimSuffix(mount, "\n") + ",hidepid=2\n"
			case "wrong filesystem":
				mount = strings.Replace(mount, "- proc", "- tmpfs", 1)
			case "missing mount":
				mount = ""
			case "missing process", "absent":
				if err := os.Remove(filepath.Join(root, "4124/stat")); err != nil {
					t.Fatal(err)
				}
			case "wrong pid":
				write("4124/stat", procStatFixture(4125, 4123, "Z", 1007))
			case "unknown state":
				write("4124/stat", procStatFixture(4124, 4123, "?", 1007))
			}
			write("100/mountinfo", []byte(mount))
			members, err := observeProcProcessGroup(root, 4123, 100, func(pid int, signal syscall.Signal) error {
				if pid != -4123 || signal != 0 {
					t.Fatal("observation signalled an unowned process", pid, signal)
				}
				if mutation == "absent" {
					return syscall.ESRCH
				}
				return nil
			})
			if mutation == "none" {
				if err != nil || !reflect.DeepEqual(members, []groupMember{{PID: 4124, PGID: 4123, State: "Z", Born: 1007}}) {
					t.Fatal("complete membership changed", members, err)
				}
			} else if mutation == "absent" {
				if err != nil || len(members) != 0 {
					t.Fatal("independent kernel absence rejected", members, err)
				}
			} else if err == nil || members != nil {
				t.Fatal("partial, hidden or foreign process view acquired terminal membership", members, err)
			}
		})
	}
}
