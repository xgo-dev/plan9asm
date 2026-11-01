//go:build linux

package ownedprocess

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var observeProcessGroup groupObserver = func(pgid int) ([]groupMember, error) {
	return observeProcProcessGroup("/proc", pgid, os.Getpid(), syscall.Kill)
}

func observeProcProcessGroup(root string, pgid, callerPID int, probe func(int, syscall.Signal) error) ([]groupMember, error) {
	if pgid <= 1 || callerPID <= 0 || probe == nil {
		return nil, fmt.Errorf("invalid Linux process membership request")
	}
	if err := requireVisibleProcMount(root); err != nil {
		return nil, err
	}
	started := time.Now()
	read := func(name string) (groupMember, error) {
		data, err := os.ReadFile(filepath.Join(root, name, "stat"))
		if err != nil {
			return groupMember{}, err
		}
		if time.Since(started) > 1500*time.Millisecond {
			return groupMember{}, fmt.Errorf("Linux process membership exceeded its budget")
		}
		return decodeProcStat(data)
	}
	caller, err := read("self")
	if err != nil || caller.PID != callerPID || caller.State == "Z" {
		return nil, errors.Join(fmt.Errorf("Linux process membership lacks its live observer"), err)
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) > 65536 {
		return nil, errors.Join(fmt.Errorf("Linux process membership directory is unavailable or oversized"), err)
	}
	var members []groupMember
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		member, err := read(entry.Name())
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ESRCH) {
			continue // A process removed during enumeration is already gone.
		}
		if err != nil || member.PID != pid {
			return nil, errors.Join(fmt.Errorf("Linux process membership is incomplete"), err)
		}
		if member.PGID == pgid {
			members = append(members, member)
		}
	}
	after, err := read("self")
	if err != nil || after.PID != caller.PID || after.PGID != caller.PGID || after.Born != caller.Born || after.State == "Z" {
		return nil, errors.Join(fmt.Errorf("Linux process membership observer changed"), err)
	}
	if len(members) == 0 {
		if err := probe(-pgid, 0); !errors.Is(err, syscall.ESRCH) {
			return nil, errors.Join(fmt.Errorf("empty Linux membership did not establish an absent group"), err)
		}
	}
	return members, nil
}

func requireVisibleProcMount(root string) error {
	data, err := os.ReadFile(filepath.Join(root, "self", "mountinfo"))
	if err != nil || len(data) > 1<<20 {
		return errors.Join(fmt.Errorf("Linux process mount visibility is unknown"), err)
	}
	found := 0
	for _, line := range strings.Split(string(data), "\n") {
		before, after, present := strings.Cut(line, " - ")
		fields, filesystem := strings.Fields(before), strings.Fields(after)
		if !present || len(fields) < 6 || fields[4] != root {
			continue
		}
		if len(filesystem) != 3 || filesystem[0] != "proc" {
			return fmt.Errorf("Linux process view is not procfs")
		}
		for _, option := range strings.Split(fields[5]+","+filesystem[2], ",") {
			if strings.HasPrefix(option, "hidepid=") && option != "hidepid=0" && option != "hidepid=off" {
				return fmt.Errorf("Linux process view hides group members")
			}
		}
		found++
	}
	if found != 1 {
		return fmt.Errorf("Linux process view lacks one complete procfs mount")
	}
	return nil
}

func decodeProcStat(data []byte) (groupMember, error) {
	// proc_pid_stat(5): comm is parenthesized and may itself contain spaces
	// or ')'. State, pgrp and starttime are fields 3, 5 and 22 respectively.
	text := string(data)
	open, close := strings.Index(text, " ("), strings.LastIndex(text, ") ")
	if len(data) > 65536 || open < 1 || close <= open {
		return groupMember{}, fmt.Errorf("invalid Linux stat record")
	}
	pid, pidErr := strconv.Atoi(text[:open])
	fields := strings.Fields(text[close+2:])
	if pidErr != nil || pid <= 0 || len(fields) < 20 || len(fields[0]) != 1 || !strings.Contains("RSDTtXZxKWPI", fields[0]) {
		return groupMember{}, fmt.Errorf("invalid Linux stat identity or state")
	}
	pgid, groupErr := strconv.Atoi(fields[2])
	born, bornErr := strconv.ParseUint(fields[19], 10, 64)
	if groupErr != nil || pgid < 0 || bornErr != nil {
		return groupMember{}, fmt.Errorf("invalid Linux stat group or lifetime")
	}
	return groupMember{PID: pid, PGID: pgid, State: fields[0], Born: born}, nil
}
