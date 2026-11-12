//go:build darwin

package ownedprocess

import (
	"encoding/binary"
	"fmt"
	"os"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Query only kernel BSD process records, without spawning ps or performing
// Mach task/thread queries. Both selectors include no-TTY processes and
// zombies. Unlike SysctlKinfoProcSlice, SysctlRaw does not retry ENOMEM in an
// unbounded loop when a process group grows between its size/read calls.
func observeProcessGroup(pgid int) ([]groupMember, error) {
	return observeKernelProcessGroup(pgid, os.Getpid(), unix.SysctlRaw)
}

type kernelProcessQuery func(string, ...int) ([]byte, error)

const membershipOutputLimit = 1 << 20

func observeKernelProcessGroup(pgid, callerPID int, query kernelProcessQuery) ([]groupMember, error) {
	if pgid <= 1 || callerPID <= 1 || query == nil {
		return nil, fmt.Errorf("invalid Darwin kernel membership request")
	}
	started := time.Now()
	read := func(name string, identity int) ([]groupMember, error) {
		data, err := query(name, identity)
		if err != nil {
			return nil, fmt.Errorf("Darwin kernel membership query: %w", err)
		}
		if time.Since(started) > 1500*time.Millisecond {
			return nil, fmt.Errorf("Darwin kernel membership observation exceeded its budget")
		}
		return decodeKernelProcessRecords(data)
	}
	caller, err := read("kern.proc.pid", callerPID)
	if err != nil {
		return nil, err
	}
	if len(caller) != 1 || caller[0].PID != callerPID || caller[0].State == "Z" {
		return nil, fmt.Errorf("Darwin kernel membership lacks its live observer")
	}
	members, err := read("kern.proc.pgrp", pgid)
	if err != nil {
		return nil, err
	}
	for _, member := range members {
		if member.PGID != pgid {
			return nil, fmt.Errorf("Darwin kernel membership contains an unselected process")
		}
	}
	after, err := read("kern.proc.pid", callerPID)
	if err != nil {
		return nil, err
	}
	// The observer is this live Go process, not a reused receipt PID. Its
	// identity/group must remain stable; runnable and sleeping are both live.
	if len(after) != 1 || after[0].PID != callerPID || after[0].PGID != caller[0].PGID || after[0].State == "Z" {
		return nil, fmt.Errorf("Darwin kernel membership observer changed")
	}
	return members, nil
}

func decodeKernelProcessRecords(data []byte) ([]groupMember, error) {
	// Use the target's generated x/sys ABI layout for field offsets; never
	// copy kernel pointer fields into Go objects or dereference them. Both
	// supported Darwin targets (amd64/arm64) have little-endian integer fields.
	var layout unix.KinfoProc
	const recordSize = unix.SizeofKinfoProc
	if unsafe.Sizeof(layout) != recordSize || len(data) > membershipOutputLimit || len(data)%recordSize != 0 {
		return nil, fmt.Errorf("Darwin kernel membership has an invalid size")
	}
	pidOffset := int(unsafe.Offsetof(layout.Proc) + unsafe.Offsetof(layout.Proc.P_pid))
	groupOffset := int(unsafe.Offsetof(layout.Eproc) + unsafe.Offsetof(layout.Eproc.Pgid))
	stateOffset := int(unsafe.Offsetof(layout.Proc) + unsafe.Offsetof(layout.Proc.P_stat))
	seen := make(map[int]bool, len(data)/recordSize)
	var members []groupMember
	for offset := 0; offset < len(data); offset += recordSize {
		record := data[offset : offset+recordSize]
		pid := int(int32(binary.LittleEndian.Uint32(record[pidOffset : pidOffset+4])))
		pgid := int(int32(binary.LittleEndian.Uint32(record[groupOffset : groupOffset+4])))
		// sys/proc.h: SIDL=1, SRUN=2, SSLEEP=3, SSTOP=4, SZOMB=5.
		state := record[stateOffset]
		if pid <= 1 || pgid <= 0 || seen[pid] || state < 1 || state > 5 {
			return nil, fmt.Errorf("Darwin kernel membership has an unknown record")
		}
		seen[pid] = true
		members = append(members, groupMember{PID: pid, PGID: pgid, State: string("IRSTZ"[state-1])})
	}
	return members, nil
}
