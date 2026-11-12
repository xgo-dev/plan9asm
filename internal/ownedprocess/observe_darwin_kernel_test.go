//go:build darwin

package ownedprocess

import (
	"encoding/binary"
	"errors"
	"reflect"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func kernelRecordFixture(pid, pgid int32, state byte) []byte {
	var layout unix.KinfoProc
	data := make([]byte, unix.SizeofKinfoProc)
	pidOffset := int(unsafe.Offsetof(layout.Proc) + unsafe.Offsetof(layout.Proc.P_pid))
	groupOffset := int(unsafe.Offsetof(layout.Eproc) + unsafe.Offsetof(layout.Eproc.Pgid))
	stateOffset := int(unsafe.Offsetof(layout.Proc) + unsafe.Offsetof(layout.Proc.P_stat))
	binary.LittleEndian.PutUint32(data[pidOffset:pidOffset+4], uint32(pid))
	binary.LittleEndian.PutUint32(data[groupOffset:groupOffset+4], uint32(pgid))
	data[stateOffset] = state
	return data
}

func TestDarwinKernelMembershipRecordStates(t *testing.T) {
	for state, want := range map[byte]string{1: "I", 2: "R", 3: "S", 4: "T", 5: "Z"} {
		members, err := decodeKernelProcessRecords(kernelRecordFixture(4124, 4123, state))
		if err != nil || !reflect.DeepEqual(members, []groupMember{{PID: 4124, PGID: 4123, State: want}}) {
			t.Fatalf("kernel state %d: %v %v", state, members, err)
		}
	}
	for name, data := range map[string][]byte{
		"truncated":      make([]byte, unix.SizeofKinfoProc-1),
		"extra byte":     make([]byte, unix.SizeofKinfoProc+1),
		"oversized":      make([]byte, membershipOutputLimit+1),
		"zero PID":       kernelRecordFixture(0, 4123, 5),
		"init PID":       kernelRecordFixture(1, 4123, 5),
		"negative PID":   kernelRecordFixture(-1, 4123, 5),
		"zero group":     kernelRecordFixture(4124, 0, 5),
		"negative group": kernelRecordFixture(4124, -1, 5),
		"unknown state":  kernelRecordFixture(4124, 4123, 0),
		"future state":   kernelRecordFixture(4124, 4123, 6),
		"duplicate PID":  append(kernelRecordFixture(4124, 4123, 5), kernelRecordFixture(4124, 4123, 5)...),
	} {
		t.Run(name, func(t *testing.T) {
			members, err := decodeKernelProcessRecords(data)
			if err == nil || members != nil {
				t.Fatalf("unknown/partial kernel records accepted: %v %v", members, err)
			}
		})
	}
}

func TestDarwinKernelMembershipExactSelectorsAndLiveWitness(t *testing.T) {
	for _, absent := range []bool{false, true} {
		calls := 0
		query := func(name string, args ...int) ([]byte, error) {
			calls++
			identity := 100
			want := "kern.proc.pid"
			if calls == 2 {
				identity, want = 4123, "kern.proc.pgrp"
			}
			if name != want || !reflect.DeepEqual(args, []int{identity}) || calls > 3 {
				t.Fatalf("broad/retried kernel query: %s %v (call %d)", name, args, calls)
			}
			if calls != 2 {
				return kernelRecordFixture(100, 99, 3), nil
			}
			if absent {
				return nil, nil
			}
			return kernelRecordFixture(4124, 4123, 5), nil
		}
		members, err := observeKernelProcessGroup(4123, 100, query)
		if err != nil || calls != 3 || absent && len(members) != 0 || !absent && len(members) != 1 {
			t.Fatalf("exact independent kernel observation: %v %v calls=%d absent=%v", members, err, calls, absent)
		}
	}
}

func TestDarwinKernelMembershipRejectsQueryAndWitnessFailures(t *testing.T) {
	for name, replace := range map[string]struct {
		stage int
		data  []byte
		err   error
	}{
		"query failure":        {1, nil, unix.EPERM},
		"group grew":           {2, nil, unix.ENOMEM},
		"after query failure":  {3, nil, unix.EIO},
		"missing caller":       {1, nil, nil},
		"zombie caller":        {1, kernelRecordFixture(100, 99, 5), nil},
		"wrong caller":         {1, kernelRecordFixture(101, 99, 3), nil},
		"multiple callers":     {1, append(kernelRecordFixture(100, 99, 3), kernelRecordFixture(101, 99, 3)...), nil},
		"wrong group":          {2, kernelRecordFixture(4124, 4000, 5), nil},
		"missing after caller": {3, nil, nil},
		"wrong after caller":   {3, kernelRecordFixture(101, 99, 3), nil},
		"changed caller group": {3, kernelRecordFixture(100, 98, 3), nil},
		"zombie after caller":  {3, kernelRecordFixture(100, 99, 5), nil},
	} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			query := func(string, ...int) ([]byte, error) {
				calls++
				if calls == replace.stage {
					return replace.data, replace.err
				}
				if calls == 2 {
					return kernelRecordFixture(4124, 4123, 5), nil
				}
				return kernelRecordFixture(100, 99, 3), nil
			}
			members, err := observeKernelProcessGroup(4123, 100, query)
			if err == nil || members != nil || calls != replace.stage || replace.err != nil && !errors.Is(err, replace.err) {
				t.Fatalf("invalid kernel observation accepted or retried: %v %v calls=%d", members, err, calls)
			}
		})
	}
}

func TestDarwinKernelMembershipRequestAndElapsedBounds(t *testing.T) {
	for _, identities := range [][2]int{{0, 100}, {1, 100}, {-10, 100}, {4123, 0}, {4123, 1}} {
		called := false
		query := func(string, ...int) ([]byte, error) {
			called = true
			return nil, nil
		}
		members, err := observeKernelProcessGroup(identities[0], identities[1], query)
		if called || err == nil || members != nil {
			t.Fatalf("invalid request reached the kernel: %v %v called=%v", identities, err, called)
		}
	}
	if _, err := observeKernelProcessGroup(4123, 100, nil); err == nil {
		t.Fatal("missing kernel query accepted")
	}
	calls := 0
	query := func(string, ...int) ([]byte, error) {
		calls++
		time.Sleep(1600 * time.Millisecond)
		return kernelRecordFixture(100, 99, 3), nil
	}
	members, err := observeKernelProcessGroup(4123, 100, query)
	if err == nil || members != nil || calls != 1 {
		t.Fatalf("late kernel result accepted or retried: %v %v calls=%d", members, err, calls)
	}
}
