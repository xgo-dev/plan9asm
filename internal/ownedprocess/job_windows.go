package ownedprocess

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ErrCleanup distinguishes descendant cleanup failures from the command exit.
var ErrCleanup = errors.New("owned command descendants")

// Run creates the leader suspended, assigns it to a private non-breakaway job,
// then resumes its sole initial thread. Assigning an already running process
// would leave a race in which its earliest descendants escape the job.
// The job handle is not inherited; closing it also terminates its descendants.
func Run(command *exec.Cmd) (result error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return err
	}
	owner := &windowsJob{handle: job}
	defer func() { result = errors.Join(result, owner.close()) }()
	owner.port, err = windows.CreateIoCompletionPort(windows.InvalidHandle, 0, 0, 1)
	if err != nil {
		return err
	}
	completion := struct {
		Key  uintptr
		Port windows.Handle
	}{uintptr(job), owner.port}
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectAssociateCompletionPortInformation,
		uintptr(unsafe.Pointer(&completion)), uint32(unsafe.Sizeof(completion))); err != nil {
		return err
	}
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		return err
	}

	attributes := syscall.SysProcAttr{}
	if command.SysProcAttr != nil {
		attributes = *command.SysProcAttr
	}
	if attributes.CreationFlags&(windows.CREATE_SUSPENDED|windows.CREATE_BREAKAWAY_FROM_JOB) != 0 {
		return fmt.Errorf("owned command cannot inherit suspended or breakaway creation flags")
	}
	attributes.CreationFlags |= windows.CREATE_SUSPENDED
	command.SysProcAttr = &attributes
	// os/exec rejects Cancel on a command not created with CommandContext.
	if command.Cancel != nil {
		command.Cancel = func() error { return owner.cancel(command) }
	}
	if command.WaitDelay == 0 {
		command.WaitDelay = 2 * time.Second
	}
	if err := command.Start(); err != nil {
		return err
	}
	process, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE|windows.SYNCHRONIZE,
		false, uint32(command.Process.Pid))
	if err == nil {
		defer func() { result = errors.Join(result, windows.CloseHandle(process)) }()
		err = owner.attachAndResume(process, uint32(command.Process.Pid))
	}
	if err != nil {
		// An unassigned leader has never executed user code or created children.
		killErr := command.Process.Kill()
		if errors.Is(killErr, os.ErrProcessDone) {
			killErr = nil
		}
		return errors.Join(err, killErr, owner.close(), command.Wait())
	}

	// Wait for the leader, not os/exec's output readers: a descendant may still
	// hold stdout/stderr open. Cancel terminates this same private job.
	state, waitErr := windows.WaitForSingleObject(process, windows.INFINITE)
	if waitErr == nil && state != windows.WAIT_OBJECT_0 {
		waitErr = fmt.Errorf("unexpected owned leader wait state %d", state)
	}
	cleanupErr := owner.close()
	return errors.Join(waitErr, cleanupErr, command.Wait())
}

type windowsJob struct {
	mu       sync.Mutex
	handle   windows.Handle
	port     windows.Handle
	assigned bool
	stopped  bool
}

func (owner *windowsJob) cancel(command *exec.Cmd) error {
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.handle == 0 {
		return os.ErrProcessDone
	}
	owner.stopped = true
	if !owner.assigned {
		return command.Process.Kill()
	}
	return windows.TerminateJobObject(owner.handle, 1)
}

func (owner *windowsJob) attachAndResume(process windows.Handle, pid uint32) error {
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.stopped {
		return fmt.Errorf("owned command cancelled before job assignment")
	}
	if err := windows.AssignProcessToJobObject(owner.handle, process); err != nil {
		return fmt.Errorf("assign suspended command to private job: %w", err)
	}
	owner.assigned = true
	thread, err := suspendedWindowsThread(pid)
	if err != nil {
		return err
	}
	count, resumeErr := windows.ResumeThread(thread)
	closeErr := windows.CloseHandle(thread)
	if resumeErr == nil && count != 1 {
		resumeErr = fmt.Errorf("initial owned thread suspend count %d, want 1", count)
	}
	return errors.Join(resumeErr, closeErr)
}

func suspendedWindowsThread(pid uint32) (thread windows.Handle, result error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return 0, err
	}
	defer func() {
		result = errors.Join(result, windows.CloseHandle(snapshot))
		if result != nil && thread != 0 {
			result = errors.Join(result, windows.CloseHandle(thread))
			thread = 0
		}
	}()
	entry := windows.ThreadEntry32{Size: uint32(unsafe.Sizeof(windows.ThreadEntry32{}))}
	var id uint32
	for err = windows.Thread32First(snapshot, &entry); err == nil; err = windows.Thread32Next(snapshot, &entry) {
		if entry.Size < uint32(unsafe.Offsetof(entry.OwnerProcessID)+unsafe.Sizeof(entry.OwnerProcessID)) {
			return 0, fmt.Errorf("incomplete thread ownership snapshot")
		}
		if entry.OwnerProcessID == pid {
			if id != 0 || entry.ThreadID == 0 {
				return 0, fmt.Errorf("suspended command does not have one initial thread")
			}
			id = entry.ThreadID
		}
		entry.Size = uint32(unsafe.Sizeof(entry))
	}
	if !errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		return 0, err
	}
	if id == 0 {
		return 0, fmt.Errorf("suspended command initial thread is missing")
	}
	thread, err = windows.OpenThread(windows.THREAD_SUSPEND_RESUME|windows.THREAD_QUERY_LIMITED_INFORMATION, false, id)
	if err != nil {
		return 0, err
	}
	// A snapshot ID is not ownership: an external termination can recycle a
	// thread ID before OpenThread. Recheck the opened handle while the leader's
	// process handle still pins its identity, before touching the thread state.
	return thread, verifyWindowsThreadOwner(thread, pid)
}

var getProcessIDOfThread = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetProcessIdOfThread")

func verifyWindowsThreadOwner(thread windows.Handle, pid uint32) error {
	actual, _, err := getProcessIDOfThread.Call(uintptr(thread))
	if actual == 0 {
		return fmt.Errorf("query opened thread ownership: %w", err)
	}
	if pid <= 1 || actual != uintptr(pid) {
		return fmt.Errorf("opened thread belongs to process %d, not owned process %d", actual, pid)
	}
	return nil
}

func (owner *windowsJob) close() error {
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.handle == 0 {
		return nil
	}
	var err error
	if owner.assigned {
		err = windows.TerminateJobObject(owner.handle, 1)
		if err == nil {
			err = waitWindowsJobEmpty(owner.handle, owner.port)
		}
	}
	// KILL_ON_JOB_CLOSE is also the fallback when explicit cleanup fails.
	err = errors.Join(err, windows.CloseHandle(owner.handle))
	owner.handle = 0
	if owner.port != 0 {
		err = errors.Join(err, windows.CloseHandle(owner.port))
		owner.port = 0
	}
	if err != nil {
		return fmt.Errorf("%w: %w", ErrCleanup, err)
	}
	return nil
}

var getJobCompletion = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetQueuedCompletionStatus")

const jobObjectMsgActiveProcessZero = 4 // winnt.h: JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO

func waitWindowsJobEmpty(job, port windows.Handle) error {
	// TerminateJobObject is asynchronous. ActiveProcesses accounting can reach
	// zero before the processes finish exiting. The private completion port is
	// attached before the first assignment, so no exit notification is missed.
	deadline := time.Now().Add(5 * time.Second)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return fmt.Errorf("owned job did not complete process termination")
		}
		var message uint32
		// Job packets use the OVERLAPPED field as an integer process ID, not a
		// Go pointer. Do not expose that ID to the GC as *windows.Overlapped.
		var key, id uintptr
		ok, _, err := getJobCompletion.Call(uintptr(port), uintptr(unsafe.Pointer(&message)),
			uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(&id)),
			uintptr((remaining+time.Millisecond-1)/time.Millisecond))
		if ok == 0 {
			return fmt.Errorf("wait for owned job termination: %w", err)
		}
		if key != uintptr(job) {
			return fmt.Errorf("foreign completion in private owned job port")
		}
		if message == jobObjectMsgActiveProcessZero {
			if id != 0 {
				return fmt.Errorf("invalid process identity in empty-job completion")
			}
			return nil
		}
	}
}
