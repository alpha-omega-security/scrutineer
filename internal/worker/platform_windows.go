//go:build windows

package worker

import (
	"os/exec"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// setNewProcessGroup detaches cmd from the console's Ctrl+C group, the
// Windows counterpart of Setpgid: the interrupt reaches scrutineer's shutdown
// path, which cancels the context and kills the child.
func setNewProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP}
}

// superviseProcessGroup adopts the started cmd into a job object limited to
// kill-on-close, and returns the func that closes it. Windows has no
// signalable process group, so a job is the only handle on a whole tree:
// closing it kills the descendants a dead CLI left behind, and the kernel
// closes it for us if scrutineer itself dies.
func superviseProcessGroup(cmd *exec.Cmd) func() {
	noop := func() {}
	if cmd.Process == nil {
		return noop
	}
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return noop
	}
	closeJob := func() { _ = windows.CloseHandle(job) }

	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
			LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
		},
	}
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		closeJob()
		return noop
	}

	proc, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid))
	if err != nil {
		closeJob()
		return noop
	}
	defer func() { _ = windows.CloseHandle(proc) }()

	if err := windows.AssignProcessToJobObject(job, proc); err != nil {
		closeJob()
		return noop
	}
	return closeJob
}

// containerUserArgs is empty on Windows: os.Getuid reports -1 there, so the
// container keeps the runner image's own non-root user.
func containerUserArgs() []string {
	return nil
}
