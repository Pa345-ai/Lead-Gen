//go:build windows

// racer.go attempts to rename a directory (or replace it with a junction)
// while locker.exe is holding it open with the exact flags kubelet's
// lockPath() uses. This answers the load-bearing question for the
// subpath_windows.go TOCTOU hypothesis:
//
//   Does NTFS block renaming a directory that is open with
//   GENERIC_READ | FILE_SHARE_READ | FILE_FLAG_OPEN_REPARSE_POINT,
//   or does the rename succeed anyway?
//
// Usage:
//   racer.exe rename   <target-dir> <new-name>
//   racer.exe junction <target-dir> <junction-target>
//
// Run this from a SECOND window/process while locker.exe (same target-dir)
// is still holding its handle open (i.e. during its "still holding" loop).
//
// Interpreting the result:
//   - If the rename/junction-replace SUCCEEDS while locker.exe holds the
//     handle: NTFS's share mode does NOT protect against this race the way
//     Linux's openat(parentFD, ...) does. The hypothesis is CONFIRMED at
//     the OS-primitive level (still need step 2/3 from the methodology to
//     confirm consequence inside kubelet's actual directory walk).
//   - If it FAILS with ERROR_SHARING_VIOLATION (or similar): NTFS's share
//     semantics already close this window, and the hypothesis is REFUTED
//     at the OS-primitive level. Stop here — no further escalation needed,
//     and nothing should be reported as a finding.
//
// Either outcome is informative. Do not proceed past this script's result
// without it.

package main

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

func main() {
	if len(os.Args) < 4 {
		fmt.Println("usage:")
		fmt.Println("  racer.exe rename   <target-dir> <new-name>")
		fmt.Println("  racer.exe junction <target-dir> <junction-target>")
		os.Exit(1)
	}

	mode := os.Args[1]
	target := os.Args[2]
	arg3 := os.Args[3]

	switch mode {
	case "rename":
		fmt.Printf("[racer] attempting os.Rename(%q -> %q) while target may be locked...\n", target, arg3)
		err := os.Rename(target, arg3)
		report("rename", err)

	case "junction":
		// Replace target with a junction pointing elsewhere. We first try
		// a plain remove+symlink as a stand-in for "replace this directory
		// entry with something else" — on Windows this exercises the same
		// underlying delete/replace-while-open question.
		fmt.Printf("[racer] attempting to remove %q and replace with junction -> %q\n", target, arg3)
		err := os.Remove(target)
		if err != nil {
			report("remove (pre-junction)", err)
			return
		}
		err = os.Symlink(arg3, target) // requires admin or dev-mode on Windows for symlink; junctions need mklink /J via exec if this fails
		report("symlink-replace", err)

	default:
		fmt.Println("unknown mode:", mode)
		os.Exit(1)
	}
}

func report(op string, err error) {
	if err == nil {
		fmt.Printf("[racer] %s SUCCEEDED while handle was (expected to be) held.\n", op)
		fmt.Println("[racer] => NTFS did NOT block this. Hypothesis CONFIRMED at OS level — escalate to step 2/3.")
		return
	}

	fmt.Printf("[racer] %s FAILED: %v\n", op, err)

	var errno syscall.Errno
	if errors.As(err, &errno) {
		fmt.Printf("[racer] underlying Win32 error code: %d\n", uint32(errno))
		// ERROR_SHARING_VIOLATION == 32
		if uint32(errno) == 32 {
			fmt.Println("[racer] => ERROR_SHARING_VIOLATION. NTFS blocked this. Hypothesis REFUTED at OS level — stop, do not report a finding.")
			return
		}
	}
	fmt.Println("[racer] => Failed for some other reason (check error above). Re-run with locker.exe confirmed actively holding the handle before concluding anything.")
}
