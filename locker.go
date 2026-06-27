//go:build windows

// locker.go replicates k8s.io/kubernetes/pkg/volume/util/subpath.lockPath()
// EXACTLY (same syscall, same flags, same access/share mode) so the test
// result reflects the real kubelet code path, not an approximation of it.
//
// Reference (current kubernetes/kubernetes master,
// pkg/volume/util/subpath/subpath_windows.go):
//
//   func lockPath(path string) (uintptr, error) {
//       pathp, err := syscall.UTF16PtrFromString(path)
//       access := uint32(syscall.GENERIC_READ)
//       sharemode := uint32(syscall.FILE_SHARE_READ)
//       createmode := uint32(syscall.OPEN_EXISTING)
//       flags := uint32(syscall.FILE_FLAG_BACKUP_SEMANTICS | syscall.FILE_FLAG_OPEN_REPARSE_POINT)
//       fd, err := syscall.CreateFile(pathp, access, sharemode, nil, createmode, flags, 0)
//       return uintptr(fd), err
//   }
//
// Usage:
//   locker.exe <path-to-lock> <seconds-to-hold>
//
// While it holds the handle, run racer.exe in a second window against the
// same path (or its parent) and observe whether the rename/replace succeeds.

package main

import (
	"fmt"
	"os"
	"strconv"
	"syscall"
	"time"
)

func lockPath(path string) (uintptr, error) {
	pathp, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return uintptr(syscall.InvalidHandle), err
	}
	access := uint32(syscall.GENERIC_READ)
	sharemode := uint32(syscall.FILE_SHARE_READ)
	createmode := uint32(syscall.OPEN_EXISTING)
	flags := uint32(syscall.FILE_FLAG_BACKUP_SEMANTICS | syscall.FILE_FLAG_OPEN_REPARSE_POINT)
	fd, err := syscall.CreateFile(pathp, access, sharemode, nil, createmode, flags, 0)
	return uintptr(fd), err
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("usage: locker.exe <path> <seconds-to-hold>")
		os.Exit(1)
	}
	path := os.Args[1]
	secs, err := strconv.Atoi(os.Args[2])
	if err != nil {
		fmt.Println("bad seconds arg:", err)
		os.Exit(1)
	}

	fmt.Printf("[locker] opening %q with GENERIC_READ | FILE_SHARE_READ | OPEN_EXISTING | FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT\n", path)

	handle, err := lockPath(path)
	if err != nil {
		fmt.Printf("[locker] CreateFile FAILED: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[locker] handle acquired (0x%x). Holding for %d seconds.\n", handle, secs)
	fmt.Println("[locker] >>> NOW run racer.exe against this path or a path beneath it in another window <<<")

	start := time.Now()
	for i := 0; i < secs; i++ {
		time.Sleep(1 * time.Second)
		fmt.Printf("[locker] still holding handle... %ds elapsed\n", int(time.Since(start).Seconds()))
	}

	syscall.CloseHandle(syscall.Handle(handle))
	fmt.Println("[locker] handle closed. Exiting.")
}
