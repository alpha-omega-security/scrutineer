//go:build !windows

package poc

import (
	"os"
	"syscall"
)

const readFlags = syscall.O_NONBLOCK | syscall.O_NOFOLLOW

func singleLink(_ *os.File, info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Nlink == 1
}
