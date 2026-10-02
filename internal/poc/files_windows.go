package poc

import (
	"os"

	"golang.org/x/sys/windows"
)

const readFlags = 0

func singleLink(file *os.File, _ os.FileInfo) bool {
	var info windows.ByHandleFileInformation
	return windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &info) == nil && info.NumberOfLinks == 1
}
