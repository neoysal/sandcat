// +build windows

package donut


import (
	"io/ioutil"
	"runtime"

	"github.com/mitre/sandcat/gocat/executors/execute"
)

type Donut struct {
	archName string
}

func init() {
	runner := &Donut{
		archName: "donut_"+runtime.GOARCH,
	}
	if runner.CheckIfAvailable() {
		execute.Executors[runner.archName] = runner
	}
}

func (d *Donut) Run(command string, timeout int) ([]byte, string, string) {
	bytes, _ := ioutil.ReadFile("something.donut")

	handle, stdout, stderr := CreateSuspendedProcessWIORedirect("rundll32.exe")

	//Start reading from the process output


	stdoutBytes := make([]byte, 4096)
	stderrBytes := make([]byte, 4096)

	// Run the shellcode and wait for it to complete
	task, pid := Runner(bytes, handle, stdout, &stdoutBytes, stderr, &stderrBytes)

	if task {

		// Assemble the final output

		total := "Shellcode executed successfully.\n\n"

		total += "STDOUT:\n"
		total += string(stdoutBytes)
		total += "\n\n"

		total += "STDERR:\n"
		total += string(stderrBytes)

		return []byte(total), execute.SUCCESS_STATUS, pid
	}
	return []byte("Shellcode execution failed."), execute.ERROR_STATUS, pid
}

func (d *Donut) String() string {
	return d.archName
}

func (d *Donut) CheckIfAvailable() bool {
	return IsAvailable()
}
