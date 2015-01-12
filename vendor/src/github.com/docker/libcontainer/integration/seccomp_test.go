// +build seccomp,linux,cgo

package integration

import (
	"strings"
	"testing"

	"github.com/docker/libcontainer/security/seccomp"
)

func TestSeccompDenyGetcwd(t *testing.T) {
	if testing.Short() {
		return
	}

	rootfs, err := newRootFs()
	if err != nil {
		t.Fatal(err)
	}
	defer remove(rootfs)

	config := newTemplateConfig(rootfs)
	config.BlockedCalls = []seccomp.BlockedSyscall{seccomp.MakeBlockedSyscall("getcwd")}

	buffers2, _, err := runContainer(config, "", "pwd")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Buffer is %s", buffers2.Stdout.String())

	buffers, exitCode, err := runContainer(config, "", "pwd")
	if err != nil {
		t.Fatal(err)
	}

	if exitCode != 1 {
		t.Fatalf("Getcwd should fail with exit code 1, instead got %d!", exitCode)
	}

	expected := "pwd: getcwd: Operation not permitted"
	actual := strings.Trim(buffers.Stderr.String(), "\n")
	if actual != expected {
		t.Fatalf("Expected output %s but got %s\n", expected, actual)
	}
}

func TestSeccompDenyMmap(t *testing.T) {
	if testing.Short() {
		return
	}

	rootfs, err := newRootFs()
	if err != nil {
		t.Fatal(err)
	}
	defer remove(rootfs)

	config := newTemplateConfig(rootfs)
	config.BlockedCalls = []seccomp.BlockedSyscall{seccomp.MakeBlockedSyscall("mmap")}

	buffers, exitCode, err := runContainer(config, "", "echo", "hello world")
	if err != nil {
		t.Fatal(err)
	}

	if exitCode != 20 {
		t.Fatalf("Busybox should fail to start with exit code 20, instead got %d!", exitCode)
	}

	expected := "mmap of a spare page failed!"
	actual := strings.Trim(buffers.Stderr.String(), "\n")
	if actual != expected {
		t.Fatalf("Expected output %s but got %s\n", expected, actual)
	}
}
