//go:build go1.27

package plan9asm

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
)

// Independent original Go/ASM/kernel fixture. No observer below can publish an
// initializer, source capability, native entry or syscall input certificate.
func arm64NanosleepRuntimeFixture(t *testing.T) (directory, packagePath, declarations string) {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	packagePath = "example.invalid/sleepinput"
	declarations = "package sleepinput\nfunc sleep(usec uint32)\n"
	const original = `package sleepinput
import (
    "fmt"
    "os"
    "os/signal"
    "runtime"
    "syscall"
    "testing"
    "time"
)
func TestOriginalNanosleepInput(t *testing.T) {
    for _, usec := range []uint32{0,1,2000} {
        start := time.Now()
        sleep(usec)
        if elapsed := time.Since(start); elapsed < 0 || elapsed > 2*time.Second {
            t.Fatal("original kernel sleep failed to return",usec,elapsed)
        }
        t.Logf("ORIGINAL_NANOSLEEP_KERNEL_PASS usec=%d",usec)
    }
    runtime.LockOSThread()
    defer runtime.UnlockOSThread()
    signals := make(chan os.Signal,1)
    signal.Notify(signals,syscall.SIGUSR1)
    defer signal.Stop(signals)
    thread := syscall.Gettid()
    stop := make(chan struct{})
    done := make(chan error,1)
    go func() {
        ticker := time.NewTicker(2*time.Millisecond)
        defer ticker.Stop()
        for attempt:=0;attempt<250;attempt++ {
            select {
            case <-stop:
                done <- nil
                return
            case <-ticker.C:
            }
            if err := syscall.Tgkill(os.Getpid(),thread,syscall.SIGUSR1); err!=nil {
                done <- err
                return
            }
        }
        done <- fmt.Errorf("bounded exact-thread interrupt sender exhausted")
    }()
    start := time.Now()
    sleep(1000000)
    elapsed := time.Since(start)
    close(stop)
    if err := <-done; err != nil { t.Fatal(err) }
    if elapsed < 0 || elapsed > 500*time.Millisecond {
        t.Fatal("original NULL-rem interrupted continuation did not return",elapsed)
    }
    select {
    case <-signals:
    case <-time.After(time.Second):
        t.Fatal("real thread-directed interrupt was not observed")
    }
    t.Log("ORIGINAL_NANOSLEEP_KERNEL_PASS interrupted-null-rem")
}
`
	for name, data := range map[string]string{
		"go.mod": "module " + packagePath + "\ngo 1.20\n", "decl.go": declarations,
		"original_arm64.s": arm64NanosleepInputSource, "original_test.go": original,
	} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return directory, packagePath, declarations
}

func arm64NanosleepRuntimeOriginalObjects(t *testing.T, directory, packagePath string) {
	t.Helper()
	archive, object, builtins := arm64ByteCarrierOriginal(t, directory, packagePath)
	members, err := gostaticstorage.ObserveARM64AssemblyArchive(archive, builtins, "linux/arm64", []string{"original_arm64.s"})
	if err != nil || len(members) != 3 {
		t.Fatalf("original complete archive precondition: %v", err)
	}
	texts, err := gostaticstorage.ObserveARM64AssemblyText(object, builtins, "linux/arm64")
	if err != nil || len(texts) != 1 || len(members[2].Texts) != 1 {
		t.Fatalf("original standalone/archive TEXT inventory: %v", err)
	}
	text, packed := texts[0], members[2].Texts[0]
	const originalCodeSHA = "360f9c85948651b364c9e030e319821df2196aa63fe118e57a856ee2faa4d9ed"
	if text.Name != packagePath+".sleep" || packed.Name != text.Name || text.ABI != 0 || packed.ABI != 0 ||
		len(text.Relocations) != 0 || len(packed.Relocations) != 0 || len(text.Positions) == 0 ||
		len(packed.Positions) == 0 || !bytes.Equal(text.Code, packed.Code) || len(text.Code) != 96 ||
		fmt.Sprintf("%x", sha256.Sum256(text.Code)) != originalCodeSHA {
		t.Fatal("first-party original body is not the exact SDK same-shape 96-byte kernel input")
	}
	t.Logf("ORIGINAL_NANOSLEEP_OBJECT archiveSHA256=%x objectSHA256=%x codeSHA256=%x bytes=%d",
		sha256.Sum256(archive), sha256.Sum256(object), sha256.Sum256(text.Code), len(text.Code))
}

func TestARM64NanosleepRuntimeOriginalObjectShape(t *testing.T) {
	directory, packagePath, _ := arm64NanosleepRuntimeFixture(t)
	arm64NanosleepRuntimeOriginalObjects(t, directory, packagePath)
}
