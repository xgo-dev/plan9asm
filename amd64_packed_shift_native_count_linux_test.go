//go:build linux && (amd64 || arm64)

package plan9asm

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func x86PackedShiftBuildOriginalCountObserver(t *testing.T, compiler []string) string {
	t.Helper()
	const main = `
#include <stdlib.h>
int main(int argc,char **argv) {
 if(argc!=2) return 97;
 int kernel=atoi(argv[1]);
 if(kernel<0 || kernel>=6) return 98;
 _Alignas(16) uint8_t storage[96];
 for(int i=0;i<96;i++) storage[i]=(uint8_t)(i*31+7);
 const uint8_t *count=storage+1;
 if((uintptr_t)count%16!=1) return 99;
 int status=observe_count(originals[kernel],kernel,0,0,count,0);
 if(WIFEXITED(status) && WEXITSTATUS(status)==0)
  printf("COUNT_NATIVE_STATUS kernel=%d mod16=%llu wait=%d outcome=normal\n",kernel,(unsigned long long)((uintptr_t)count%16),status);
 else if(WIFSIGNALED(status) && WTERMSIG(status)==SIGSEGV)
  printf("COUNT_NATIVE_STATUS kernel=%d mod16=%llu wait=%d outcome=fault\n",kernel,(unsigned long long)((uintptr_t)count%16),status);
 else { fprintf(stderr,"original count status=%x\n",status); return 100; }
 return 0;
}
`
	dir := t.TempDir()
	input, executable := filepath.Join(dir, "original.c"), filepath.Join(dir, "original-count-observer")
	if err := os.WriteFile(input, []byte(x86PackedShiftLegacyCountCHeader+x86PackedShiftOriginalCountC()+x86PackedShiftCountCChecks+main), 0600); err != nil {
		t.Fatal(err)
	}
	arguments := append(append([]string(nil), compiler[1:]...), "-O2", input, "-o", executable)
	ctx, cancel := runtimeOracleStageContext(t)
	output, err := runtimeOracleCombinedOutput(ctx, exec.CommandContext(ctx, compiler[0], arguments...))
	cancel()
	if err != nil {
		t.Fatalf("original opcode status observer: %v\n%s", err, output)
	}
	return executable
}
