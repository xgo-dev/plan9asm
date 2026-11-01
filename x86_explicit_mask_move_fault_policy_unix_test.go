//go:build unix

package plan9asm

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

func x86ExplicitMaskMoveFaultPolicy(header, observer, driver, main string) error {
	if observer != numericalRuntimeFaultObservationC {
		return fmt.Errorf("fault observer must retain the shared synchronous address/code policy")
	}
	if err := runtimeOracleFaultCorePolicy(driver); err != nil {
		return err
	}
	compact := func(text string) string { return strings.Join(strings.Fields(text), "") }
	body, application := compact(driver), compact(main)
	setup := "numerical_fault_begin(protectedPage,protectedBytes);"
	if !strings.Contains(header, "#include <errno.h>") || !strings.Contains(body, setup) ||
		strings.Index(body, setup) > strings.Index(body, "test->run(p,data,mask,out);") ||
		!strings.Contains(application, "observe(test,region+page-extents[e],data,mask,region+page,(size_t)page)") {
		return fmt.Errorf("actual guard-page range must be bound before invoking the fault child")
	}
	if !strings.Contains(body, "do{waited=waitpid(child,&status,0);}while(waited<0&&errno==EINTR);") ||
		!strings.Contains(body, "if(waited!=child)return-2;") {
		return fmt.Errorf("fault child must wait for its exact PID and retry EINTR only")
	}
	if strings.Contains(body, "WIFSIGNALED") || strings.Contains(body, "WTERMSIG") ||
		!strings.Contains(body, "if(numerical_fault_status(status))return1;") ||
		!strings.Contains(body, "if(WIFEXITED(status)&&WEXITSTATUS(status)==0)return0;") {
		return fmt.Errorf("only the shared owned synchronous-fault receipt may classify a fault")
	}
	return nil
}

func TestX86ExplicitMaskMoveFaultObserverPolicy(t *testing.T) {
	if err := x86ExplicitMaskMoveFaultPolicy(x86ExplicitMaskMoveActualHostHeader,
		numericalRuntimeFaultObservationC, x86ExplicitMaskMoveActualHostDriver, x86ExplicitMaskMoveActualHostMain); err != nil {
		t.Fatal(err)
	}
	file, err := parser.ParseFile(token.NewFileSet(), "x86_explicit_mask_move_portable_runtime_unix_test.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := x86ExplicitMaskMoveRuntimeOwnerPolicy(file); err != nil {
		t.Fatal(err)
	}
}

func x86ExplicitMaskMoveRuntimeOwnerPolicy(file *ast.File) error {
	owners, observers, drivers := 0, 0, 0
	validChain := false
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "TestX86ExplicitMaskMoveActualHostValuesAliasesAndFaults" {
			continue
		}
		owners++
		ast.Inspect(function.Body, func(node ast.Node) bool {
			if name, ok := node.(*ast.Ident); ok && name.Name == "numericalRuntimeFaultObservationC" {
				observers++
			}
			assignment, ok := node.(*ast.AssignStmt)
			if !ok || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 {
				return true
			}
			name, ok := assignment.Lhs[0].(*ast.Ident)
			if !ok || name.Name != "driver" {
				return true
			}
			drivers++
			var chain []string
			ast.Inspect(assignment.Rhs[0], func(node ast.Node) bool {
				if name, ok := node.(*ast.Ident); ok {
					switch name.Name {
					case "x86ExplicitMaskMoveActualHostHeader", "numericalRuntimeFaultObservationC", "x86ExplicitMaskMoveActualHostDriver":
						chain = append(chain, name.Name)
					}
				}
				return true
			})
			validChain = strings.Join(chain, ",") == "x86ExplicitMaskMoveActualHostHeader,numericalRuntimeFaultObservationC,x86ExplicitMaskMoveActualHostDriver"
			return true
		})
	}
	if owners != 1 || observers != 1 || drivers != 1 || !validChain {
		return fmt.Errorf("actual driver must consume the shared observer once before the oracle: owners=%d observers=%d drivers=%d chain=%t", owners, observers, drivers, validChain)
	}
	return nil
}

func TestX86ExplicitMaskMoveFaultPolicyNegativeControls(t *testing.T) {
	for _, control := range []string{"missing-observer", "user-signal", "unowned-address", "unbound-page", "late-handler", "late-core-limit", "unchecked-core-limit", "wrong-page", "missing-EINTR", "unchecked-PID", "any-signal"} {
		t.Run(control, func(t *testing.T) {
			header, observer := x86ExplicitMaskMoveActualHostHeader, numericalRuntimeFaultObservationC
			driver, main := x86ExplicitMaskMoveActualHostDriver, x86ExplicitMaskMoveActualHostMain
			switch control {
			case "missing-observer":
				observer = ""
			case "user-signal":
				observer = strings.Replace(observer, "info->si_code <= 0", "0", 1)
			case "unowned-address":
				observer = strings.Replace(observer, "address < atomic_load_explicit(&numerical_fault_first,memory_order_relaxed)", "0", 1)
			case "unbound-page":
				driver = strings.Replace(driver, "numerical_fault_begin(protectedPage,protectedBytes);", "", 1)
			case "late-handler":
				driver = strings.Replace(driver, "numerical_fault_begin(protectedPage,protectedBytes);", "", 1)
				driver = strings.Replace(driver, "test->run(p,data,mask,out);", "test->run(p,data,mask,out);\n        numerical_fault_begin(protectedPage,protectedBytes);", 1)
			case "late-core-limit":
				driver = strings.Replace(driver, "struct rlimit no_core={0,0};", "test->run(p,data,mask,out);\n        struct rlimit no_core={0,0};", 1)
			case "unchecked-core-limit":
				driver = strings.Replace(driver, "if(setrlimit(RLIMIT_CORE,&no_core)) _exit(120);", "setrlimit(RLIMIT_CORE,&no_core);", 1)
			case "wrong-page":
				main = strings.Replace(main, "data,mask,region+page,(size_t)page", "data,mask,region,(size_t)page", 1)
			case "missing-EINTR":
				driver = strings.Replace(driver, "waited<0 && errno==EINTR", "0", 1)
			case "unchecked-PID":
				driver = strings.Replace(driver, "if(waited!=child) return -2;", "", 1)
			case "any-signal":
				driver = strings.Replace(driver, "numerical_fault_status(status)", "WIFSIGNALED(status)", 1)
			}
			if header == x86ExplicitMaskMoveActualHostHeader && observer == numericalRuntimeFaultObservationC &&
				driver == x86ExplicitMaskMoveActualHostDriver && main == x86ExplicitMaskMoveActualHostMain {
				t.Fatal("fault negative control did not mutate its actual source", control)
			}
			if err := x86ExplicitMaskMoveFaultPolicy(header, observer, driver, main); err == nil {
				t.Fatal("weakened resource or unowned fault observation was accepted", control)
			}
		})
	}
	for _, chain := range []string{
		"x86ExplicitMaskMoveActualHostHeader+x86ExplicitMaskMoveActualHostDriver",
		"x86ExplicitMaskMoveActualHostHeader+numericalRuntimeFaultObservationC+numericalRuntimeFaultObservationC+x86ExplicitMaskMoveActualHostDriver",
		"x86ExplicitMaskMoveActualHostHeader+x86ExplicitMaskMoveActualHostDriver+numericalRuntimeFaultObservationC",
	} {
		t.Run("actual-driver/"+chain, func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), "control.go", "package plan9asm\n"+
				"func TestX86ExplicitMaskMoveActualHostValuesAliasesAndFaults(){driver:="+chain+";_=driver}\n", 0)
			if err != nil {
				t.Fatal(err)
			}
			if err := x86ExplicitMaskMoveRuntimeOwnerPolicy(file); err == nil {
				t.Fatal("missing/duplicate/reordered actual driver fault observer was accepted")
			}
		})
	}
}
