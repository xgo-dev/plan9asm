package plan9asm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/internal/goasmcmd"
)

// Machine-readable Go output must not include download progress from stderr.
// Keep both streams and the actual exit through the existing bounded, owned
// process implementation. This test helper does not relax production Run.
func runtimeOracleMachineOutput(ctx context.Context, command *exec.Cmd) ([]byte, []byte, error) {
	if command == nil || len(command.Args) == 0 || command.Stdin != nil || command.Stdout != nil || command.Stderr != nil {
		return nil, nil, fmt.Errorf("machine-output oracle requires an unstarted command without stream overrides")
	}
	observed, err := goasmcmd.Observe(ctx, command.Dir, command.Env, command.Path, command.Args[1:]...)
	return observed.Stdout, observed.Stderr, err
}

// Keep command output and the original exit, but never wait indefinitely for
// an emulator retaining its parent's pipe. Unix also owns the fresh group.
func runtimeOracleCombinedOutput(ctx context.Context, command *exec.Cmd) ([]byte, error) {
	if ctx == nil || command == nil {
		return nil, fmt.Errorf("runtime oracle requires a command and its context")
	}
	if command.Stdout != nil || command.Stderr != nil {
		return nil, fmt.Errorf("runtime oracle command already has output writers")
	}
	var output bytes.Buffer
	command.Stdout, command.Stderr = &output, &output
	command.WaitDelay = 2 * time.Second
	err := runtimeOracleRun(command)
	if ctx.Err() != nil {
		err = errors.Join(err, ctx.Err())
	}
	return output.Bytes(), err
}

const (
	runtimeOracleStageTimeout        = 5 * time.Minute
	runtimeOracleProofTimeout        = 20 * time.Minute
	runtimeOracleStageCleanupReserve = 3 * time.Second
)

func runtimeOracleStageContext(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()
	deadline, hasDeadline := t.Deadline()
	return context.WithDeadline(context.Background(), runtimeOracleStageDeadline(time.Now(), deadline, hasDeadline))
}

func runtimeOracleStageDeadline(now, testDeadline time.Time, hasTestDeadline bool) time.Time {
	return runtimeOracleBoundedDeadline(now, testDeadline, hasTestDeadline, runtimeOracleStageTimeout)
}

// Composed source proofs retain one context identity through owner capture,
// independent object capture, binding and final API/runtime verification.
// That lease spans multiple stages; it must not expire after the first stage's
// budget. Individual subprocess/stage limits and cancellation remain intact.
func runtimeOracleProofContext(t testing.TB) (context.Context, context.CancelFunc) {
	t.Helper()
	var deadline time.Time
	var hasDeadline bool
	if bounded, ok := t.(interface{ Deadline() (time.Time, bool) }); ok {
		deadline, hasDeadline = bounded.Deadline()
	}
	return context.WithDeadline(context.Background(),
		runtimeOracleBoundedDeadline(time.Now(), deadline, hasDeadline, runtimeOracleProofTimeout))
}

func runtimeOracleBoundedDeadline(now, testDeadline time.Time, hasTestDeadline bool, budget time.Duration) time.Time {
	deadline := now.Add(budget)
	if hasTestDeadline {
		// Reserve the existing bounded pipe/group cleanup before testing's
		// overall deadline. An exhausted budget stays expired: do not launch.
		latest := testDeadline.Add(-runtimeOracleStageCleanupReserve)
		if latest.Before(deadline) {
			deadline = latest
		}
	}
	return deadline
}

func TestRuntimeOracleCommandRequiresBoundContextAndOutput(t *testing.T) {
	ctx := context.Background()
	command := exec.CommandContext(ctx, os.Args[0])
	for _, test := range []struct {
		name    string
		ctx     context.Context
		command *exec.Cmd
	}{
		{name: "no context", command: command},
		{name: "no command", ctx: ctx},
	} {
		t.Run(test.name, func(t *testing.T) {
			if output, err := runtimeOracleCombinedOutput(test.ctx, test.command); err == nil || len(output) != 0 {
				t.Fatalf("unbound runtime command accepted: %v %q", err, output)
			}
		})
	}
	var existing bytes.Buffer
	command.Stdout = &existing
	if output, err := runtimeOracleCombinedOutput(ctx, command); err == nil || len(output) != 0 || command.Stdout != &existing || command.Process != nil {
		t.Fatalf("runtime command replaced an output writer or ran: %v %q", err, output)
	}

	expired, cancel := context.WithDeadline(ctx, time.Now().Add(-time.Second))
	defer cancel()
	command = exec.CommandContext(expired, os.Args[0])
	if output, err := runtimeOracleCombinedOutput(expired, command); !errors.Is(err, context.DeadlineExceeded) || len(output) != 0 || command.Process != nil {
		t.Fatalf("expired command was launched or lost its deadline: %v %q", err, output)
	}
}

func TestRuntimeOracleCommandConsumersRetainOwnedExecution(t *testing.T) {
	// Every Go compiler/executable/emulator command in these native oracles
	// must use the same bounded lifecycle. Do not just fix the discovering case.
	for _, name := range []string{
		"go_ordinary_global_line_map_test.go",
		"wasm_integer_count_runtime_test.go",
		"arm64_vector_memory_indexbyte_test.go",
		"x86_fma3_portable_access_runtime_test.go",
		"arm_fp_symbol_offset_context_go127_test.go",
		"arm_symbol_offset_context_go127_test.go",
		"translate_text_context_test.go",
		"native_c_tools_darwin_arm64_test.go",
		"arm64_scalar_conversion_status_runtime_linux_test.go",
		"toolchain_test.go",
		"data_global_alignment_link_test.go",
		"arm64_abi0_byte_region_witness_test.go",
		"arm64_linux_syscall_effects_go127_test.go",
		"arm64_linux_syscall_effects_runtime_linux_test.go",
		"arm64_abi0_byte_region_role_test.go",
		"arm64_abi0_byte_region_naming_test.go",
		"arm64_closed_tail_stdlib_test.go",
		"stdlib_arm64_test_helpers_test.go",
		"llvm_object_lifecycle_unix_test.go",
		"runtime_exec_test.go",
		"runtime_c_asm_label_linux_test.go",
		"runtime_oracle_fault_core_unix_test.go",
		"amd64_cmpxchg_fault_observer_test.go",
		"amd64_cmpxchg_fault_portability_test.go",
		"runtime_oracle_binary_output_test.go",
		"amd64_packed_logical_oracle_test.go",
		"amd64_go_caller_lea_test.go",
		"amd64_raw_operand_handoff_test.go",
		"amd64_raw_nop_handoff_test.go",
		"amd64_scalar_bitcount_test.go",
		"amd64_movemask_grammar_test.go",
		"amd64_lower_movnti_test.go",
		"amd64_movnti_runtime_test.go",
		"x86_implicit_divide_runtime_test.go",
		"x86_duplicate_move_runtime_test.go",
		"x86_duplicate_move_wig_test.go",
		"x86_blend_minpos_native_test.go",
		"x86_blend_minpos_mode32_binding_test.go",
		"x86_named_half_tdd_test.go",
		"x86_named_half_fault_tdd_test.go",
		"x86_named_half_raw_tdd_test.go",
		"x86_scalar_reciprocal_physical_test.go",
		"x86_packed_reciprocal_native_read_test.go",
		"x86_unsigned_scalar_integer_float_physical_test.go",
		"x86_unsigned_scalar_integer_float_named_tuple_test.go",
		"amd64_raw_packed_sign_test.go",
		"x86_raw_abs_literal_test.go",
		"x86_packed_shift_raw_physical_test.go",
		"x86_vnni_raw_replay_test.go",
		"amd64_move_half_complete_test.go",
		"x86_move_half_fault_unix_test.go",
		"x86_result_bitcount_test.go",
		"amd64_scalar_lane_original_go_test.go",
		"amd64_scalar_lane_mode32_test.go",
		"amd64_source_integer_address_index_test.go",
		"x86_reciprocal_sib_profile_test.go",
		"x86_reciprocal_sib_oracle_test.go",
		"go_translate_test.go",
		"amd64_go_caller_lea_runtime_test.go",
		"amd64_raw_lea_runtime_test.go",
		"amd64_go_caller_acyclic_runtime_test.go",
		"amd64_go_caller_counted_loop_runtime_test.go",
		"amd64_go_caller_counted_scc_runtime_test.go",
		"amd64_fixed_local_runtime_test.go",
		"amd64_fixed_local_packed_runtime_test.go",
		"amd64_fixed_local_original_test.go",
		"amd64_scalar_float_integer_status_runtime_test.go",
		"x86_scalar_float_integer_native_read_test.go",
		"x86_scalar_float_integer_original_format_test.go",
		"x86_scalar_float_integer_raw_source_test.go",
		"x86_result_initialization_test.go",
		"x86_result_native_pointer_alias_test.go",
		"x86_result_auto_runtime_test.go",
		"x86_result_typed_effects_runtime_test.go",
		"x86_result_scalar_import_runtime_test.go",
		"amd64_legacy_packed_move_runtime_test.go",
		"amd64_legacy_integer_arithmetic_runtime_test.go",
		"amd64_legacy_logical_memory_test.go",
		"amd64_packed_word_multiply_runtime_test.go",
		"amd64_movnti_runtime_test.go",
		"amd64_packed_align_fault_unix_test.go",
		"x86_implicit_divide_runtime_test.go",
		"x86_segment_query_runtime_linux_amd64_test.go",
		"amd64_dword_product_forms_test.go",
		"amd64_packed_narrow_independent_runtime_test.go",
		"x86_explicit_imul_immediate_semantics_test.go",
		"amd64_fixed_local_frame_test.go",
		"go_x86_numerical_read_owned_role_test.go",
		"go_x86_numerical_read_family_test.go",
		"go_ordinary_global_vector_read_test.go",
		"go_ordinary_global_vector_runtime_test.go",
		"go_x86_tls_move_runtime_linux_amd64_go127_test.go",
		"x86_direct_tail_runtime_linux_amd64_test.go",
		"x86_direct_tail_386_runtime_linux_amd64_test.go",
		"x86_direct_tail_followup_runtime_linux_amd64_test.go",
		"x86_continuation_runtime_linux_amd64_test.go",
		"x86_abi0_bool_runtime_linux_amd64_test.go",
		"x86_custom_helper_pointer_runtime_linux_amd64_test.go",
		"x86_custom_helper_pointer_runtime_fixture_test.go",
		"x86_direct_tail_object_test.go",
		"x86_direct_tail_followup_object_test.go",
		"amd64_tls_move_source_banks_test.go",
		"amd64_movq_source_alias_test.go",
		"amd64_movq_source_alias_provenance_test.go",
		"amd64_movq_source_alias_runtime_linux_amd64_test.go",
		"go_x86_numerical_read_runtime_test.go",
		"go_x86_numerical_read_local_runtime_test.go",
		"go_x86_sdk_asm_data_lifecycle_test.go",
		"amd64_go_caller_saved_g_runtime_test.go",
		"amd64_go_caller_logical_runtime_test.go",
		"amd64_float_add_sub_go_oracle_test.go",
		"amd64_float_add_sub_literal_runtime_test.go",
		"amd64_float_compare_oracle_test.go",
		"amd64_float_compare_original_vector_test.go",
		"amd64_float_compare_vex_numerical_test.go",
		"amd64_float_compare_transport_test.go",
		"amd64_original_sysv_test.go",
		"amd64_comi_fixture_compile_unix_test.go",
		"amd64_packed_vector_move_aligned_oracle_unix_test.go",
		"amd64_float_compare_preflight_portability_test.go",
		"x86_original_floating_runtime_preflight_policy_test.go",
		"x86_numerical_vex_gp_boundaries_test.go",
		"amd64_conformance_native_test.go",
		"amd64_insert_extract_native_runtime_test.go",
		"amd64_packed_double_dword_native_test.go",
		"amd64_packed_narrow_rules_test.go",
		"amd64_maddword_go_oracle_test.go",
		"amd64_madd_typed_rules_test.go",
		"amd64_madd_typed_runtime_test.go",
		"amd64_timestamp_runtime_test.go",
		"amd64_cpu_query_consumers_test.go",
		"amd64_cpu_query_runtime_unix_test.go",
		"amd64_defined_status_numerical_test.go",
		"amd64_defined_status_ia32_test.go",
		"amd64_packed_string_vector_test.go",
		"amd64_cpu_query_native_reference_test.go",
		"amd64_cpu_query_linux_amd64_test.go",
		"amd64_timestamp_linux_amd64_test.go",
		"amd64_timestamp_rule_consumers_test.go",
		"amd64_undefined_trap_consumers_test.go",
		"amd64_undefined_trap_runtime_unix_test.go",
		"amd64_undefined_trap_linux_amd64_test.go",
		"amd64_ordering_hint_rule_consumers_test.go",
		"amd64_raw_minpos_allocator_boundary_test.go",
		"amd64_ordering_hint_runtime_test.go",
		"amd64_stack_flags_id_transport_test.go",
		"amd64_stack_flags_id_native_linux_test.go",
		"amd64_stack_address_defect_test.go",
		"amd64_cmpxchg_object_test.go",
		"amd64_cmpxchg_original_c_runtime_test.go",
		"amd64_cmpxchg_actual_observation_test.go",
		"amd64_cmpxchg_original_catalogue_test.go",
		"amd64_ordering_hint_linux_amd64_test.go",
		"amd64_lock_scalar_rmw_linux_amd64_test.go",
		"amd64_lock_scalar_rmw_objects_test.go",
		"amd64_packed_add_go_oracle_test.go",
		"amd64_packed_average_original_go_test.go",
		"amd64_packed_average_raw_test.go",
		"amd64_auxiliary_carry_runtime_test.go",
		"amd64_scalar_flag_compare_af_runtime_test.go",
		"amd64_x87_flag_compare_test.go",
		"amd64_x87_native_ia32_test.go",
		"amd64_packed_subtract_go_oracle_test.go",
		"amd64_packed_integer_compare_go_oracle_test.go",
		"amd64_packed_integer_compare_linux_amd64_test.go",
		"amd64_go_caller_maddword_runtime_test.go",
		"amd64_packed_sad_runtime_test.go",
		"amd64_conditional_set_runtime_test.go",
		"amd64_packed_sad_forms_test.go",
		"x86_sad_raw_width_test.go",
		"x86_sqrt_raw_contract_test.go",
		"amd64_signed_integer_scalar_float_go_oracle_test.go",
		"amd64_float_binary_fp_span_test.go",
		"amd64_scalar_fp_bit_runtime_test.go",
		"amd64_legacy_float_memory_test.go",
		"amd64_horizontal_float_go_oracle_test.go",
		"amd64_horizontal_integer_memory_runtime_test.go",
		"amd64_horizontal_integer_full_alias_runtime_test.go",
		"amd64_horizontal_integer_family_test.go",
		"amd64_go_caller_horizontal_integer_test.go",
		"amd64_packed_unpack_go_oracle_test.go",
		"amd64_packed_zero_extend_runtime_test.go",
		"amd64_packed_zero_extend_raw_axes_test.go",
		"amd64_signed_packed_integer_float_runtime_test.go",
		"amd64_signed_packed_integer_float_resource_unix_test.go",
		"amd64_signed_packed_integer_float_raw_test.go",
		"amd64_scalar_vector_literal_test.go",
		"amd64_scalar_vector_literal_source_test.go",
		"amd64_scalar_vector_literal_runtime_test.go",
		"amd64_insert_extract_go_oracle_test.go",
		"amd64_insert_extract_sdk_source_test.go",
		"amd64_register_result_runtime_test.go",
		"amd64_scalar_relocation_runtime_linux_test.go",
		"amd64_go_caller_vector_zero_test.go",
		"arm64_local_register_branch_test.go",
		"arm64_gp_data_runtime_test.go",
		"arm64_gp_immediate_encoding_test.go",
		"arm64_lower_permute_test.go",
		"arm64_lower_move_test.go",
		"amd64_go_assembler_test.go",
		"go_assembler_oracle_test.go",
		"go_assembler_oracle_listing_test.go",
		"go_assembler_defect_go127_test.go",
		"go_assembler_oracle_infrastructure_go127_unix_test.go",
		"arm64_private_structure_runtime_test.go",
		"arm64_large_frame_runtime_test.go",
		"arm64_control_gp_move_runtime_test.go",
		"arm64_go_internal_aggregate_test.go",
		"arm64_native_scratch_runtime_test.go",
		"arm64_control_scalar_multiply_runtime_test.go",
		"arm64_raw_zero_frame_runtime_test.go",
		"arm64_raw_private_frame_runtime_test.go",
		"wasm_packed_go_runtime_test.go",
		"wasm_packed_node_compat_test.go",
		"arm64_control_memory_width_runtime_test.go",
		"arm64_raw_context_runtime_test.go",
		"arm64_sm3_runtime_test.go",
		"arm64_raw_self_bl_runtime_test.go",
		"arm64_scalar_minmax_state_test.go",
		"arm64_scalar_memory_encoding_audit_test.go",
		"arm64_fp_pair_observation_test.go",
		"arm64_fp_padding_runtime_test.go",
		"arm64_result_tail_native_runtime_test.go",
		"arm64_byte_carrier_consumer_darwin_arm64_test.go",
		"arm64_byte_carrier_runtime_go127_test.go",
		"arm64_byte_carrier_two_scalar_runtime_go127_test.go",
		"arm64_byte_carrier_signed_runtime_go127_test.go",
		"arm_word_float_scratch_runtime_linux_test.go",
		"arm_word_float_status_runtime_linux_test.go",
		"arm64_result_tail_compiler_audit_test.go",
		"amd64_mov_extension_caller_test.go",
		"amd64_mov_extension_runtime_test.go",
		"amd64_raw_movsxd_runtime_test.go",
		"amd64_float_compare_native_test.go",
		"amd64_raw_insertps_mode32_test.go",
		"arm64_scalar_writeback_test.go",
		"arm64_barrier_encoding_go127_test.go",
		"arm64_syscall_forms_go127_test.go",
		"arm64_ret_source_width_test.go",
		"arm64_opaque_preservation_observation_test.go",
		"arm64_private_sp_helper_test.go",
		"preprocess_macro_controls_test.go",
		"preprocess_semantic_oracle_test.go",
		"parser_label_prefix_test.go",
		"parser_opcode_suffix_test.go",
		"x86_official_binary_witness_test.go",
		"amd64_fixed_local_conversion_tool_cache_test.go",
	} {
		t.Run(name, func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			consumers, unowned := runtimeOracleCommandConsumers(file)
			for _, method := range unowned {
				t.Errorf("runtime command bypasses its owned lifecycle: %s", method)
			}
			if consumers == 0 {
				t.Fatal("native oracle has no bounded command consumer")
			}
		})
	}
}

func runtimeOracleCommandConsumers(file *ast.File) (consumers int, unowned []string) {
	testingImports := make(map[string]bool)
	for _, spec := range file.Imports {
		path, err := strconv.Unquote(spec.Path.Value)
		if err != nil || path != "testing" {
			continue
		}
		name := "testing"
		if spec.Name != nil {
			name = spec.Name.Name
		}
		if name != "." && name != "_" {
			testingImports[name] = true
		}
	}

	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if function, ok := call.Fun.(*ast.Ident); ok {
			switch function.Name {
			case "runtimeOracleCombinedOutput", "runtimeOracleMachineOutput", "goAssemblerOracleOutput", "x86FloatCompareCaptureCommand", "numericalLocalRuntimeCommand":
				consumers++
				return true
			}
		}
		method, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		switch method.Sel.Name {
		case "CombinedOutput", "Output", "Start", "Run":
		default:
			return true
		}
		if runtimeOracleTestingRun(method, testingImports) {
			return true
		}
		unowned = append(unowned, method.Sel.Name)
		return true
	})
	return consumers, unowned
}

func runtimeOracleTestingRun(method *ast.SelectorExpr, testingImports map[string]bool) bool {
	if method.Sel.Name != "Run" {
		return false
	}
	receiver := method.X
	for {
		paren, ok := receiver.(*ast.ParenExpr)
		if !ok {
			break
		}
		receiver = paren.X
	}
	ident, ok := receiver.(*ast.Ident)
	if !ok || ident.Obj == nil || ident.Obj.Kind != ast.Var {
		return false
	}
	// ParseFile resolves lexical objects, so a command shadowing a testing
	// parameter cannot inherit the parameter's exemption merely by its name.
	parameter, ok := ident.Obj.Decl.(*ast.Field)
	if !ok {
		return false
	}
	pointer, ok := parameter.Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	typ, ok := pointer.X.(*ast.SelectorExpr)
	if !ok || (typ.Sel.Name != "T" && typ.Sel.Name != "B") {
		return false
	}
	pkg, ok := typ.X.(*ast.Ident)
	return ok && pkg.Obj == nil && testingImports[pkg.Name]
}
