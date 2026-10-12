import pathlib
import re
import tempfile
import unittest

from port_review_test_support import ROOT, compile_fixture, function_source, run_fixture


class SystemhookLoaderFallbackTests(unittest.TestCase):
    def test_child_patch_policy_honors_explicit_fallback_marker(self):
        implementation = '#define ROOTHIDE_SYSTEMHOOK_DYLD_FALLBACK_ENV "ROOTHIDE_SYSTEMHOOK_DYLD_FALLBACK"\n'
        implementation += function_source("BaseBin/libjailbreak/src/roothider/common.m", "roothide_systemhook_dyld_fallback_enabled")
        implementation += "\n" + function_source("BaseBin/libjailbreak/src/roothider/common.m", "roothide_patch_proc")
        with tempfile.TemporaryDirectory(prefix="systemhook-loader-policy-") as directory:
            executable = compile_fixture(pathlib.Path(directory), implementation, "tests/systemhook_loader_fallback_tests.c")
            result = run_fixture(executable)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("14 systemhook loader policy cases passed", result.stdout)

    def test_fallback_bootstraps_stock_dyld_instead_of_replacing_it(self):
        source = (ROOT / "BaseBin/libjailbreak/src/roothider/dyld_patch.m").read_text()
        self.assertIn("int proc_bootstrap_dyld(pid_t pid)", source)
        bootstrap = function_source(
            "BaseBin/libjailbreak/src/roothider/dyld_patch.m",
            "proc_bootstrap_dyld",
        )
        self.assertIn("bootstrap_return", bootstrap)
        self.assertIn("vm_write", bootstrap)
        self.assertIn("thread_set_state", bootstrap)
        self.assertIn("patchedDyldInfo->entrypoint", bootstrap)
        self.assertNotIn("task_set_dyld_info", bootstrap)
        self.assertNotIn("vm_deallocate(task, dyld_address", bootstrap)
        self.assertNotIn("hook_dyld_entry", bootstrap)

        header = (ROOT / "BaseBin/libjailbreak/src/roothider/common.h").read_text()
        self.assertIn("int proc_bootstrap_dyld(pid_t pid);", header)

    def test_merged_dyld_can_return_to_stock_entry_after_bootstrap(self):
        assembly = (ROOT / "BaseBin/dyldhook/src/main.S").read_text()
        self.assertIn("_gDyldhookBootstrapReturn", assembly)
        self.assertIn("_gDyldhookBootstrapComplete", assembly)
        init_call = assembly.index("bl _dyldhook_init")
        real_start = assembly.index("b _MACHOMERGER_REAL_START", init_call)
        bootstrap_load = assembly.index("_gDyldhookBootstrapReturn@PAGE", init_call)
        indirect_branch = assembly.index("br x16", bootstrap_load)
        complete_store = assembly.index("_gDyldhookBootstrapComplete@PAGE", bootstrap_load)
        self.assertLess(bootstrap_load, indirect_branch)
        self.assertLess(complete_store, indirect_branch)
        self.assertLess(indirect_branch, real_start)

        patch_source = (ROOT / "BaseBin/libjailbreak/src/roothider/dyld_patch.m").read_text()
        self.assertIn('get_symbol(path, "_gDyldhookBootstrapReturn")', patch_source)
        self.assertIn('get_symbol(path, "_gDyldhookBootstrapComplete")', patch_source)

    def test_bootstrap_mapping_cleanup_is_delayed_and_identity_checked(self):
        source = (ROOT / "BaseBin/libjailbreak/src/roothider/dyld_patch.m").read_text()
        cleanup = function_source(
            "BaseBin/libjailbreak/src/roothider/dyld_patch.m",
            "schedule_bootstrap_mapping_cleanup",
        )
        self.assertIn("dispatch_after", cleanup)
        self.assertIn("proc_task(currentProc) != expectedTask", cleanup)
        self.assertIn("task_for_pid", cleanup)
        self.assertIn("vm_read_overwrite", cleanup)
        self.assertIn("bootstrapComplete != 1", cleanup)
        self.assertIn("vm_deallocate", cleanup)

        bootstrap = function_source(
            "BaseBin/libjailbreak/src/roothider/dyld_patch.m",
            "proc_bootstrap_dyld",
        )
        self.assertIn("schedule_bootstrap_mapping_cleanup", bootstrap)
        self.assertIn("proc_getcsflags", bootstrap)
        self.assertIn("proc_csflags_set", bootstrap)
        self.assertIn("proc_csflags_update", bootstrap)

    def test_bootstrap_seeds_only_targeted_sandbox_extensions_before_stock_dyld(self):
        patch_source = (ROOT / "BaseBin/libjailbreak/src/roothider/dyld_patch.m").read_text()
        self.assertIn("read_target_audit_token", patch_source)
        audit_reader = function_source(
            "BaseBin/libjailbreak/src/roothider/dyld_patch.m",
            "read_target_audit_token",
        )
        self.assertIn("koffsetof(proc_ro, task_tokens)", audit_reader)
        self.assertIn("koffsetof(task_token_ro_data, audit_token)", audit_reader)
        self.assertIn("kreadbuf", audit_reader)
        self.assertIn("audit_token_to_pid", audit_reader)

        bootstrap = function_source(
            "BaseBin/libjailbreak/src/roothider/dyld_patch.m",
            "proc_bootstrap_dyld",
        )
        self.assertIn("generate_sandbox_extensions", bootstrap)
        self.assertIn("bootstrap_sandbox_extensions", bootstrap)
        self.assertIn("JBSERVER_SANDBOX_EXTENSIONS_MAX", bootstrap)
        self.assertIn("vm_write", bootstrap)
        self.assertIn("free(bootstrapSandboxExtensions)", bootstrap)
        self.assertNotIn("jbclient_mach_process_checkin", bootstrap)
        self.assertNotIn("proc_allow_all_syscalls", bootstrap)
        self.assertNotIn("proc_remove_msg_filter", bootstrap)
        self.assertNotIn("cs_allow_invalid", bootstrap)

    def test_bootstrap_dyld_consumes_seeded_tokens_without_full_checkin(self):
        source = (ROOT / "BaseBin/dyldhook/src/main.c").read_text()
        self.assertIn("gDyldhookBootstrapSandboxExtensions", source)
        self.assertIn("gDyldhookBootstrapReturn", source)
        init = function_source("BaseBin/dyldhook/src/main.c", "dyldhook_init")
        bootstrap_branch = re.search(
            r"if\s*\(gDyldhookBootstrapReturn\s*!=\s*0\)\s*\{(?P<body>.*?)\n\s*\}",
            init,
            re.S,
        )
        self.assertIsNotNone(bootstrap_branch, init)
        body = bootstrap_branch.group("body")
        self.assertIn("consume_tokenized_sandbox_extensions(gDyldhookBootstrapSandboxExtensions)", body)
        self.assertIn("return;", body)
        self.assertNotIn("dyldhook_perform_checkin", body)
        self.assertGreater(init.index("dyldhook_perform_checkin();"), bootstrap_branch.end())

        patch_source = (ROOT / "BaseBin/libjailbreak/src/roothider/dyld_patch.m").read_text()
        self.assertIn('get_symbol(path, "_gDyldhookBootstrapSandboxExtensions")', patch_source)

    def test_reboot_publication_uses_usr_lib_logical_path_via_private_search_dir_without_kcall(self):
        source = (ROOT / "BaseBin/launchdhook/src/roothider.m").read_text()
        reboot = source[source.index("else\n\t{") : source.index("if (__builtin_available(iOS 16.0, *))", source.index("else\n\t{"))]
        self.assertIn("is_kcall_initialized()", reboot)
        self.assertRegex(reboot, r"(?s)if \(is_kcall_initialized\(\)\).*?else \{.*?/usr/lib/systemhook-%016llX\.dylib")
        self.assertIn("systemhookSearchDir", reboot)
        self.assertIn("HOOK_DYLIB_SEARCH_PATH", reboot)
        self.assertIn("link(", reboot)
        self.assertRegex(reboot, r"(?s)if \(is_kcall_initialized\(\)\).*?else \{.*?setenv\(ROOTHIDE_SYSTEMHOOK_DYLD_FALLBACK_ENV,\s*\"1\",\s*1\)")
        self.assertRegex(reboot, r"(?s)is_kcall_initialized\(\).*?unsandbox\(\"/usr/lib\",")

    def test_shared_spawn_hook_pairs_logical_systemhook_with_private_search_path(self):
        header = (ROOT / "BaseBin/systemhook/src/common/common.h").read_text()
        source = (ROOT / "BaseBin/systemhook/src/common/common.c").read_text()
        self.assertIn("extern const char* HOOK_DYLIB_SEARCH_PATH;", header)
        self.assertIn("hook_dylib_backing_path", source)
        self.assertIn('"DYLD_LIBRARY_PATH"', source)
        self.assertIn("HOOK_DYLIB_SEARCH_PATH", source)
        self.assertIn("hookSearchAlreadyInserted", source)
        self.assertRegex(source, r"(?s)shouldInsertJBEnv.*?DYLD_LIBRARY_PATH.*?HOOK_DYLIB_SEARCH_PATH")
        self.assertRegex(source, r"(?s)!shouldInsertJBEnv.*?DYLD_LIBRARY_PATH")

    def test_systemhook_recovers_usr_lib_logical_identity_and_clears_private_search_override(self):
        source = (ROOT / "BaseBin/systemhook/src/roothider_main.c").read_text()
        init = function_source("BaseBin/systemhook/src/roothider_main.c", "roothide_init")
        self.assertIn("HOOK_DYLIB_SEARCH_PATH", source)
        self.assertIn("/usr/lib/systemhook-", init)
        self.assertIn('getenv("DYLD_LIBRARY_PATH")', init)
        self.assertIn("dyld_image_path_containing_address", init)
        self.assertIn("paths_refer_to_same_file(candidate, actualHookPath)", init)
        self.assertIn('unsetenv("DYLD_LIBRARY_PATH")', init)

    def test_systemhook_search_path_accepts_private_var_alias_by_file_identity(self):
        implementation = "\n".join([
            "#include <stdbool.h>",
            "#include <string.h>",
            "#include <sys/stat.h>",
            function_source("BaseBin/systemhook/src/roothider_main.c", "paths_refer_to_same_file"),
        ])
        with tempfile.TemporaryDirectory(prefix="systemhook-path-identity-") as directory:
            executable = compile_fixture(
                pathlib.Path(directory),
                implementation,
                "tests/systemhook_path_identity_tests.c",
            )
            result = run_fixture(executable)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("systemhook path identity cases passed", result.stdout)

    def test_recovered_private_search_path_respects_target_scope(self):
        header = (ROOT / "BaseBin/systemhook/src/common/common.h").read_text()
        common = (ROOT / "BaseBin/systemhook/src/common/common.c").read_text()
        systemhook = (ROOT / "BaseBin/systemhook/src/roothider_main.c").read_text()
        launchdhook = (ROOT / "BaseBin/launchdhook/src/roothider.m").read_text()

        self.assertIn("extern bool HOOK_DYLIB_SEARCH_PATH_JBROOT_ONLY;", header)
        self.assertIn("bool HOOK_DYLIB_SEARCH_PATH_JBROOT_ONLY = false;", launchdhook)
        self.assertIn("bool HOOK_DYLIB_SEARCH_PATH_JBROOT_ONLY = false;", systemhook)

        init = function_source("BaseBin/systemhook/src/roothider_main.c", "roothide_init")
        self.assertRegex(
            init,
            r"(?s)paths_refer_to_same_file\(candidate, actualHookPath\).*?"
            r"HOOK_DYLIB_SEARCH_PATH\s*=\s*matchingSearchPath;.*?"
            r"HOOK_DYLIB_SEARCH_PATH_JBROOT_ONLY\s*=\s*true;",
        )

        self.assertIn("static bool path_is_within_jbroot(const char *path)", common)
        spawn = function_source("BaseBin/systemhook/src/common/common.c", "spawn_exec_hook_common")
        self.assertRegex(
            spawn,
            r"(?s)HOOK_DYLIB_SEARCH_PATH_JBROOT_ONLY\s*&&\s*!path_eligible_for_private_search_injection\(path\).*?"
            r"shouldInsertJBEnv\s*=\s*false;",
        )
        self.assertNotIn("ROOTHIDE_SSHD_EXEC_TRACE", spawn)

    def test_private_search_fallback_can_reach_user_apps_for_frida_but_not_system_daemons(self):
        spawn = function_source("BaseBin/systemhook/src/common/common.c", "spawn_exec_hook_common")
        self.assertIn("!path_eligible_for_private_search_injection(path)", spawn)
        policy = function_source("BaseBin/systemhook/src/common/common.c", "path_eligible_for_private_search_injection")
        self.assertIn("path_is_within_jbroot(path)", policy)
        self.assertIn("jbclient_blacklist_check_path_checked(path, &blacklisted) == 0 && !blacklisted", policy)
        with tempfile.TemporaryDirectory(prefix="private-search-scope-") as directory:
            executable = compile_fixture(
                pathlib.Path(directory), policy, "tests/private_search_injection_scope_tests.c"
            )
            result = run_fixture(executable)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("6 private-search injection scope cases passed", result.stdout)

    def test_blacklist_rpc_lookup_distinguishes_allow_from_transport_failure(self):
        checked = function_source("BaseBin/libjailbreak/src/jbclient_roothide.c", "jbclient_blacklist_check_path_checked")
        with tempfile.TemporaryDirectory(prefix="blacklist-rpc-contract-") as directory:
            executable = compile_fixture(pathlib.Path(directory), checked, "tests/blacklist_rpc_contract_tests.c")
            result = run_fixture(executable)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("10 blacklist RPC contract cases passed", result.stdout)

    def test_jbroot_target_scope_uses_canonical_filesystem_boundary(self):
        implementation = "\n".join([
            "#include <limits.h>",
            "#include <stdbool.h>",
            "#include <stdlib.h>",
            "#include <string.h>",
            "static const char *fixtureJbroot = NULL;",
            "char *get_jbroot(void) { return (char *)fixtureJbroot; }",
            function_source("BaseBin/systemhook/src/common/common.c", "path_is_within_jbroot"),
        ])
        with tempfile.TemporaryDirectory(prefix="jbroot-target-scope-") as directory:
            executable = compile_fixture(
                pathlib.Path(directory),
                implementation,
                "tests/jbroot_target_scope_tests.c",
            )
            result = run_fixture(executable)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("jbroot target scope cases passed", result.stdout)

    def test_fallback_marker_is_propagated_to_reboot_jailbreakd(self):
        source = (ROOT / "BaseBin/libjailbreak/src/roothider/jailbreakd.c").read_text()
        spawn = function_source("BaseBin/libjailbreak/src/roothider/jailbreakd.c", "spawnJailbreakd")
        self.assertIn("ROOTHIDE_SYSTEMHOOK_DYLD_FALLBACK_ENV", source)
        self.assertIn("RESPAWN_REQUIRED=1", spawn)
        self.assertRegex(spawn, r"(?s)ROOTHIDE_SYSTEMHOOK_DYLD_FALLBACK_ENV.*?getenv\(ROOTHIDE_SYSTEMHOOK_DYLD_FALLBACK_ENV\)")

    def test_randomized_direct_systemhook_path_triggers_dyld_checkin(self):
        source = (ROOT / "BaseBin/dyldhook/src/main.c").read_text()
        self.assertIn('"/basebin/systemhook-"', source)
        self.assertRegex(source, r"(?s)/usr/lib/systemhook-.*?/basebin/systemhook\.dylib.*?/basebin/systemhook-")

    def test_namecache_kcall_gate_checks_initialized_primitive(self):
        header = (ROOT / "BaseBin/libjailbreak/src/primitives.h").read_text()
        source = (ROOT / "BaseBin/libjailbreak/src/primitives.c").read_text()
        transaction = (ROOT / "BaseBin/libjailbreak/src/roothider/namecache_transaction.h").read_text()
        self.assertIn("bool is_kcall_initialized(void);", header)
        self.assertRegex(source, r"(?s)bool is_kcall_initialized\(void\).*?gPrimitives\.kcall != NULL")
        self.assertIn("is_kcall_initialized()", transaction)


if __name__ == "__main__":
    unittest.main()
