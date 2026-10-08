import pathlib
import re
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
UPSTREAM_REVISION = "939a3a21400f0dc6d6163b2b5999ba2ace0d2732"
PORT_SUBMODULE_REVISIONS = {
    "BaseBin/XPF": "7751467e2d7f51cde692108a9f2ac1b63d5c6544",
    "BaseBin/opainject": "bd60149a9d324b5e26c769ffe358eb9935f90b8b",
}
PORT_SUBMODULE_URLS = {
    "BaseBin/XPF": "https://github.com/devnoname120/XPF",
    "BaseBin/opainject": "https://github.com/devnoname120/opainject",
}


def git(*args: str) -> bytes:
    return subprocess.run(
        ["git", *args], cwd=ROOT, check=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout


class PortIntegrityTests(unittest.TestCase):
    """Source integration checks; these do not establish on-device correctness."""

    def test_upstream_exploit_implementations_are_preserved(self):
        prefixes = (
            "Application/Dopamine/Exploits/ClearSword/",
            "Application/Dopamine/Exploits/DarkSword/",
            "Application/Dopamine/Exploits/Titan/",
            "Application/Dopamine/Exploits/momentarius/",
        )
        paths = git("ls-tree", "-r", "--name-only", UPSTREAM_REVISION, *prefixes)
        self.assertTrue(paths, "The pinned Dopamine 3 sources must be available")
        for path in paths.decode().splitlines():
            with self.subTest(path=path):
                file = ROOT / path
                self.assertTrue(file.is_file(), f"Missing upstream component: {path}")
                self.assertEqual(file.read_bytes(), git("show", f"{UPSTREAM_REVISION}:{path}"))

    def test_first_load_spawn_mode_is_published_before_spawn_hook_install(self):
        main = (ROOT / "BaseBin/launchdhook/src/main.m").read_text()
        postinit_decl = re.search(r"void\s+roothide_launchd_postinit\s*\(bool firstLoad\);", main)
        self.assertIsNotNone(postinit_decl)

        publish = main.find("launchdhookFirstLoad = firstLoad;")
        install = main.find("initSpawnHooks();")
        self.assertNotEqual(publish, -1, "first-load spawn mode must be published in launchd initializer")
        self.assertNotEqual(install, -1)
        self.assertLess(
            publish,
            install,
            "launchdhookFirstLoad must be set before the spawn hook becomes live",
        )

    def test_upstream_kernel_compatibility_is_preserved(self):
        paths = (
            "BaseBin/libjailbreak/src/kernel.c",
            "BaseBin/libjailbreak/src/kernel.h",
            "BaseBin/libjailbreak/src/translation.c",
            "BaseBin/libjailbreak/src/physrw.c",
            "BaseBin/libjailbreak/src/physrw_pte.c",
        )
        for path in paths:
            with self.subTest(path=path):
                self.assertEqual((ROOT / path).read_bytes(), git("show", f"{UPSTREAM_REVISION}:{path}"))

        # RootHide's counted credential repair needs the cr_ngroups offset, which
        # sits between the upstream uid/svuid and groups fields.  Keep the rest
        # of info.c byte-for-byte upstream while admitting only that adaptation.
        path = "BaseBin/libjailbreak/src/info.c"
        current = (ROOT / path).read_text()
        adaptation = "\tgSystemInfo.kernelStruct.ucred.ngroups = ucred_cr_posix + 0xC;\n"
        self.assertEqual(current.count(adaptation), 1)
        self.assertEqual(current.replace(adaptation, ""), git("show", f"{UPSTREAM_REVISION}:{path}").decode())

    def test_upstream_serialized_fields_are_preserved(self):
        path = "BaseBin/libjailbreak/src/info.h"
        field = re.compile(r"iterator\(ctx,\s*([\w.]+)\)")
        upstream = set(field.findall(git("show", f"{UPSTREAM_REVISION}:{path}").decode()))
        current = set(field.findall((ROOT / path).read_text()))
        self.assertTrue(upstream)
        self.assertEqual(upstream - current, set(), "Upstream state must survive IPC serialization")
        self.assertIn("jailbreakInfo.jbrand", current)
        self.assertIn("kernelSymbol.nchashtbl", current)

    def test_server_domains_preserve_roothide_client_abi(self):
        header = (ROOT / "BaseBin/libjailbreak/src/jbserver_domains.h").read_text()
        domains = dict(re.findall(r"#define\s+(JBS_DOMAIN_\w+)\s+(\d+)\b", header))
        self.assertEqual(len(domains), len(set(domains.values())), "IPC domains must not collide")
        self.assertEqual(domains["JBS_DOMAIN_ROOTHIDE"], "5")
        self.assertEqual(domains["JBS_DOMAIN_DOPAMINE"], "6")
        server = (ROOT / "BaseBin/launchdhook/src/jbserver/jbserver_global.c").read_text()
        implementations = re.findall(r"&(g\w+Domain)\s*,", server)
        self.assertEqual(implementations[4:6], ["gRootHideDomain", "gDopamineDomain"])

    def test_reviewed_submodule_revisions_are_pinned(self):
        for path in ("BaseBin/ChOma", "BaseBin/XPF", "BaseBin/opainject", "BaseBin/_external/modules/litehook"):
            with self.subTest(path=path):
                expected = PORT_SUBMODULE_REVISIONS.get(path)
                if expected is None:
                    expected = git("rev-parse", f"{UPSTREAM_REVISION}:{path}").strip().decode()
                actual = git("-C", path, "rev-parse", "HEAD").strip()
                self.assertEqual(actual.decode(), expected)

        gitmodules = (ROOT / ".gitmodules").read_text()
        for path, url in PORT_SUBMODULE_URLS.items():
            with self.subTest(path=path, url=url):
                self.assertIn(f"path = {path}", gitmodules)
                self.assertIn(f"url = {url}", gitmodules)

    def test_no_unresolved_merge_markers(self):
        paths = git("ls-files", "-z").decode().split("\0")
        marker = re.compile(rb"^(?:<<<<<<< |=======\r?$|>>>>>>> )", re.MULTILINE)
        for path in filter(None, paths):
            file = ROOT / path
            if not file.is_file():
                continue
            content = file.read_bytes()
            if b"\0" in content:
                continue
            with self.subTest(path=path):
                self.assertIsNone(marker.search(content), f"Unresolved merge in {path}")

    def test_build_workflow_uses_the_requested_checkout(self):
        workflow = (ROOT / ".github/workflows/roothide.yml").read_text()
        self.assertNotIn("git clone --recursive https://github.com/roothide/Dopamine2-roothide", workflow)
        self.assertRegex(workflow, r"uses:\s*actions/checkout@")

    def test_build_workflow_does_not_modify_xcode_sdk(self):
        workflow = (ROOT / ".github/workflows/roothide.yml").read_text()
        self.assertNotRegex(workflow, r"rm\s+-rf\s+\$\(xcrun")

    def test_ci_runs_host_regressions_with_full_history(self):
        workflow = (ROOT / ".github/workflows/roothide.yml").read_text()
        self.assertRegex(workflow, r"fetch-depth:\s*0\b")
        self.assertIn("sh tests/run_host_tests.sh", workflow)

    def test_workflow_curl_ignores_local_configuration(self):
        workflow = (ROOT / ".github/workflows/roothide.yml").read_text()
        commands = re.findall(r"^\s*curl\s+(.+)$", workflow, re.MULTILINE)
        self.assertTrue(commands)
        for arguments in commands:
            self.assertTrue(arguments.startswith("-q "), arguments)

    def test_libjailbreak_compiles_translation_units_independently(self):
        result = subprocess.run(
            ["make", "-n", "-B", "objects", "BUILD_STANDALONE=0"],
            cwd=ROOT / "BaseBin/libjailbreak", text=True, capture_output=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        for architecture in ("arm64", "arm64e"):
            for source in ("src/info.c", "src/util.m", "src/roothider/code_signing.c", "src/roothider/blacklist.cpp"):
                self.assertRegex(
                    result.stdout,
                    rf"-arch {architecture}\b[^\n]*-c {re.escape(source)} -o ",
                )

    def test_dyld_string_trampolines_have_one_definition(self):
        sources = list((ROOT / "BaseBin/dyldhook/src").glob("*.S"))
        for symbol in ("strlcpy", "strlcat"):
            definition = re.compile(rf"^\s*MAKE_TRAMPOLINE\({symbol}\)", re.MULTILINE)
            owners = [path.name for path in sources if definition.search(path.read_text())]
            self.assertEqual(owners, ["main.S"], f"Duplicate trampoline: {symbol}")

    def test_exploit_settings_use_the_declared_preference_getter(self):
        source = (ROOT / "Application/Dopamine/UI/Settings/DOSettingsController.m").read_text()
        self.assertIn("SEL defGetter = @selector(readPreferenceValue:);", source)
        for specifier in ("kernelExploitSpecifier", "pacBypassSpecifier", "pplBypassSpecifier"):
            declaration = re.search(rf"PSSpecifier \*{specifier} = ([^\n]+);", source)
            self.assertIsNotNone(declaration, specifier)
            self.assertIn("get:defGetter", declaration.group(1))

    def test_bundled_palera1n_is_not_marked_as_shared_cache_eligible(self):
        makefile = (ROOT / "Application/Dopamine/Exploits/palera1n/Makefile").read_text()
        flags = re.search(r"^palera1n_LDFLAGS\s*=\s*(.+)$", makefile, re.MULTILINE)
        self.assertIsNotNone(flags)
        self.assertIn("-Wl,-not_for_dyld_shared_cache", flags.group(1).split())

    def test_application_recursion_preserves_selected_make(self):
        for target, operation in (("all", "package"), ("clean", "clean")):
            with self.subTest(target=target):
                result = subprocess.run(
                    ["make", "-n", target, "MAKE=echo"],
                    cwd=ROOT / "Application", text=True, capture_output=True,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(f"echo -C Dopamine/Exploits/palera1n {operation}", result.stdout)

    def test_default_package_excludes_unported_standalone_installer(self):
        result = subprocess.run(
            ["make", "-n", "all", "MAKE=echo", "BUILD_STANDALONE=0"],
            cwd=ROOT, text=True, capture_output=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("-C Standalone", result.stdout)
        basebin = (ROOT / "BaseBin/Makefile").read_text()
        subprojects = re.search(r"^subprojects:\s*(.+)$", basebin, re.MULTILINE)
        self.assertIsNotNone(subprojects)
        self.assertNotIn("dopamine", subprojects.group(1).split())

    def test_unported_standalone_build_is_rejected(self):
        result = subprocess.run(
            ["make", "-n", "all", "MAKE=echo", "BUILD_STANDALONE=1"],
            cwd=ROOT, text=True, capture_output=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("standalone", result.stderr.lower())

    def test_staged_external_headers_keep_source_timestamps(self):
        build = ROOT / ".build/tests"
        build.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="header-stage-", dir=build) as directory:
            fixture = pathlib.Path(directory)
            (fixture / "Makefile").write_bytes((ROOT / "BaseBin/Makefile").read_bytes())
            headers = fixture / "_external/include"
            headers.mkdir(parents=True)
            source = headers / "port_timestamp_test.h"
            source.write_text("#define PORT_TIMESTAMP_TEST 1\n")
            for _ in range(2):
                result = subprocess.run(
                    ["make", ".include"], cwd=fixture, text=True, capture_output=True,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                staged = fixture / ".include/port_timestamp_test.h"
                self.assertEqual(staged.read_bytes(), source.read_bytes())
                self.assertEqual(staged.stat().st_mtime_ns, source.stat().st_mtime_ns)


if __name__ == "__main__":
    unittest.main()
