import pathlib
import re
import tempfile
import unittest

from port_review_test_support import ROOT, compile_fixture, function_source, run_fixture


class RpcArgumentContractTests(unittest.TestCase):
    def test_dispatch_and_roothide_argument_contracts(self):
        header = (ROOT / "BaseBin/libjailbreak/src/jbserver.h").read_text()
        declarations = header[header.index("typedef enum"):header.index("extern struct jbserver_impl")]
        source = (ROOT / "BaseBin/libjailbreak/src/jbserver.c").read_text()
        source = "\n".join(line for line in source.splitlines() if not line.startswith("#include"))
        roothide_path = "BaseBin/launchdhook/src/jbserver/jbdomain_roothide.c"
        roothide_source = (ROOT / roothide_path).read_text()
        arch_declaration = re.search(r"typedef struct \{[^}]+\} preferredArchInfo;", roothide_source).group(0)
        implementation = declarations + "\n" + source + "\n" + arch_declaration + "\n"
        implementation += function_source(roothide_path, "trust_macho_recurse") + "\n"
        implementation += function_source(roothide_path, "roothide_blacklist_check") + "\n"
        flags = ["-Wno-sign-compare", "-fno-sanitize-recover=all"]
        if "bool optional;" in declarations:
            flags.append("-DFIXTURE_HAS_OPTIONAL=1")
        with tempfile.TemporaryDirectory(prefix="rpc-arguments-") as temporary:
            executable = compile_fixture(pathlib.Path(temporary), implementation,
                                         "tests/rpc_argument_contract_tests.c", flags)
            cases = ["missing-string", "wrong-string", "wrong-bool", "wrong-integer",
                     "wrong-array", "wrong-dictionary", "wrong-data", "missing-generic",
                     "valid-scalars", "optional-absent", "data-followed-by-bool",
                     "data-output-followed-by-integer", "data-capacity", "eight-slots",
                     "caller-token-no-lookup", "output-no-lookup",
                     "unknown-action", "wrong-domain-type", "wrong-action-type",
                     "missing-blacklist-type", "wrong-blacklist-pid", "oversized-blacklist-pid",
                     "wrong-blacklist-path", "valid-blacklist-pid", "valid-blacklist-path",
                     "unknown-blacklist-type", "arch-absent", "arch-empty", "arch-valid",
                     "arch-collector-failure", "arch-collected-hash",
                     "arch-limit", "arch-over-limit", "arch-wrong-container",
                     "arch-wrong-element", "arch-wrong-type", "arch-missing-subtype",
                     "arch-overflow"]
            failures = []
            for case in cases:
                result = run_fixture(executable, case)
                if result.returncode:
                    failures.append(f"{case}: exit {result.returncode}\n{result.stdout}{result.stderr}")
            self.assertFalse(failures, "\n".join(failures))
            print(f"RPC argument contracts: {len(cases)} scenarios passed")


if __name__ == "__main__":
    unittest.main()
