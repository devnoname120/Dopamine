import pathlib
import tempfile
import unittest

from port_review_test_support import ROOT, compile_fixture, run_fixture


class HookdExternalSafetyTests(unittest.TestCase):
    def test_memory_api_is_published_before_image_callbacks(self):
        common = ROOT / "BaseBin/systemhook/src/common"
        memory = (common / "memory_hooks.c").read_text().replace('#include "common.h"', "")
        external = (common / "hookd_external.c").read_text().replace('#include "common.h"', "")
        with tempfile.TemporaryDirectory(prefix="hookd-external-api-") as temporary:
            directory = pathlib.Path(temporary)
            (directory / "libjailbreak").symlink_to(ROOT / "BaseBin/libjailbreak/src")
            executable = compile_fixture(
                directory, memory + "\n" + external, "tests/hookd_external_support_tests.c",
                ("-I", str(common)),
            )
            result = run_fixture(executable)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
