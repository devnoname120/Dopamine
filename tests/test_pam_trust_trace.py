import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "BaseBin/launchdhook/src/jbserver/jbdomain_roothide.c"


class PamTrustTraceTests(unittest.TestCase):
    def test_temporary_pam_trust_trace_is_removed(self):
        source = SOURCE.read_text()
        self.assertNotIn('#include <libjailbreak/roothider/bootlog.h>', source)
        self.assertNotIn("should_trace_pam_trust", source)
        self.assertNotIn("trace_pam_trust", source)
        self.assertNotIn("jbserver: pam trust", source)
        start = source.index("static int roothide_trust_library_recurse")
        end = source.index("static int roothide_jailbroken_check", start)
        handler = source[start:end]
        self.assertRegex(handler, r"return\s+trust_macho_recurse\(")
        self.assertEqual(handler.count("trust_macho_recurse("), 1)


if __name__ == "__main__":
    unittest.main()
