from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]

class UserspaceRebootHandoffTests(unittest.TestCase):
    def test_ios26_userspace_reboot_does_not_render_boot_logo_in_launchd(self):
        source = (ROOT / "BaseBin/launchdhook/src/main.m").read_text()
        start = source.index("int sysctlbyname_hook(")
        end = source.index("__attribute__((constructor))", start)
        hook = source[start:end]

        self.assertIn('if (!strcmp(name, "kern.willuserspacereboot"))', hook)
        self.assertIn("if (__builtin_available(iOS 19.0, *))", hook)
        modern = hook.index("if (__builtin_available(iOS 19.0, *))")
        legacy = hook.index("else", modern)
        draw = hook.index('draw_boot_logo(JBROOT_PATH("/basebin/bootlogo.jp2"))')
        self.assertLess(modern, legacy)
        self.assertLess(legacy, draw)

    def test_first_load_launchd_self_spawn_routes_before_bypass(self):
        source = (ROOT / "BaseBin/launchdhook/src/roothider.m").read_text()
        self_route = source.index('if(strcmp(path, "/sbin/launchd") == 0)')
        first_load = source.index('if(launchdhookFirstLoad)', self_route)
        self.assertLess(self_route, first_load)
        route = source[self_route:first_load]
        self.assertIn('__posix_spawn_hook(pidp, path, desc, argv, envp)', route)
        self.assertIn('prehook routing self-spawn', route)

    def test_self_spawn_match_logs_before_primitive_stash(self):
        source = (ROOT / "BaseBin/launchdhook/src/spawn_hook.c").read_text()
        match = source.index('if (!strcmp(path, executablePath))')
        stash = source.index('boomerang_stashPrimitives()', match)
        block = source[match:stash]
        self.assertIn('self-spawn hook matched', block)
        self.assertIn('roothide_bootlog', block)

    def test_reboot_request_has_persistent_boundary_markers(self):
        jbctl = (ROOT / "BaseBin/jbctl/src/main.m").read_text()
        self.assertIn('jbctl: reboot_userspace calling reboot3', jbctl)
        self.assertIn('jbctl: reboot3 returned result=%d errno=%d', jbctl)
        xpc = (ROOT / "BaseBin/libjailbreak/src/roothider/xpc_hook.m").read_text()
        self.assertIn('launchd: observed userreboot XPC', xpc)
        self.assertIn('launchd: userreboot XPC accepted', xpc)

if __name__ == '__main__':
    unittest.main()
