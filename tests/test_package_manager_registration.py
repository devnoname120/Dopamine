import pathlib
import plistlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
BOOTSTRAPPER = ROOT / "Application/Dopamine/Jailbreak/DOBootstrapper.m"
PKG_MANAGERS = ROOT / "Application/Dopamine/UI/PkgManagers/PkgManagers.plist"


class PackageManagerRegistrationTests(unittest.TestCase):
    def test_package_manager_metadata_names_the_installed_application_bundle(self):
        managers = plistlib.loads(PKG_MANAGERS.read_bytes())
        self.assertGreater(len(managers), 0)
        for manager in managers:
            with self.subTest(manager=manager.get("Key")):
                application = manager.get("Application")
                self.assertIsInstance(application, str)
                self.assertTrue(application.endswith(".app"))

    def test_finalization_refreshes_only_enabled_present_package_manager_apps(self):
        source = BOOTSTRAPPER.read_text()
        self.assertIn("- (NSError *)refreshJailbreakAppRegistrations", source)
        helper = source[
            source.index("- (NSError *)refreshJailbreakAppRegistrations") :
            source.index("- (BOOL)shouldInstallPackage", source.index("- (NSError *)refreshJailbreakAppRegistrations"))
        ]
        self.assertIn("enabledPackageManagers", helper)
        self.assertIn('packageManagerDict[@"Application"]', helper)
        self.assertIn("jbrootPrefix", helper)
        self.assertIn("fileExistsAtPath", helper)
        self.assertIn('JBROOT_PATH("/usr/bin/uicache")', helper)
        self.assertIn('"-p"', helper)
        self.assertNotIn("availablePackageManagers", helper)

    def test_roothide_manager_is_refreshed_separately_and_every_finalize_calls_helper(self):
        source = BOOTSTRAPPER.read_text()
        helper_start = source.index("- (NSError *)refreshJailbreakAppRegistrations")
        helper_end = source.index("- (BOOL)shouldInstallPackage", helper_start)
        helper = source[helper_start:helper_end]
        self.assertIn('@"/Applications/RootHide.app"', helper)

        active = source.rsplit("- (NSError *)finalizeBootstrap", 1)[1]
        call = "[self refreshJailbreakAppRegistrations]"
        self.assertIn(call, active)
        self.assertGreater(active.index(call), active.index("/usr/libexec/updatelinks.sh"))
        self.assertLess(active.index(call), active.index("return nil;"))


if __name__ == "__main__":
    unittest.main()
