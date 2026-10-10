import copy
import importlib.util
import io
from pathlib import Path
import stat
import unittest
import zipfile

spec = importlib.util.spec_from_file_location('signer', Path(__file__).parent / 'sign_ipa.py')
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)


class SigningTests(unittest.TestCase):
    def setUp(self):
        self.profile = {'ApplicationIdentifierPrefix': ['NEW'], 'TeamIdentifier': ['TEAM'],
                        'Entitlements': {'application-identifier': 'NEW.com.example.*',
                                         'com.apple.developer.team-identifier': 'TEAM',
                                         'get-task-allow': False, 'keychain-access-groups': ['NEW.*']}}

    def test_rebind_identity_and_keychain(self):
        result = s.make_entitlements({'application-identifier': 'OLD.com.example.app',
                                     'keychain-access-groups': ['OLD.com.example.app']},
                                    self.profile, 'com.example.app')
        self.assertEqual(result['application-identifier'], 'NEW.com.example.app')
        self.assertEqual(result['keychain-access-groups'], ['NEW.com.example.app'])
        self.assertFalse(result['get-task-allow'])

    def test_reject_bundle_mismatch(self):
        with self.assertRaises(s.ValidationError):
            s.make_entitlements({}, self.profile, 'org.other.app')

    def test_do_not_silently_drop_capabilities(self):
        with self.assertRaises(s.ValidationError):
            s.make_entitlements({'aps-environment': 'production'}, self.profile, 'com.example.app')

    def test_profile_does_not_add_unrequested_capabilities(self):
        profile = copy.deepcopy(self.profile)
        profile['Entitlements']['aps-environment'] = 'production'
        self.assertNotIn('aps-environment', s.make_entitlements({}, profile, 'com.example.app'))

    def test_array_grants_require_every_element(self):
        self.assertTrue(s.allowed(['a.one', 'a.two'], ['a.*']))
        self.assertFalse(s.allowed(['a.one', 'b.two'], ['a.*']))
        self.assertFalse(s.allowed(True, 1))

    def validate_zip(self, names, symlink=False):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, 'w') as archive:
            for name in names:
                info = zipfile.ZipInfo(name)
                if symlink:
                    info.external_attr = (stat.S_IFLNK | 0o777) << 16
                archive.writestr(info, b'data')
        stream.seek(0)
        with zipfile.ZipFile(stream) as archive:
            s.inspect_zip(archive)

    def test_reject_traversal_absolute_and_backslash_paths(self):
        for name in ['Payload/../../outside', '/outside', 'Payload\\..\\outside']:
            with self.subTest(name=name), self.assertRaises(s.ValidationError):
                self.validate_zip([name])

    def test_reject_symlink(self):
        with self.assertRaises(s.ValidationError):
            self.validate_zip(['Payload/app.app/link'], symlink=True)

    def test_reject_case_collision(self):
        with self.assertRaises(s.ValidationError):
            self.validate_zip(['Payload/app.app/A', 'Payload/app.app/a'])

    def test_valid_archive_with_export_metadata(self):
        self.validate_zip(['Payload/app.app/Info.plist', 'iTunesMetadata.plist'])

    def test_reject_oversize_archive(self):
        class Archive:
            def infolist(self):
                item = zipfile.ZipInfo('Payload/app.app/large')
                item.file_size = s.MAX_SIZE + 1
                return [item]
        with self.assertRaises(s.ValidationError):
            s.inspect_zip(Archive())


if __name__ == '__main__':
    unittest.main()
