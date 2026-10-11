import hashlib
import importlib.util
from pathlib import Path
import tarfile
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('builder',ROOT/'scripts/build_release.py')
builder=importlib.util.module_from_spec(spec); spec.loader.exec_module(builder)


class ReleaseTests(unittest.TestCase):
    def test_runtime_and_installer_included_with_verified_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            archive=builder.build(directory)
            with tarfile.open(archive) as tar:
                names=tar.getnames()
                prefix='malsonsa-v'+(ROOT/'VERSION').read_text().strip()+'/'
                self.assertIn(prefix+'install.sh',names)
                self.assertIn(prefix+'dashboard/frontend/risk-details.js',names)
                self.assertIn(prefix+'backend/detection_rules.py',names)
                self.assertIn(prefix+'dashboard/frontend/rules.html',names)
                self.assertIn(prefix+'dashboard/frontend/rules.js',names)
                self.assertEqual(tar.getmember(prefix+'install.sh').mode,0o755)
                self.assertFalse(any(name.endswith(('.db','.key','.log')) or '.local-tools' in name for name in names))
                for line in tar.extractfile(prefix+'SHA256SUMS').read().decode().splitlines():
                    digest,name=line.split('  ',1)
                    self.assertEqual(hashlib.sha256(tar.extractfile(prefix+''+name).read()).hexdigest(),digest)


if __name__=='__main__': unittest.main()
