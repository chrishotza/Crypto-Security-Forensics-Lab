import csv
import hashlib
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from verify_publication_manifest import verify_manifest


class ManifestGuardTests(unittest.TestCase):
    def test_repo_archived_manifest_unchanged(self):
        report = verify_manifest()
        self.assertEqual(report["verified_artifacts"], 52)

    def test_rejects_modified_evidence(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / "sana" / "research.txt"
            artifact.parent.mkdir()
            artifact.write_bytes(b"original")
            manifest = root / "manifest.csv"
            self._write(manifest, "sana/research.txt", b"original")
            self.assertEqual(verify_manifest(root, manifest)["verified_artifacts"], 1)
            artifact.write_bytes(b"changed!")
            with self.assertRaisesRegex(ValueError, "size mismatch|SHA256 mismatch"):
                verify_manifest(root, manifest)

    def test_rejects_path_traversal(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = root / "manifest.csv"
            self._write(manifest, "sana/../../private.txt", b"private")
            with self.assertRaisesRegex(ValueError, "unsafe publication path"):
                verify_manifest(root, manifest)

    @staticmethod
    def _write(manifest, path, content):
        with manifest.open("w", encoding="utf-8", newline="") as file:
            writer = csv.DictWriter(
                file, fieldnames=["PublishedPath", "Size", "SHA256", "HashBasis"]
            )
            writer.writeheader()
            writer.writerow({
                "PublishedPath": path, "Size": len(content),
                "SHA256": hashlib.sha256(content).hexdigest(),
                "HashBasis": "published_content_sha256",
            })


if __name__ == "__main__":
    unittest.main()
