import csv
import hashlib
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from verify_publication_manifest import verify_manifest, verify_current_blobs


class ManifestGuardTests(unittest.TestCase):
    def test_repo_current_git_blob_snapshot_matches_published_bytes(self):
        report = verify_current_blobs()
        self.assertEqual(report["verified_artifacts"], 52)

    def test_original_historical_sha256_manifest_is_preserved_not_silently_rebased(self):
        with (ROOT / "manifests" / "repo-v0.1-manifest.csv").open(encoding="utf-8-sig", newline="") as stream:
            self.assertEqual(len(list(csv.DictReader(stream))), 52)

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

    def test_current_blob_guard_catches_equal_size_tampering(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / "sana" / "archive.json"
            artifact.parent.mkdir()
            artifact.write_bytes(b"original")
            manifest = root / "current.csv"
            self._write_current(manifest, "sana/archive.json", b"original")
            self.assertEqual(verify_current_blobs(root, manifest)["verified_artifacts"], 1)
            artifact.write_bytes(b"replaced")
            with self.assertRaisesRegex(ValueError, "Git blob mismatch"):
                verify_current_blobs(root, manifest)

    def test_current_blob_guard_rejects_single_backslash_in_path(self):
        # A single backslash may be a separator on Windows but a filename
        # character on POSIX: neither is a canonical Git manifest path.
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = root / "current.csv"
            self._write_current(manifest, r"sana/archive\faked.json", b"fixture")
            with self.assertRaisesRegex(ValueError, "unsafe publication path"):
                verify_current_blobs(root, manifest)

    def test_current_blob_guard_rejects_traversal(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = root / "current.csv"
            self._write_current(manifest, "sana/../../forbidden.json", b"xxx")
            with self.assertRaisesRegex(ValueError, "unsafe publication path"):
                verify_current_blobs(root, manifest)


    def test_rejects_noncanonical_and_empty_path_components(self):
        for published_path in (
            ".", "sana", "sana/", "sana//archive.json",
            "sana/./archive.json", "sana/../archive.json",
            "sana/archive.json/", "sana\\archive.json",
        ):
            with self.subTest(published_path=published_path), TemporaryDirectory() as tmp:
                root = Path(tmp)
                historical = root / "historical.csv"
                current = root / "current.csv"
                self._write(historical, published_path, b"fixture")
                self._write_current(current, published_path, b"fixture")
                with self.assertRaisesRegex(ValueError, "unsafe publication path"):
                    verify_manifest(root, historical)
                with self.assertRaisesRegex(ValueError, "unsafe publication path"):
                    verify_current_blobs(root, current)

    def test_rejects_unindexed_new_forensic_file(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            area = root / "sana"
            area.mkdir()
            (area / "indexed.txt").write_bytes(b"pinned")
            manifest = root / "current.csv"
            self._write_current(manifest, "sana/indexed.txt", b"pinned")
            self.assertEqual(verify_current_blobs(root, manifest)["verified_artifacts"], 1)
            (area / "unindexed.txt").write_bytes(b"should not be published unnoticed")
            with self.assertRaisesRegex(ValueError, "unindexed"):
                verify_current_blobs(root, manifest)

    def test_rejects_symlinked_intermediate_directory(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            real = root / "sana" / "real"
            real.mkdir(parents=True)
            (real / "artifact.json").write_bytes(b"proof")
            alias = root / "sana" / "alias"
            try:
                alias.symlink_to(real, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("Symlinks unavailable")
            manifest = root / "current.csv"
            self._write_current(manifest, "sana/alias/artifact.json", b"proof")
            with self.assertRaisesRegex(ValueError, "missing or unsafe"):
                verify_current_blobs(root, manifest)
            historical = root / "historical.csv"
            self._write(historical, "sana/alias/artifact.json", b"proof")
            with self.assertRaisesRegex(ValueError, "missing/unsafe"):
                verify_manifest(root, historical)

    @staticmethod
    def _write_current(manifest, path, content):
        checksum = hashlib.sha1(b"blob " + str(len(content)).encode() + b"\x00" + content).hexdigest()
        with manifest.open("w", encoding="utf-8", newline="") as file:
            writer = csv.DictWriter(file, fieldnames=["PublishedPath", "GitBlobSHA1"])
            writer.writeheader()
            writer.writerow({"PublishedPath": path, "GitBlobSHA1": checksum})

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
