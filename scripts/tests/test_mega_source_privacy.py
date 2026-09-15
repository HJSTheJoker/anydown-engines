"""Source bundles preserve code and notices while excluding local profiles."""
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from collect_notices import archive_tree


class SourcePrivacyTests(unittest.TestCase):
    def test_local_config_and_secrets_do_not_enter_corresponding_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "source"
            names = ["resources/config/downloads.db", "resources/config/downloads.db-wal",
                     "resources/config/downloads.db-shm", "resources/config/settings.json",
                     "resources/config/cookies/session.txt", ".env", ".build/release.pem",
                     "resources/config/i18n/en.json", "src/Engine.java", "LICENSE"]
            for name in names:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("synthetic fixture")
            archive = Path(directory) / "source.tar.gz"
            archive_tree(root, archive, "engine")
            with tarfile.open(archive) as contents:
                self.assertEqual(set(contents.getnames()), {
                    "engine/resources/config/i18n/en.json", "engine/src/Engine.java", "engine/LICENSE"
                })
