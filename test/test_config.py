import json
import tempfile
import unittest
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
ROOT_CONFIG_FILE = ROOT_DIR / "config.json"


class ConfigLoadingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._created_root_config = False
        if not ROOT_CONFIG_FILE.exists():
            ROOT_CONFIG_FILE.write_text(json.dumps({"auth-key": "test-auth"}), encoding="utf-8")
            cls._created_root_config = True

        from services import config as config_module

        cls.config_module = config_module

    @classmethod
    def tearDownClass(cls) -> None:
        if cls._created_root_config and ROOT_CONFIG_FILE.exists():
            ROOT_CONFIG_FILE.unlink()

    def test_load_settings_ignores_directory_config_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            base_dir = Path(tmp_dir)
            data_dir = base_dir / "data"
            config_dir = base_dir / "config.json"
            os_auth_key = "env-auth"

            config_dir.mkdir()

            module = self.config_module
            old_base_dir = module.BASE_DIR
            old_data_dir = module.DATA_DIR
            old_config_file = module.CONFIG_FILE
            old_env_auth_key = module.os.environ.get("CHATGPT2API_AUTH_KEY")
            try:
                module.BASE_DIR = base_dir
                module.DATA_DIR = data_dir
                module.CONFIG_FILE = config_dir
                module.os.environ["CHATGPT2API_AUTH_KEY"] = os_auth_key

                settings = module._load_settings()

                self.assertEqual(settings.auth_key, os_auth_key)
                self.assertEqual(settings.refresh_account_interval_minute, 5)
            finally:
                module.BASE_DIR = old_base_dir
                module.DATA_DIR = old_data_dir
                module.CONFIG_FILE = old_config_file
                if old_env_auth_key is None:
                    module.os.environ.pop("CHATGPT2API_AUTH_KEY", None)
                else:
                    module.os.environ["CHATGPT2API_AUTH_KEY"] = old_env_auth_key




    def test_save_falls_back_to_data_config_when_primary_readonly(self) -> None:
        import os
        import stat
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp_dir:
            base_dir = Path(tmp_dir)
            data_dir = base_dir / "data"
            data_dir.mkdir(parents=True, exist_ok=True)
            primary = base_dir / "config.json"
            primary.write_text('{"auth-key": "test-auth", "proxy": ""}', encoding="utf-8")
            # make primary read-only
            os.chmod(primary, stat.S_IREAD)

            module = self.config_module
            old_base = module.BASE_DIR
            old_data = module.DATA_DIR
            old_config = module.CONFIG_FILE
            old_data_config = module.DATA_CONFIG_FILE
            try:
                module.BASE_DIR = base_dir
                module.DATA_DIR = data_dir
                module.CONFIG_FILE = primary
                module.DATA_CONFIG_FILE = data_dir / "config.json"
                store = module.ConfigStore(primary)
                store.update({"proxy": "http://127.0.0.1:7890", "base_url": "http://example:18083"})
                self.assertTrue((data_dir / "config.json").exists())
                # reload should pick overlay
                store2 = module.ConfigStore(primary)
                self.assertEqual(store2.get_proxy_settings(), "http://127.0.0.1:7890")
                self.assertIn("http://example:18083", store2.base_url)
            finally:
                module.BASE_DIR = old_base
                module.DATA_DIR = old_data
                module.CONFIG_FILE = old_config
                module.DATA_CONFIG_FILE = old_data_config
                try:
                    os.chmod(primary, stat.S_IWRITE | stat.S_IREAD)
                except Exception:
                    pass


if __name__ == "__main__":
    unittest.main()
