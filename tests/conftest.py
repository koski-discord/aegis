import os

os.environ.setdefault("AEGIS_CONFIG_FILE", "tests/missing-config.json")
os.environ.setdefault("AEGIS_ENVIRONMENT", "testing")
os.environ.setdefault("AEGIS_DATABASE_URL", "sqlite+aiosqlite:///./test.db")
os.environ.setdefault("AEGIS_TRUSTED_HOSTS", '["testserver","localhost","127.0.0.1"]')
