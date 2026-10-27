"""Test fixtures for ps011 tests."""

import tempfile
from pathlib import Path
import pytest

SAMPLE_SCOPE_YAML = """
scope:
  domains:
    - lab.internal
    - example.com
  hosts:
    - hostname: www.lab.internal
      ports: [80, 443]
    - hostname: mail.lab.internal
      ports: [25, 143, 993]
checks:
  - C1: tcp_connect
  - C2: banner_identify
  - C3: tls_inspect
  - C4: http_head
discovery:
  allowed_labels: [www, api, mail, dev]
  max_candidates: 50
limits:
  max_rps: 20
  per_host_concurrency: 2
  timeout_s: 5
"""

SCOPE_LOCALHOST_YAML = """
scope:
  domains:
    - localhost
  hosts:
    - hostname: localhost
      ports: [8080, 443]
checks:
  - C1: tcp_connect
limits:
  max_rps: 20
  per_host_concurrency: 2
  timeout_s: 5
"""


@pytest.fixture
def sample_scope_file(tmp_path: Path) -> Path:
    """Fixture providing a temporary scope.yaml configuration file."""
    scope_file = tmp_path / "sample_scope.yaml"
    scope_file.write_text(SAMPLE_SCOPE_YAML, encoding="utf-8")
    return scope_file


@pytest.fixture
def sample_scope_with_localhost(tmp_path: Path) -> Path:
    """Fixture providing a temporary scope.yaml with localhost ports."""
    scope_file = tmp_path / "scope_localhost.yaml"
    scope_file.write_text(SCOPE_LOCALHOST_YAML, encoding="utf-8")
    return scope_file


@pytest.fixture
def audit_log_sink(tmp_path: Path):
    """Fixture providing an AuditLogSink with temp file."""
    from ps011.sinks.audit_log import AuditLogSink
    log_file = tmp_path / "audit.jsonl"
    sink = AuditLogSink(str(log_file))
    return sink


@pytest.fixture
def db_setup(request):
    """Setup temp database for tests - isolated per test using file-based SQLite."""
    import ps011.models.db as db_module
    import tempfile
    import os
    import uuid
    
    db_module._db = None  # Reset global before each test
    
    # Use unique temporary file for each test
    unique_id = uuid.uuid4().hex[:8]
    test_name = request.node.name
    db_filename = f"ps011_test_{test_name}_{unique_id}.db"
    db_path = os.path.join(tempfile.gettempdir(), db_filename)
    # Convert to proper file URI for SQLAlchemy
    db_url = f"sqlite:///{db_path.replace(os.sep, '/')}"
    
    db = db_module.Database(db_url)
    db.init_db()
    yield db
    
    # Cleanup: dispose engine before removing file
    if db._engine:
        db._engine.dispose()
    db_module._db = None
    
    # Force garbage collection and try to remove the file
    import gc
    gc.collect()
    
    # Try multiple times to remove the file (Windows file locking)
    for _ in range(3):
        try:
            os.unlink(db_path)
            break
        except OSError:
            import time
            time.sleep(0.1)