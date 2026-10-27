"""Database initialization and session management for PS-011."""

from contextlib import contextmanager
from pathlib import Path
from typing import Generator, Optional
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import NullPool

from ps011.models.schema import Base


class Database:
    """Database manager with SQLite WAL mode support."""

    def __init__(self, db_path: str = "ps011/data/ps011.db") -> None:
        """Initialize database manager.

        Args:
            db_path: Path to SQLite database file or 'sqlite:///:memory:' for in-memory.
        """
        self.db_url = db_path
        self._engine: Optional[Engine] = None
        self._session_factory: Optional[sessionmaker] = None

        # Only create directory for file-based databases
        if not db_path.startswith("sqlite:///:memory:") and not db_path.startswith("sqlite://"):
            self.db_path = Path(db_path)
            self.db_path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def engine(self) -> Engine:
        """Get or create SQLAlchemy engine with WAL mode."""
        if self._engine is None:
            # Handle file paths properly - convert to sqlite:/// URL format
            if self.db_url.startswith("sqlite://"):
                engine_url = self.db_url
            else:
                # Assume it's a file path, convert to proper URL
                engine_url = f"sqlite:///{self.db_url}"
            
            self._engine = create_engine(
                engine_url,
                connect_args={"check_same_thread": False},
                pool_pre_ping=True,
                future=True,
                poolclass=NullPool,
            )
            # Enable WAL mode and foreign keys (only for file-based databases)
            if not engine_url.startswith("sqlite:///:memory:"):
                with self._engine.begin() as conn:
                    conn.execute(text("PRAGMA journal_mode=WAL"))
                    conn.execute(text("PRAGMA foreign_keys=ON"))
            else:
                # For in-memory, just enable foreign keys
                with self._engine.begin() as conn:
                    conn.execute(text("PRAGMA foreign_keys=ON"))
        return self._engine

    @property
    def session_factory(self) -> sessionmaker:
        """Get or create session factory."""
        if self._session_factory is None:
            self._session_factory = sessionmaker(
                bind=self.engine, expire_on_commit=False, future=True
            )
        return self._session_factory

    def init_db(self) -> None:
        """Create all tables."""
        Base.metadata.create_all(self.engine)

    def get_session(self) -> Session:
        """Return a new SQLAlchemy session."""
        return self.session_factory()

    @contextmanager
    def session(self) -> Generator[Session, None, None]:
        """Context manager for session lifecycle with auto-commit/rollback."""
        sess = self.get_session()
        try:
            yield sess
            sess.commit()
        except Exception:
            sess.rollback()
            raise
        finally:
            sess.close()

    def verify_wal_mode(self) -> bool:
        """Verify WAL mode is enabled.

        Returns:
            True if WAL mode is active.
        """
        with self.engine.connect() as conn:
            result = conn.execute(text("PRAGMA journal_mode")).scalar()
            return result.upper() == "WAL"

    def get_table_names(self) -> list[str]:
        """Get list of table names in the database."""
        from sqlalchemy import inspect

        inspector = inspect(self.engine)
        return inspector.get_table_names()


# Global singleton instance
_db: Optional[Database] = None


def get_db(db_path: str = "ps011/data/ps011.db") -> Database:
    """Get global database instance (singleton pattern).

    Args:
        db_path: Path to database file (used only on first call).

    Returns:
        Database instance.
    """
    global _db
    if _db is None:
        _db = Database(db_path)
    return _db


def reset_db() -> None:
    """Reset global database instance (for testing)."""
    global _db
    _db = None