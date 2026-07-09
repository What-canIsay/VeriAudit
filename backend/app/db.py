"""Database engine / session (SQLAlchemy 2.0, SQLite by default)."""
from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from .config import settings

_IS_SQLITE = settings.database_url.startswith("sqlite")
connect_args = {"check_same_thread": False} if _IS_SQLITE else {}
engine = create_engine(settings.database_url, connect_args=connect_args, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)

if _IS_SQLITE:
    # WAL lets API reads (e.g. /findings) run concurrently with the audit's heavy writes
    # instead of being blocked — without this, a running deep audit starves read endpoints
    # (the console's findings/counts appear stalled). busy_timeout waits for a lock instead
    # of erroring; synchronous=NORMAL is durable enough with WAL and much faster under load.
    @event.listens_for(engine, "connect")
    def _sqlite_pragmas(dbapi_conn, _rec):  # pragma: no cover
        cur = dbapi_conn.cursor()
        try:
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA busy_timeout=10000")
            cur.execute("PRAGMA synchronous=NORMAL")
        finally:
            cur.close()


class Base(DeclarativeBase):
    pass


def init_db() -> None:
    from . import models  # noqa: F401  (register mappers)
    Base.metadata.create_all(bind=engine)


@contextmanager
def session_scope() -> Iterator[Session]:
    """Transactional session for use inside background tasks."""
    s = SessionLocal()
    try:
        yield s
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()


def get_db() -> Iterator[Session]:
    """FastAPI dependency."""
    s = SessionLocal()
    try:
        yield s
    finally:
        s.close()
