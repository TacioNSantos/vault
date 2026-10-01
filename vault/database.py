from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, declarative_base
from vault import config

engine = create_engine(config.DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def is_database_in_recovery() -> bool:
    """Verifica se o PostgreSQL esta operando em modo recovery (standby / read-only)."""
    try:
        with engine.connect() as conn:
            result = conn.execute(text("SELECT pg_is_in_recovery()")).scalar()
            return bool(result)
    except Exception:
        return False
