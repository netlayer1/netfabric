"""
database.py — SQLAlchemy setup
PostgreSQL via DATABASE_URL environment variable
"""

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase

DATABASE_URL = os.environ["DATABASE_URL"]

engine = create_engine(DATABASE_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


def get_db():
    """FastAPI dependency — yields a DB session, always closes after request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
