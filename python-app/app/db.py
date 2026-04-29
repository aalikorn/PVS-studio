import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from flask import g

DATABASE_URI = os.getenv("DATABASE_URL", "postgresql://user:password@db:5432/vuln_db")

engine = create_engine(DATABASE_URI)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    if 'db' not in g:
        g.db = SessionLocal()
    return g.db

def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db(app):
    app.teardown_appcontext(close_db)
