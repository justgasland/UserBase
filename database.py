from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from config import Config

engine = create_engine(Config.DATABASE_URL, echo=True)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False
)

Base = declarative_base()