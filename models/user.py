from sqlalchemy import Column, Integer, String

# Import the Base from the database module
from db.database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)

    # 25-12-2025 - Added Users Name
    name = Column(String, index=True)

    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)