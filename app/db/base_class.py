from typing import Any
from sqlalchemy.ext.declarative import declarative_base, declared_attr


class CustomBase:
    # Generate __tablename__ automatically based on class name
    @declared_attr
    def __tablename__(cls) -> str:
        return cls.__name__.lower()


Base = declarative_base(cls=CustomBase) 