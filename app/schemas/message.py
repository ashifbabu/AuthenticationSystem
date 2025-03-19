from pydantic import BaseModel

class Message(BaseModel):
    """Message schema for API responses."""
    message: str 