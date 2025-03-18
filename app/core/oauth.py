from enum import Enum

class OAuthProvider(str, Enum):
    """
    Supported OAuth providers.
    """
    GOOGLE = "google"
    GITHUB = "github" 