"""SprayBiclique package."""

from .api import app
from .meta import AUTHOR, VERSION

__version__ = VERSION
__author__ = AUTHOR

__all__ = ["app", "__version__", "__author__"]
