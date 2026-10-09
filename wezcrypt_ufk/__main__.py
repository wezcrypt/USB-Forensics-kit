"""Entry point: `python -m wezcrypt_ufk` (GUI when no arguments, CLI otherwise)."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
