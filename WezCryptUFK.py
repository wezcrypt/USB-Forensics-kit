"""PyInstaller entry script for the portable executable."""

import multiprocessing
import sys

from wezcrypt_ufk.cli import main

if __name__ == "__main__":
    multiprocessing.freeze_support()
    sys.exit(main())
