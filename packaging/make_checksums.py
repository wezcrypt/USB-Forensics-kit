"""Writes SHA256SUMS.txt for every file of the portable distribution (verify the kit itself before use)."""

import hashlib
import os
import sys


def main(root: str) -> int:
    out = os.path.join(root, "SHA256SUMS.txt")
    lines = []
    for dirpath, dirs, files in os.walk(root):
        dirs.sort()
        for name in sorted(files):
            path = os.path.join(dirpath, name)
            if os.path.abspath(path) == os.path.abspath(out):
                continue
            h = hashlib.sha256()
            with open(path, "rb") as fh:
                for block in iter(lambda: fh.read(1 << 20), b""):
                    h.update(block)
            lines.append(f"{h.hexdigest()}  {os.path.relpath(path, root).replace(os.sep, '/')}")
    with open(out, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines) + "\n")
    print(f"{len(lines)} files hashed -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else os.path.join("dist", "WezCryptUFK")))
