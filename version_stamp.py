"""Insert the project release number into a page served or packaged locally."""
import re
import sys
from pathlib import Path


def stamp(content, root):
    version = (root / "VERSION").read_text(encoding="ascii").strip()
    if not re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", version):
        raise ValueError("VERSION must contain a numeric major.minor.patch release")
    return content.replace(b"__APP_VERSION__", ("v" + version).encode("ascii"), 1)


if __name__ == "__main__":
    source, output = map(Path, sys.argv[1:])
    output.write_bytes(stamp((source / "static/index.html").read_bytes(), source))
