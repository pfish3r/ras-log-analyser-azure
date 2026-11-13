"""Render the header using the Git revision of the deployed source."""
from pathlib import Path
import re
import subprocess


def revision(root):
    # Image builds only receive HEAD and branch refs. Git credentials and
    # history are excluded from the build context.
    git = root / ".git"
    head = git / "HEAD"
    if head.is_file():
        value = head.read_text().strip()
        if value.startswith("ref: refs/heads/"):
            ref = value[5:]
            if ".." not in ref and re.fullmatch(r"refs/heads/[A-Za-z0-9_./-]+", ref):
                branch = git / ref
                if branch.is_file():
                    value = branch.read_text().strip()
                elif (git / "packed-refs").is_file():
                    for line in (git / "packed-refs").read_text().splitlines():
                        fields = line.split()
                        if len(fields) == 2 and fields[1] == ref:
                            value = fields[0]
                            break
        if re.fullmatch(r"[a-f0-9]{40,64}", value):
            return value[:8]
    if git.is_file():  # Linked worktree
        try:
            return subprocess.check_output(
                ["git", "-C", str(root), "rev-parse", "--short=8", "HEAD"],
                text=True, stderr=subprocess.DEVNULL,
            ).strip()
        except (OSError, subprocess.CalledProcessError):
            pass
    return "dev"


def stamp(content, root):
    return content.replace(b"v1.1+dev", ("v1.1+" + revision(root)).encode(), 1)


if __name__ == "__main__":
    import sys
    source, output = map(Path, sys.argv[1:])
    output.write_bytes(stamp((source / "static/index.html").read_bytes(), source))
