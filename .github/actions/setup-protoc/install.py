"""Verify and unpack a pinned protoc release.

Separate from action.yml on purpose: an inline script inside a YAML block scalar has to
be indented consistently, and a single unindented line silently ends the block and breaks
the whole file. It also cost a debugging round when written inline.

Python rather than sha256sum + unzip because both runners ship Python, while `unzip` is
NOT reliably present in Git Bash on windows-latest -- and a missing tool here would
surface as a confusing Rust build failure two steps later rather than as "unzip missing".

THE CHECKSUM IS CHECKED BEFORE ANYTHING IS EXTRACTED OR RUN. That ordering is the point
(T16): the same reasoning as the Gradle wrapper's distributionSha256Sum, and as verifying
a release signature before parsing the manifest.
"""

import hashlib
import os
import pathlib
import sys
import zipfile


def main() -> int:
    archive, want, dest = sys.argv[1], sys.argv[2], sys.argv[3]

    got = hashlib.sha256(pathlib.Path(archive).read_bytes()).hexdigest()
    if got != want:
        # ::error:: makes it a GitHub annotation rather than a line in a 900-line log.
        print(f"::error::protoc checksum mismatch. want={want} got={got}")
        return 1
    print(f"checksum ok: {got}")

    with zipfile.ZipFile(archive) as z:
        z.extractall(dest)

    # Zip archives carry no POSIX permission bits, so an extracted protoc is not
    # executable on Linux. Silent on Windows, fatal on Ubuntu.
    binary = os.path.join(dest, "bin", "protoc")
    if os.path.exists(binary):
        os.chmod(binary, 0o755)
        print(f"extracted: {binary}")
    else:
        print(f"::error::protoc binary not found at {binary} after extraction")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
