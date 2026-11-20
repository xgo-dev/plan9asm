#!/usr/bin/env python3

"""Replace existing Ubuntu runner mirror lists without changing source roles."""

import pathlib
import sys


def configure(apt_dir, architecture):
    if architecture in ("amd64", "i386"):
        archive = "https://archive.ubuntu.com/ubuntu/"
        security = "https://security.ubuntu.com/ubuntu/"
    else:
        archive = security = "https://ports.ubuntu.com/ubuntu-ports/"

    # Keep the source files' suites, components and signing keys, along with
    # unrelated repositories. Direct-source runners need no new mirror lists.
    for name, url in (("apt-mirrors.txt", archive),
                      ("apt-mirrors-security.txt", security)):
        path = apt_dir / name
        if path.exists():
            path.write_text(url + "\n")
    return archive


if __name__ == "__main__":
    print(configure(pathlib.Path(sys.argv[1]), sys.argv[2]))
