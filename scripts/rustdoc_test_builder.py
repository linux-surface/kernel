#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""rustdoc_test_builder - Test builder for `rustdoc`-generated tests.
"""

import json
import pathlib
import re
import sys

RUST_DIR = pathlib.Path("rust")
TESTS_DIR = RUST_DIR / "test" / "doctests" / "kernel"

# `[^\s]*` removes the prefix (e.g. `_doctest_main_`) plus any
# leading path (for `O=` builds).
MAIN_RE = re.compile(
    r"^"
    r"fn main\(\) { "
    r"#\[allow\(non_snake_case\)\] "
    r"fn ([^\s]*rust_kernel_([a-zA-Z0-9_]+))\(\) {"
    r"$"
)

def main():
    found_main = False
    test_header = ""
    test_body = ""
    for line in sys.stdin.readlines():
        main_match = MAIN_RE.match(line)
        if main_match:
            if found_main:
                raise Exception("More than one `main` line found.")
            found_main = True
            function_name = main_match.group(1)
            test_name = f"rust_kernel_doctest_{main_match.group(2)}"
            continue

        if found_main:
            test_body += line
        else:
            test_header += line

    if not found_main:
        raise Exception("No `main` line found.")

    call_line = f"}} {function_name}() }}"
    if not test_body.endswith(call_line):
        raise Exception("Unexpected end of test body.")
    test_body = test_body[:-len(call_line)]

    with open(TESTS_DIR / f"{test_name}.json", "w") as fd:
        json.dump({
            "name": test_name,
            "header": test_header,
            "body": test_body,
        }, fd, sort_keys=True, indent=4)

if __name__ == "__main__":
    main()
