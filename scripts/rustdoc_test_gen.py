#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""rustdoc_test_gen - Generates KUnit tests from saved `rustdoc`-generated tests.
"""

import json
import os
import pathlib

RUST_DIR = pathlib.Path("rust")
TESTS_DIR = RUST_DIR / "test" / "doctests" / "kernel"

RUST_FILE = RUST_DIR / "doctests_kernel_generated.rs"
C_FILE = RUST_DIR / "doctests_kernel_generated_kunit.c"

RUST_TEMPLATE_TEST = """
/// Generated `{test_name}` KUnit test case from a Rust documentation test.
#[no_mangle]
pub fn {test_name}(__kunit_test: *mut kernel::bindings::kunit) {{
    /// Provides mutual exclusion (see `# Implementation` notes).
    static __KUNIT_TEST_MUTEX: kernel::sync::smutex::Mutex<()> =
        kernel::sync::smutex::Mutex::new(());

    /// Saved argument (see `# Implementation` notes).
    static __KUNIT_TEST: core::sync::atomic::AtomicPtr<kernel::bindings::kunit> =
        core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

    let __kunit_test_mutex_guard = __KUNIT_TEST_MUTEX.lock();
    __KUNIT_TEST.store(__kunit_test, core::sync::atomic::Ordering::SeqCst);

    /// Overrides the usual [`assert!`] macro with one that calls KUnit instead.
    macro_rules! assert {{
        ($cond:expr $(,)?) => {{{{
            kernel::kunit_assert!(
                __KUNIT_TEST.load(core::sync::atomic::Ordering::SeqCst),
                $cond
            );
        }}}}
    }}

    /// Overrides the usual [`assert_eq!`] macro with one that calls KUnit instead.
    macro_rules! assert_eq {{
        ($left:expr, $right:expr $(,)?) => {{{{
            kernel::kunit_assert_eq!(
                __KUNIT_TEST.load(core::sync::atomic::Ordering::SeqCst),
                $left,
                $right
            );
        }}}}
    }}

    // Many tests need the prelude, so provide it by default.
    use kernel::prelude::*;

    {test_body}
}}
"""
RUST_TEMPLATE = """// SPDX-License-Identifier: GPL-2.0

//! `kernel` crate documentation tests.

// # Implementation
//
// KUnit gives us a context in the form of the `kunit_test` parameter that one
// needs to pass back to other KUnit functions and macros.
//
// However, we want to keep this as an implementation detail because:
//
//   - Test code should not care about the implementation.
//
//   - Documentation looks worse if it needs to carry extra details unrelated
//     to the piece being described.
//
//   - Test code should be able to define functions and call them, without
//     having to carry the context (since functions cannot capture dynamic
//     environment).
//
//   - Later on, we may want to be able to test non-kernel code (e.g. `core`,
//     `alloc` or external crates) which likely use the standard library
//     `assert*!` macros.
//
// For this reason, `static`s are used in the generated code to save the
// argument which then gets read by the asserting macros. These macros then
// call back into KUnit, instead of panicking.
//
// To avoid depending on whether KUnit allows to run tests concurrently and/or
// reentrantly, we ensure mutual exclusion on our end. To ensure a single test
// being killed does not trigger failure of every other test (timing out),
// we provide different `static`s per test (which also allow for concurrent
// execution, though KUnit runs them sequentially).
//
// Furthermore, since test code may create threads and assert from them, we use
// an `AtomicPtr` to hold the context (though each test only writes once before
// threads may be created).

{rust_header}

const __LOG_PREFIX: &[u8] = b"rust_kernel_doctests\\0";

{rust_tests}
"""

C_TEMPLATE_TEST_DECLARATION = "void {test_name}(struct kunit *);\n"
C_TEMPLATE_TEST_CASE = "    KUNIT_CASE({test_name}),\n"
C_TEMPLATE = """// SPDX-License-Identifier: GPL-2.0
/*
 * `kernel` crate documentation tests.
 */

#include <kunit/test.h>

{c_test_declarations}

static struct kunit_case test_cases[] = {{
    {c_test_cases}
    {{ }}
}};

static struct kunit_suite test_suite = {{
    .name = "rust_kernel_doctests",
    .test_cases = test_cases,
}};

kunit_test_suite(test_suite);

MODULE_LICENSE("GPL");
"""

def main():
    rust_header = set()
    rust_tests = ""
    c_test_declarations = ""
    c_test_cases = ""
    for filename in sorted(os.listdir(TESTS_DIR)):
        with open(TESTS_DIR / filename, "r") as fd:
            test = json.load(fd)
            for line in test["header"].strip().split("\n"):
                rust_header.add(line)
            rust_tests += RUST_TEMPLATE_TEST.format(
                test_name = test["name"],
                test_body = test["body"]
            )
            c_test_declarations += C_TEMPLATE_TEST_DECLARATION.format(
                test_name = test["name"]
            )
            c_test_cases += C_TEMPLATE_TEST_CASE.format(
                test_name = test["name"]
            )
    rust_header = sorted(rust_header)

    with open(RUST_FILE, "w") as fd:
        fd.write(RUST_TEMPLATE.format(
            rust_header = "\n".join(rust_header).strip(),
            rust_tests = rust_tests.strip(),
        ))

    with open(C_FILE, "w") as fd:
        fd.write(C_TEMPLATE.format(
            c_test_declarations=c_test_declarations.strip(),
            c_test_cases=c_test_cases.strip(),
        ))

if __name__ == "__main__":
    main()
