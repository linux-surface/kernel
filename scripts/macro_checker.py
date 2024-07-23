#!/usr/bin/python3
# SPDX-License-Identifier: GPL-2.0
# Author: Julian Sun <sunjunchao2870@gmail.com>

""" Find macro definitions with unused parameters. """

import argparse
import os
import re

macro_pattern = r"#define\s+(\w+)\(([^)]*)\)"
# below two vars were used to reduce false positives
do_while0_pattern = r"\s*do\s*\{\s*\}\s*while\s*\(\s*0\s*\)"
correct_macros = []

def check_macro(macro_line, report):
    match = re.match(macro_pattern, macro_line)
    if match:
        macro_def = re.sub(macro_pattern, '', macro_line)
        identifier = match.group(1)
        content = match.group(2)
        arguments = [item.strip() for item in content.split(',') if item.strip()]

        if (re.match(do_while0_pattern, macro_def)):
            return

        for arg in arguments:
            # used to reduce false positives
            if "..." in arg:
                continue
            if not arg in macro_def and report == False:
                return
            if not arg in macro_def and identifier not in correct_macros:
                print(f"Argument {arg} is not used in function-line macro {identifier}")
                return

        correct_macros.append(identifier)


# remove comment and whitespace
def macro_strip(macro):
    comment_pattern1 = r"\/\/*"
    comment_pattern2 = r"\/\**\*\/"

    macro = macro.strip()
    macro = re.sub(comment_pattern1, '', macro)
    macro = re.sub(comment_pattern2, '', macro)

    return macro

def file_check_macro(file_path, report):
    # only check .c and .h file
    if not file_path.endswith(".c") and not file_path.endswith(".h"):
        return

    with open(file_path, "r") as f:
        while True:
            line = f.readline()
            if not line:
                return

            macro = re.match(macro_pattern, line)
            if macro:
                macro = macro_strip(macro.string)
                while macro[-1] == '\\':
                    macro = macro[0:-1]
                    macro = macro.strip()
                    macro += f.readline()
                    macro = macro_strip(macro)
                check_macro(macro, report)

def get_correct_macros(path):
    file_check_macro(path, False)

def dir_check_macro(dir_path):

    for dentry in os.listdir(dir_path):
        path = os.path.join(dir_path, dentry)
        if os.path.isdir(path):
            dir_check_macro(path)
        elif os.path.isfile(path):
            get_correct_macros(path)
            file_check_macro(path, True)


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("path", type=str, help="The file or dir path that needs check")
    args = parser.parse_args()

    if os.path.isfile(args.path):
        get_correct_macros(args.path)
        file_check_macro(args.path, True)
    elif os.path.isdir(args.path):
        dir_check_macro(args.path)
    else:
        print(f"{args.path} doesn't exit or is neither a file nor a dir")

if __name__ == "__main__":
    main()