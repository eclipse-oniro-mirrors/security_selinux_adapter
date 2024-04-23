#!/usr/bin/env python
# coding: utf-8

"""
Copyright (c) 2023 Huawei Device Co., Ltd.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

"""

import argparse
import os
import re
from check_common import read_file, traverse_file_in_each_type

WHITELIST_FILE_NAME = "data_regex_whitelist.txt"


def check_regex_path(path):
    # remove all escape
    path = re.sub(r'\\\\', '', path)
    path = re.sub(r'\\/', '/', path)

    path_elements = path.split('/')
    second_dir_name = path_elements[2]

    # remove all escape
    replace_str = re.sub(r'\\[\$\(\)\*\+\.\[\]\?\\\^\{\}\|]', '', second_dir_name)

    # find special characters that have not been escaped
    return re.search(r'[\$\(\)\*\+\.\[\]\?\\\^\{\}\|]', replace_str)


def check_file_contexts(args, file_contexts, whitelist_set):
    line_index = 0
    err = False
    for line in file_contexts:
        line_index += 1
        split_list = line.split(None, 1)
        if len(split_list) == 0:
            continue
        path = split_list[0]
        normalize_path = os.path.normpath(path)
        if normalize_path.startswith("/data/"):
            if path in whitelist_set:
                continue
            if not check_regex_path(normalize_path):
                continue
            print("Regex is not allowed in the secondary directory under data,",
                "check '{}' failed in file {}:{}\n".format(path, args.file_contexts, line_index),
                "There are two solutions:\n",
                "1. Add '{}' to whitelist file \'{}\' under \'{}\';\n".format(
                    path, WHITELIST_FILE_NAME, args.policy_dir_list),
                "2. Modify '{}' to remove the regular expression\n".format(path))
            err = True
    if err:
        raise Exception(-1)


def get_whitelist(args):
    whitelist_file_list = traverse_file_in_each_type(args.policy_dir_list, WHITELIST_FILE_NAME)
    whitelist_set = set()
    for path in whitelist_file_list:
        whitelist = read_file(path)
        for it in whitelist:
            whitelist_set.add(it)
    return whitelist_set


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--file_contexts', help='the file_contexts file path', required=True)
    parser.add_argument(
        '--policy-dir-list', help='the whitelist path list', required=True)
    return parser.parse_args()


if __name__ == "__main__":
    input_args = parse_args()
    script_path = os.path.dirname(os.path.realpath(__file__))
    whitelist_data = get_whitelist(input_args)

    file_contexts_data = read_file(input_args.file_contexts)
    check_file_contexts(input_args, file_contexts_data, whitelist_data)
