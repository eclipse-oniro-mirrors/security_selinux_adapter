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
from collections import defaultdict
from check_common import read_file, traverse_file_in_each_type

WHITELIST_FILE_NAME = "partition_label_use_whitelist.txt"


def check_file_contexts(args, file_contexts, whitelist_map, label_list):
    label_list_set = set()
    for it in label_list:
        label_list_set.add(it)

    line_index = 0
    err = False
    for line in file_contexts:
        line_index += 1
        elements = line.split()
        if len(elements) < 2:
            continue
        path = elements[0]
        label = elements[1]
        if label in label_list_set:
            if path in whitelist_map[label]:
                continue
            print("partition label is not allow to use,",
                  "check '{} {}' failed in file {}:{}\n".format(path, label, args.file_contexts, line_index),
                  "There are two solutions:\n",
                  "1. Add '{} {}' to whitelist file \'{}\' under \'{}\';\n".format(
                        path, label, WHITELIST_FILE_NAME, args.policy_dir_list),
                  "2. Change '{} {}' to avoid using label in {}\n".format(path, label, label_list))
            err = True
    if err:
        raise Exception(-1)


def get_whitelist(args):
    whitelist_file_list = traverse_file_in_each_type(args.policy_dir_list, WHITELIST_FILE_NAME)
    whitelist_map = defaultdict(list)
    for path in whitelist_file_list:
        whitelist = read_file(path)
        for it in whitelist:
            split_str = it.split()
            if len(split_str) < 2:
                continue
            whitelist_map[split_str[1]].append(split_str[0])
    return whitelist_map


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--file_contexts', help='the file_contexts file path', required=True)
    parser.add_argument(
        '--policy-dir-list', help='the whitelist path list', required=True)
    parser.add_argument(
        '--config', help='the config file path', required=True)
    return parser.parse_args()


if __name__ == "__main__":
    input_args = parse_args()
    script_path = os.path.dirname(os.path.realpath(__file__))
    whitelist_data = get_whitelist(input_args)

    label_path = os.path.join(script_path, input_args.config)
    label_data = read_file(label_path)

    file_contexts_data = read_file(input_args.file_contexts)
    check_file_contexts(input_args, file_contexts_data, whitelist_data, label_data)
