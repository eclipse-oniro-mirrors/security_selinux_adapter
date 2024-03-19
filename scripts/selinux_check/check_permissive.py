#!/usr/bin/env python
# coding: utf-8

"""
Copyright (c) 2024 Huawei Device Co., Ltd.
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
from check_common import read_json_file, traverse_file_in_each_type

WHITELIST_FILE_NAME = "permissive_whitelist.json"


def simplify_string(string):
    return string.strip().replace('(', '').replace(')', '')


def deal_with_allow(cil_file, allow_set):
    with open(cil_file, 'r', encoding='utf-8') as cil_read:
        for line in cil_read:
            if not line.startswith('(typepermissive '):
                continue
            sub_string = simplify_string(line)
            elem_list = sub_string.split(' ')
            # (typepermissive xx)
            if len(elem_list) < 2:
                continue
            split_attribute(elem_list, allow_set)


def split_attribute(elem_list, allow_set):
    rulename = elem_list[0]
    scontext = elem_list[1]
    if rulename == 'typepermissive' :
        allow_set.add(scontext)


def get_permissive_set(args, with_developer):
    allow_set = set()
    if with_developer:
        deal_with_allow(args.developer_cil_file, allow_set)
    else:
        deal_with_allow(args.cil_file, allow_set)
    return allow_set


def get_whitelist(args, with_developer):
    whitelist_file_list = traverse_file_in_each_type(args.policy_dir_list, WHITELIST_FILE_NAME)
    contexts_list = []
    for path in whitelist_file_list:
        white_list = read_json_file(path).get('whitelist')
        contexts_list.extend(white_list.get('user'))
        if with_developer:
            contexts_list.extend(white_list.get('developer'))
    return contexts_list


def check(args, with_developer):
    permissive_set = get_permissive_set(args, with_developer)
    contexts_list = get_whitelist(args, with_developer)
    notallow = permissive_set - set(contexts_list)
    if len(notallow) > 0 :
        print('check permissive rule in {} mode failed.'.format("developer" if with_developer else "user"))
        print('violation list (scontext):')
        for diff in sorted(list(notallow)):
            print('\t{}'.format(diff))
        print('There are two solutions:\n',
              '\t1. Add the above list to whitelist file \'{}\' under \'{}\' in \'{}\' mode.\n'.format(
                    WHITELIST_FILE_NAME, args.policy_dir_list, "developer" if with_developer else "user"),
              '\t2. Change the policy to avoid violating rule.')
    return len(notallow) > 0


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--cil_file', help='the cil file path', required=True)
    parser.add_argument('--developer_cil_file', help='the developer cil file path', required=True)
    parser.add_argument('--policy-dir-list', help='policy dirs need to be included', required=True)

    return parser.parse_args()


if __name__ == '__main__':
    input_args = parse_args()
    print("check permissive input_args: {}".format(input_args))
    result = check(input_args, False)
    if result:
        raise Exception(-1)
    result = check(input_args, True)
    if result:
        raise Exception(-1)

