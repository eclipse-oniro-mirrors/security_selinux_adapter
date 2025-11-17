#!/usr/bin/env python
# coding: utf-8

"""
Copyright (c) 2025 Huawei Device Co., Ltd.
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

WHITELIST_FILE_NAME = "socket_whitelist.json"
SUBJECT_INDEX = 1
GUEST_INDEX = 2
SOCK_FILE_INDEX = 3


def simplify_string(string):
    return string.strip().replace('(', '').replace(')', '')


def split_attribute(elem_list, allow_set):
    guest = elem_list[GUEST_INDEX]
    rulename = elem_list[SOCK_FILE_INDEX]
    if rulename == 'sock_file' :
        if guest == 'self':
            guest = elem_list[SUBJECT_INDEX]
        allow_set.add(guest)


def search_rule_data(elem_list, rule_data_set):
    start_pos = 2  # index 2 begin
    data_len = len(elem_list)
    for i in range(start_pos, data_len):
        rule_data_set.add(elem_list[i])


def deal_with_allow(cil_file, allow_set, rule_system_set, rule_chipset_set):
    with open(cil_file, 'r', encoding='utf-8') as cil_read:
        for line in cil_read:
            line = line.strip()
            if not line:
                continue
            if line.startswith('(typeattributeset system_sock_domain ('):
                # typeattributeset system_sock_domain fd_holder_socket hdcd_socket hilog_output_socket nwebspawn_socket
                sub_string = simplify_string(line)
                elem_list = sub_string.split(' ')
                search_rule_data(elem_list, rule_system_set)
                continue
            elif line.startswith('(typeattributeset chipset_sock_domain ('):
                # typeattributeset chipset_sock_domain
                sub_string = simplify_string(line)
                elem_list = sub_string.split(' ')
                search_rule_data(elem_list, rule_chipset_set)
                continue
            elif not line.startswith('(allow '):
                continue
            sub_string = simplify_string(line)
            elem_list = sub_string.split(' ')
            # allow SP_daemon hilog_input_socket sock_file write
            if len(elem_list) < 5:
                print('Error rule: "{}"'.format(line))
                continue
            split_attribute(elem_list, allow_set)


def get_socket_set(args, with_developer, rule_system_set, rule_chipset_set):
    allow_set = set()
    if with_developer:
        deal_with_allow(args.developer_cil_file, allow_set, rule_system_set, rule_chipset_set)
    else:
        deal_with_allow(args.cil_file, allow_set, rule_system_set, rule_chipset_set)
    return allow_set - rule_system_set - rule_chipset_set


def get_whitelist(args, with_developer):
    whitelist_file_list = traverse_file_in_each_type(args.policy_dir_list, WHITELIST_FILE_NAME)
    contexts_list = []
    for path in whitelist_file_list:
        white_list = read_json_file(path).get('whitelist')
        contexts_list.extend(white_list.get('user'))
        if with_developer:
            contexts_list.extend(white_list.get('developer'))
    return contexts_list


# Only check
def check_sock_unique(with_developer, rule_system_set, rule_chipset_set):
    notallow = rule_system_set & rule_chipset_set
    if len(notallow) > 0 :
        print('Check sock_file with correct socket attribute in {} mode failed.'.format(
            "developer" if with_developer else "user"))
        print('Violation list (type):')
        for diff in sorted(list(notallow)):
            print('\t"{}",'.format(diff))
        print('The above types should be associated with exactly one of the two attributes: '
            'chipset_sock_domain and system_sock_domain.\n')
    return len(notallow) > 0


def check(args, with_developer):
    check_result = False
    rule_system_set = set()
    rule_chipset_set = set()
    socket_set = get_socket_set(args, with_developer, rule_system_set, rule_chipset_set)
    unique_rule = check_sock_unique(with_developer, rule_system_set, rule_chipset_set)
    contexts_list = get_whitelist(args, with_developer)
    notallow = socket_set - set(contexts_list)
    if len(notallow) > 0 :
        check_result = True
        print('Check sock_file with single socket attribute in {} mode failed.'.format(
            "developer" if with_developer else "user"))
        print('Violation list (types):')
        for diff in sorted(list(notallow)):
            print('\t"{}",'.format(diff))
        print('There are two solutions:\n',
            '\t1. Associate types with either chipset_sock_domain or system_sock_domain.\n',
            '\t2. Add the above list to "{}" field in {} file.\n'.format(
                "developer" if with_developer else "user", WHITELIST_FILE_NAME))

    notallow = set(contexts_list) - socket_set
    if len(notallow) > 0 :
        check_result = True
        print('Check whitelist of socket rule in {} mode failed.'.format(
            "developer" if with_developer else "user"))
        print('Violation list (types):')
        for diff in sorted(list(notallow)):
            print('\t"{}",'.format(diff))
        print('Solution: delete any unused data from "{}" field in {} file.\n'.format(
            "developer" if with_developer else "user", WHITELIST_FILE_NAME
        ))
    return check_result | unique_rule


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--cil_file', help='the cil file path', required=True)
    parser.add_argument(
        '--developer_cil_file', help='the developer cil file path', required=True)
    parser.add_argument(
        '--policy-dir-list', help='policy dirs need to be included', required=True)

    return parser.parse_args()


if __name__ == '__main__':
    input_args = parse_args()
    print("check socket input_args: {}".format(input_args))
    result = check(input_args, False)
    if result:
        raise Exception(-1)
    result = check(input_args, True)
    if result:
        raise Exception(-1)
