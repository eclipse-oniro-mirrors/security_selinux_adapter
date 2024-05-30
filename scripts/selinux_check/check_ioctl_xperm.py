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

WHITELIST_FILE_NAME = "ioctl_xperm_whitelist.json"

ALLOW_TCONTEXT_CLASS_LIST = ["data_log_sanitizer_file file","proc_attr dir","self dir","self fifo_file",
                     "self file","self lnk_file","self unix_stream_socket"]


class PolicyDb(object):
    def __init__(self, allowx_set, allow_set, typetransition_set):
        self.allowx_set = allowx_set
        self.allow_set = allow_set
        self.typetransition_set = typetransition_set


def simplify_string(string):
    return string.strip().replace('(', '').replace(')', '')


def split_allow_rule(elem_list, allow_set, allowx_set):
    if len(elem_list) < 5:
        print("not an allow/allowx rule: {}".format(elem_list))
        return
    rulename = elem_list[0]
    scontext = elem_list[1]
    tcontext = elem_list[2]
    tclass = elem_list[3]
    if rulename == 'allow' and 'ioctl' in elem_list[4:]:
        keycontent = f'{scontext} {tcontext} {tclass}'
        allow_set.add(keycontent)
    if rulename == 'allowx' and 'ioctl' == tclass:
        keycontent = f'{scontext} {tcontext} {elem_list[4]}'
        allowx_set.add(keycontent)


def split_typetransition(elem_list, typetransition_set):
    if len(elem_list) < 5:
        print("not a typetransition rule: {}".format(elem_list))
        return
    rulename = elem_list[0]
    source_t = elem_list[1]
    target_t = elem_list[2]
    tclass = elem_list[3]
    default_t = elem_list[4]
    if tclass == 'process':
        keycontent = f'{source_t} {target_t} file'
        typetransition_set.add(keycontent)


def deal_with_allow(cil_file, allow_set, allowx_set, typetransition_set):
    with open(cil_file, 'r', encoding='utf-8') as cil_read:
        for line in cil_read:
            if line.startswith('(typetransition '):
                # (typetransition A B process C)
                sub_string = simplify_string(line)
                elem_list = sub_string.split(' ')
                split_typetransition(elem_list, typetransition_set)

            if line.startswith('(allow ') or line.startswith('(allowx '):
                sub_string = simplify_string(line)
                elem_list = sub_string.split(' ')
                # (allow A B (file (ioctl x x x)))
                # (allowx A B (ioctl file (x x x)))
                split_allow_rule(elem_list, allow_set, allowx_set)


def generate_database(args, with_developer):
    allowx_set = set()
    allow_set = set()
    typetransition_set= set()
    if with_developer:
        deal_with_allow(args.developer_cil_file, allow_set, allowx_set, typetransition_set)
    else:
        deal_with_allow(args.cil_file, allow_set, allowx_set, typetransition_set)

    return PolicyDb(allowx_set, allow_set, typetransition_set)


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
    policy_db = generate_database(args, with_developer)
    contexts_list = get_whitelist(args, with_developer)
    diff_set = policy_db.allow_set - policy_db.allowx_set - policy_db.typetransition_set - set(contexts_list)
    notallow = list()
    for diff in diff_set:
        if not (diff.endswith(tuple(ALLOW_TCONTEXT_CLASS_LIST))) :
            notallow.append(diff)
    
    if len(notallow) > 0 :
        print('check ioctl rule in {} mode failed.'.format("developer" if with_developer else "user"))
        print('violation list (allow scontext tcontext:tclass ioctl)')
        for e in sorted(notallow):
            elem_list = e.split(' ')
            print('\tallow {} ioctl;'.format(elem_list[0] + ' ' + elem_list[1] + ':' + elem_list[2]))
        print('please add "allowxperm" rule based on the above list.')
    return len(notallow) > 0


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--cil_file', help='the cil file path', required=True)
    parser.add_argument('--developer_cil_file', help='the developer cil file path', required=True)
    parser.add_argument('--policy-dir-list', help='policy dirs need to be included', required=True)

    return parser.parse_args()


if __name__ == '__main__':
    input_args = parse_args()
    print("check xperm input_args: {}".format(input_args))
    result = check(input_args, False)
    if result:
        raise Exception(-1)
    result = check(input_args, True)
    if result:
        raise Exception(-1)

