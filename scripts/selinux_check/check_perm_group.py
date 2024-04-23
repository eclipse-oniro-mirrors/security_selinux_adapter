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
from check_common import read_json_file, traverse_file_in_each_type

WHITELIST_FILE_NAME = "perm_group_whitelist.json"


class PolicyDb(object):
    def __init__(self, attributes_map, allow_map, class_map):
        self.attributes_map = attributes_map
        self.allow_map = allow_map
        self.class_map = class_map


def simplify_string(string):
    return string.replace('(', '').replace(')', '').replace('\n', '').strip()


def deal_with_allow(cil_file, allow_map, attributes_map):
    with open(cil_file, 'r', encoding='utf-8') as cil_read:
        for line in cil_read:
            if not line.startswith('(allow ') and not line.startswith('(auditallow '):
                continue
            sub_string = simplify_string(line)
            elem_list = sub_string.split(' ')
            # (allow A B (dir (getattr)))
            if len(elem_list) < 5:
                continue
            split_attribute(elem_list, allow_map, attributes_map)


def split_attribute(elem_list, allow_map, attributes_map):
    scontext = elem_list[1]
    tcontext = elem_list[2]
    tclass = elem_list[3]
    perm = elem_list[4:]
    if scontext not in attributes_map:
        # allow type self
        if tcontext == 'self':
            allow_map[(scontext, scontext)][tclass] += perm
        # allow type attribute
        elif tcontext in attributes_map:
            for tcon in attributes_map[tcontext]:
                allow_map[(scontext, tcon)][tclass] += perm
        # allow type type
        else:
            allow_map[(scontext, tcontext)][tclass] += perm
        return

    for scon in attributes_map[scontext]:
        # allow attribute self
        if tcontext == 'self':
            allow_map[(scon, scon)][tclass] += perm
        # allow attribute attribute
        elif tcontext in attributes_map:
            for tcon in attributes_map[tcontext]:
                allow_map[(scon, tcon)][tclass] += perm
        # allow attribute type
        else:
            allow_map[(scon, tcontext)][tclass] += perm


def deal_with_typeattributeset(cil_file, attributes_map):
    with open(cil_file, 'r', encoding='utf-8') as cil_read:
        for line in cil_read:
            if not line.startswith('(typeattributeset '):
                continue
            sub_string = simplify_string(line)
            elem_list = sub_string.split(' ')
            if len(elem_list) < 3:
                continue
            attributes_map[elem_list[1]] += elem_list[2:]


def deal_with_class(cil_file, class_map):
    with open(cil_file, 'r', encoding='utf-8') as cil_read:
        common_map = defaultdict(list)
        for line in cil_read:
            if not line.startswith('(common '):
                continue
            sub_string = simplify_string(line)
            elem_list = sub_string.split(' ')
            if len(elem_list) < 3:
                continue
            common_map[elem_list[1]] += elem_list[2:]

    with open(cil_file, 'r', encoding='utf-8') as cil_read:
        for line in cil_read:
            if not line.startswith('(class '):
                continue
            sub_string = simplify_string(line)
            elem_list = sub_string.split(' ')
            if len(elem_list) > 2:
                class_map[elem_list[1]] += elem_list[2:]

    with open(cil_file, 'r', encoding='utf-8') as cil_read:
        for line in cil_read:
            if not line.startswith('(classcommon '):
                continue
            sub_string = simplify_string(line)
            elem_list = sub_string.split(' ')
            if len(elem_list) < 3:
                continue
            class_map[elem_list[1]] += common_map[elem_list[2]]


def generate_database(cil_file):
    attributes_map = defaultdict(list)
    class_map = defaultdict(list)
    allow_map = defaultdict(lambda: defaultdict(list))
    deal_with_typeattributeset(cil_file, attributes_map)
    deal_with_allow(cil_file, allow_map, attributes_map)
    deal_with_class(cil_file, class_map)
    return PolicyDb(attributes_map, allow_map, class_map)


class CheckPermGroup(object):
    def __init__(self, check_class_list, check_perms):
        self.check_class_list = check_class_list
        self.check_perms = check_perms


def get_check_class_list(check_tclass, check_perms, class_map):
    if check_tclass == '*':
        check_class_list = []
        for tclass in class_map.keys():
            if set(check_perms) <= set(class_map[tclass]):
                check_class_list.append(tclass)
        return check_class_list
    return [check_tclass]


def get_perm_group_list(rule, class_map):
    check_perm_group_list = []
    perm_group_list = rule.get('perm_group')
    for perm_group in perm_group_list:
        check_tclass = perm_group.get('tclass')
        check_perms = perm_group.get('perm').split(' ')
        check_class_list = get_check_class_list(check_tclass, check_perms, class_map)
        check_perm_group_list.append(CheckPermGroup(check_class_list, check_perms))
    return check_perm_group_list


def get_whitelist(args, check_name, with_developer):
    whitelist_file_list = traverse_file_in_each_type(args.policy_dir_list, WHITELIST_FILE_NAME)
    contexts_list = []
    for path in whitelist_file_list:
        white_list = read_json_file(path).get('whitelist')
        for item in white_list:
            if item.get('name') != check_name:
                continue
            contexts_list.extend(item.get('user'))
            if with_developer:
                contexts_list.extend(item.get('developer'))
    return contexts_list


def check_perm_group(args, rule, policy_db, with_developer):
    check_name = rule.get('name')
    check_perm_group_list = get_perm_group_list(rule, policy_db.class_map)
    contexts_list = get_whitelist(args, check_name, with_developer)

    non_exempt_violator_list = []
    violator_list = []
    for contexts in policy_db.allow_map.keys():
        check_result = 0
        for perm_group in check_perm_group_list:
            check_success = False
            for check_class in perm_group.check_class_list:
                check_success |= (set(perm_group.check_perms) <= set(policy_db.allow_map[contexts][check_class]))
            if check_success:
                check_result += 1
        if check_result != len(check_perm_group_list):
            continue
        violater = ' '.join(contexts)
        # all violation list
        violator_list.append(violater)
        # if not in whitelist
        if violater not in contexts_list:
            non_exempt_violator_list.append(violater)

    if len(non_exempt_violator_list):
        print('\tcheck rule \'{}\' in {} mode failed, {}'.format(
            check_name, "developer" if with_developer else "user", rule.get('description')))
        print('\tviolation list (scontext tcontext):')
        for violation in non_exempt_violator_list:
            print('\t\t{}'.format(violation))
        print('\tThere are two solutions:\n',
              '\t1. Add the above list to whitelist file \'{}\' under \'{}\' in \'{}\' part of \'{}\'\n'.format(
                    WHITELIST_FILE_NAME, args.policy_dir_list, "developer" if with_developer else "user", check_name),
              '\t2. Change the policy to avoid violating rule \'{}\'\n'.format(check_name))
        return True

    diff_list = list(set(contexts_list) - set(violator_list))
    if len(diff_list):
        print('\tcheck rule \'{}\' failed in whitelist file \'{}\'\n'.format(check_name, WHITELIST_FILE_NAME),
              '\tremove the following unnecessary whitelists in rule \'{}\' part \'{}\':'.format(
                    check_name, 'developer' if with_developer else 'user'))
        for diff in diff_list:
            print('\t\t{}'.format(diff))
        return True
    return False


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--cil_file', help='the cil file path', required=True)
    parser.add_argument(
        '--developer_cil_file', help='the developer cil file path', required=True)
    parser.add_argument(
        '--policy-dir-list', help='the whitelist path list', required=True)
    parser.add_argument(
        '--config', help='the config file path', required=True)
    return parser.parse_args()


if __name__ == '__main__':
    input_args = parse_args()
    script_path = os.path.dirname(os.path.realpath(__file__))

    user_policy_db = generate_database(input_args.cil_file)
    developer_policy_db = generate_database(input_args.developer_cil_file)
    check_rules = read_json_file(os.path.join(script_path, input_args.config)).get('check_rules')
    result = False
    for check_rule in check_rules:
        result |= check_perm_group(input_args, check_rule, user_policy_db, False)
        result |= check_perm_group(input_args, check_rule, developer_policy_db, True)
    if result:
        raise Exception(-1)
