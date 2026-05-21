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
from check_common import read_json_file, load_json_objects_in_dir_list
from cil_parser import parse_policy_db

WHITELIST_FILE_NAME = "perm_group_whitelist.json"


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
    contexts_list = []
    for _, data in load_json_objects_in_dir_list(args.policy_dir_list, WHITELIST_FILE_NAME):
        white_list = data.get('whitelist')
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
                check_success |= (set(perm_group.check_perms) <= policy_db.allow_map[contexts][check_class])
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

    user_policy_db = parse_policy_db(input_args.cil_file)
    developer_policy_db = parse_policy_db(input_args.developer_cil_file)
    check_rules = read_json_file(os.path.join(script_path, input_args.config)).get('check_rules')
    result = False
    for check_rule in check_rules:
        result |= check_perm_group(input_args, check_rule, user_policy_db, False)
        result |= check_perm_group(input_args, check_rule, developer_policy_db, True)
    if result:
        raise Exception(-1)
