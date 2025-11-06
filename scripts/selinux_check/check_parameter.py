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
from collections import defaultdict
from check_common import read_json_file, traverse_file_in_each_type

WHITELIST_FILE_NAME = "parameter_whitelist.json"
BASELINE_FILE_NAME = "parameter_baseline.json"


def simplify_string(string):
    return string.strip().replace('(', '').replace(')', '')


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


def get_attributes_map(args, with_developer):
    attributes_map = defaultdict(list)
    if with_developer:
        deal_with_typeattributeset(args.developer_cil_file, attributes_map)
    else:
        deal_with_typeattributeset(args.cil_file, attributes_map)
    return attributes_map


def get_whitelist(args, with_developer):
    whitelist_file_list = traverse_file_in_each_type(args.policy_dir_list, WHITELIST_FILE_NAME)
    whitelist_map = defaultdict(set)
    for path in whitelist_file_list:
        white_list = read_json_file(path).get('whitelist')
        user_data = white_list.get('user')
        for k, v in user_data.items():
            whitelist_map[k] |= set(v)
        if with_developer:
            dev_data = white_list.get('developer')
            for k, v in dev_data.items():
                whitelist_map[k] |= set(v)
    return whitelist_map


def get_baseline(args, with_developer):
    baseline_file_list = traverse_file_in_each_type(args.policy_dir_list, BASELINE_FILE_NAME)
    baseline_map = defaultdict(set)
    for path in baseline_file_list:
        baseline = read_json_file(path).get('baseline')
        user_data = baseline.get('user')
        for k, v in user_data.items():
            baseline_map[k] |= set(v)
        if with_developer:
            dev_data = baseline.get('developer')
            for k, v in dev_data.items():
                baseline_map[k] |= set(v)
    return baseline_map


def get_config_check(args):
    config_file = os.path.join(os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.realpath(__file__)))), input_args.config)
    check_rules = read_json_file(config_file).get('checks')
    return check_rules


def output_policy_err(args, with_developer, typeattr, notallow, file_name):
    print('************************************************************************************************')
    print('\tcheck "{}" parameter in "{}" mode failed'.format(typeattr, "developer" if with_developer else "user"))
    print('\tviolation list (type):')
    for violation in sorted(list(notallow)):
        print('\t\t"{}",'.format(violation))
    print('\tSolution: policy information needs to be added to the "{}" file as well in "{}" mode.'.format(
        file_name, "developer" if with_developer else "user"))
    print('************************************************************************************************')


def output_whitelist_err(args, with_developer, typeattr, notallow, file_name):
    print('************************************************************************************************')
    print('\tcheck "{}" parameter in "{}" mode failed.'.format(typeattr, "developer" if with_developer else "user"))
    print('\tviolation list (type):')
    for violation in sorted(list(notallow)):
        print('\t\t"{}",'.format(violation))
    print('\tSolution: delete unused type from file "{}" in "{}" mode.'.format(
        file_name, "developer" if with_developer else "user"
    ))
    print('************************************************************************************************')


def check_unique(with_developer, check_map, attributes_map):
    check_result = False
    typeattr = check_map.get('typeattr')
    subtypeattr = check_map.get('subtypeattr')

    temp_set = set()
    result = set()
    for subtype in subtypeattr:
        if subtype not in attributes_map:
            continue
        for item in set(attributes_map.get(subtype)):
            if item not in temp_set:
                temp_set.add(item)
            else:
                result.add(item)
    if (len(result) > 0):
        check_result = True
        print('************************************************************************************************')
        print('\tcheck "{}" parameter in "{}" mode failed.'.format(typeattr, "developer" if with_developer else "user"))
        print('\tviolation list (type):')
        for violation in sorted(list(result)):
            print('\t\t"{}",'.format(violation))
        print('\tSolution: modify the policy in "{}" mode; it cannot belong to multiple typeattributes ("{}") at the same time.'
            .format("developer" if with_developer else "user", ",".join(subtypes) ))
        print('************************************************************************************************')

    return check_result


def check_baseline(args, with_developer, check_map, baseline_map, attributes_map):
    check_result = False
    typeattr = check_map.get('typeattr')
    baseline = check_map.get('baseline')

    if len(baseline) == 0:
        print('Check {}: No baseline data, default to pass'.format(typeattr)) 
    for subtype in baseline:
        baseline_data = baseline_map.get(subtype)
        if subtype not in attributes_map:
            if len(baseline_data) == 0:
                continue
            else:
                check_result = True
                output_whitelist_err(args, with_developer, typeattr, baseline_data, BASELINE_FILE_NAME)
                continue

        subtype_data = attributes_map.get(subtype)
        if len(baseline_data) == 0:
            check_result = True
            output_policy_err(args, with_developer, typeattr, subtype_data, BASELINE_FILE_NAME)
            continue

        notallow = subtype_data - baseline_data
        if (len(notallow) > 0):
            check_result = True
            output_policy_err(args, with_developer, typeattr, notallow, BASELINE_FILE_NAME)

        notallow = baseline_data - subtype_data
        if (len(notallow) > 0):
            check_result = True
            output_whitelist_err(args, with_developer, typeattr, notallow, BASELINE_FILE_NAME)

    return check_result


def check_whitelist(args, with_developer, check_map, whitelist_map, attributes_map):
    check_result = False
    typeattr = check_map.get('typeattr')
    subtypeattr = check_map.get('subtypeattr')

    history_data = set()
    if typeattr in attributes_map:
        history_data = set(attributes_map.get(typeattr))
    for subtype in subtypeattr:
        if subtype not in attributes_map:
            continue
        history_data -= set(attributes_map.get(subtype))
    
    whitelist_data = set()
    if typeattr in whitelist_map:
        whitelist_data = whitelist_map.get(typeattr)
    notallow = history_data - whitelist_data
    if (len(notallow) > 0):
        check_result = True
        print('************************************************************************************************')
        print('\tcheck "{}" parameter in "{}" mode failed'.format(typeattr, "developer" if with_developer else "user"))
        print('\tviolation list (type):')
        for violation in sorted(list(notallow)):
            print('\t\t"{}",'.format(violation))
        print('\tSolution:\n',
            '\t1. Modified parameter to belong to system_parameter_attr or vendor_parameter_attr.\n' 
            '\t2. Policy information needs to be added to the "{}" file as well in "{}" mode.'.format(
            WHITELIST_FILE_NAME, "developer" if with_developer else "user"))
        print('************************************************************************************************')

    notallow = whitelist_data - history_data
    if (len(notallow) > 0):
        check_result = True
        output_whitelist_err(args, with_developer, typeattr, notallow, WHITELIST_FILE_NAME)

    return check_result


def check(args, with_developer):
    attributes_map = get_attributes_map(args, with_developer)
    whitelist_map = get_whitelist(args, with_developer)
    baseline_map = get_baseline(args, with_developer)
    check_result = False
    check_rules = get_config_check(args)
    for check_map in check_rules:
        check_result |= check_whitelist(args, with_developer, check_map, whitelist_map, attributes_map)
        check_result |= check_unique(with_developer, check_map, attributes_map)
        check_result |= check_baseline(args, with_developer, check_map, baseline_map, attributes_map)
    return check_result


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--cil_file', help='the cil file path', required=True)
    parser.add_argument(
        '--developer_cil_file', help='the developer cil file path', required=True)
    parser.add_argument(
        '--policy-dir-list', help='policy dirs need to be included', required=True)
    parser.add_argument(
        '--config', help='the config file path', required=True)

    return parser.parse_args()


if __name__ == '__main__':
    input_args = parse_args()
    print("check parameter input_args: {}".format(input_args))
    result = check(input_args, False)
    if result:
        raise Exception(-1)
    result = check(input_args, True)
    if result:
        raise Exception(-1)
