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

DOMAIN_BASELINE = "domain_baseline.json"
TYPE_GROUP_FILE_NAME = "type_group.json"
WHITELIST_FILE_NAME = "domian_whitelist.json"
HISTORY_LEGACY_DOMAIN = 'history_legacy_domain.txt'


def simplify_string(string):
    return string.strip().replace('(', '').replace(')', '')


def search_data(source_data_list, target_data_set):
    start_pos = 2  # index 2 begin
    data_len = len(source_data_list)
    for i in range(start_pos, data_len):
        target_data_set.add(source_data_list[i])


def deal_with_allow(cil_file, domain_set, domain_map):
    with open(cil_file, 'r', encoding='utf-8') as cil_read:
        for line in cil_read:
            line = line.strip()
            if not line:
                continue
            if line.startswith('(typeattributeset domain ('):
                # typeattributeset domain SP_daemon a2dp_host aa access_control_level_manager
                sub_string = simplify_string(line)
                elem_list = sub_string.split(' ')
                if len(elem_list) < 3:
                    continue
                domain_set |= set(elem_list[2:])
                continue
            if line.startswith('(typeattributeset '):
                # typeattributeset 
                sub_string = simplify_string(line)
                elem_list = sub_string.split(' ')
                if len(elem_list) < 3:
                    continue
                key = elem_list[1]
                if key not in domain_map:
                    continue
                search_data(elem_list, domain_map[key])


def get_domain_set(args, with_developer, domain_map):
    domain_set = set()
    if with_developer:
        deal_with_allow(args.developer_cil_file, domain_set, domain_map)
    else:
        deal_with_allow(args.cil_file, domain_set, domain_map)
    return domain_set


def get_type_group(input_args):
    config_file = os.path.join(os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.realpath(__file__)))), input_args.config)
    group_map = {}
    group_list = read_json_file(config_file).get('groups').get('group')
    for item in group_list:
        group_map.update(item)
    return group_map


def get_whitelist(args, with_developer):
    whitelist_file_list = traverse_file_in_each_type(args.policy_dir_list, WHITELIST_FILE_NAME)
    whitelist_map = {}
    whitelist_map['missing_domain'] = set()
    whitelist_map['conflict_domain'] = set()
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


def construct_domain_map(group_map):
    domain_map = {}
    for values in group_map.values():
        for item in values:
            domain_map[item] = set()
    return domain_map


def output_file(file_path, data):
    with open(file_path, 'w', encoding='utf-8') as f:
        lines = [item + '\n' for item in data]
        f.writelines(lines)


def write_domain(args, domain_set, domain_map, group_map):
    history_legacy_domain = domain_set
    for name, values in group_map.items():
        domain_union = set()
        for key in values:
            domain_union |= domain_map[key]
        domain_path = os.path.join(os.path.dirname(args.cil_file), '{}_new.txt'.format(name))
        output_file(domain_path, domain_union)
        history_legacy_domain -= domain_union
    history_legacy_domain_path = os.path.join(os.path.dirname(args.cil_file), HISTORY_LEGACY_DOMAIN)
    output_file(history_legacy_domain_path, history_legacy_domain)


# Only check
def non_unique_domain_data(args, with_developer, domain_map, whitelist_map):
    temp_set = set()
    result = set()
    check_result = False
    for domain in domain_map.values():
        for item in domain:
            if item not in temp_set:
                temp_set.add(item)
            else:
                result.add(item)

    conflict_domain = whitelist_map['conflict_domain']
    notallow = conflict_domain - result
    if (len(notallow) > 0):
        check_result = True
        print('\tCheck whitelist of "conflict_domain" in {} mode failed.'.format(
            "developer" if with_developer else "user"
        ))
        print('\tViolation list (type):')
        for violation in sorted(list(notallow)):
            print('\t\t"{}",'.format(violation))
        print('\tSolution: delete any unused data from "conflict_domain" field under "{}" field '
            'in {} file\n'.format("developer" if with_developer else "user", WHITELIST_FILE_NAME))

    notallow = result - conflict_domain
    if (len(notallow) > 0):
        check_result = True
        print("\tCheck rule in {} mode failed: a process is restricted to a single domain."
            .format("developer" if with_developer else "user"))
        print('\tViolation list (type):')
        for violation in sorted(list(notallow)):
            print('\t\t"{}",'.format(violation))
        
        print('\tThere are two solutions:\n',
            '\t1. Change types to prevent association with multiple domains.\n'.format(
            "developer" if with_developer else "user"),
            '\t2. Add the above list to "conflict_domain" field under "{}" field in {} file.\n'.format(
            "developer" if with_developer else "user", WHITELIST_FILE_NAME))
    return check_result


def get_notallow(domain_set, domain_map):
    rule_domain = set()
    for domain in domain_map.values():
        rule_domain |= domain
    return (domain_set - rule_domain)


def output_policy_err(args, with_developer, domain, domain_err_set):
    print('\tCheck "{}" baseline in {} mode failed.'.format(domain, "developer" if with_developer else "user"))
    print('\tViolation list (type):')
    for violation in sorted(list(domain_err_set)):
        print('\t\t"{}",'.format(violation))
    print('\tSolution: add the above list to "{}" field under "{}" field in baseline file {}.\n'.format(
        domain, "developer" if with_developer else "user", DOMAIN_BASELINE))


def output_baseline_err(args, with_developer, domain, domain_err_set):
    print('\tCheck "{}" baseline in "{}" mode failed.'.format(domain, "developer" if with_developer else "user"))
    print('\tViolation list (type):')
    for violation in sorted(list(domain_err_set)):
        print('\t\t"{}",'.format(violation))
    print('\tSolution: delete any unused data from "{}" field under "{}" field in baseline file {}.\n'.format(
        domain, "developer" if with_developer else "user", DOMAIN_BASELINE
    ))


def check_baseline(args, domain_map, with_developer):
    check_result = False
    baseline_json = {}
    for k in domain_map.keys():
        baseline_json[k] = []

    baseline_data_list = traverse_file_in_each_type(args.policy_dir_list, DOMAIN_BASELINE)
    for path in baseline_data_list:
        baseline_data = read_json_file(path)
        user_baseline = baseline_data.get('user')
        for k, v in baseline_json.items():
            v.extend(user_baseline.get(k))
        if with_developer:
            dev_baseline = baseline_data.get('developer')
            for k, v in baseline_json.items():
                v.extend(dev_baseline.get(k))

    for key, values in domain_map.items():
        domain_err_set = values - set(baseline_json.get(key))
        if (len(domain_err_set) > 0):
            check_result = True
            output_policy_err(args, with_developer, key, domain_err_set)

        domain_err_set = set(baseline_json.get(key)) - values
        if (len(domain_err_set) > 0):
            check_result = True
            output_baseline_err(args, with_developer, key, domain_err_set)

    return check_result


def check(args, with_developer):
    group_map = get_type_group(args)
    domain_map = construct_domain_map(group_map)
    domain_set = get_domain_set(args, with_developer, domain_map)
    write_domain(args, domain_set, domain_map, group_map)
    history_data = get_notallow(domain_set, domain_map)
    whitelist_map = get_whitelist(args, with_developer)
    baseline_result = check_baseline(args, domain_map, with_developer)
    multiple_mapping_result = non_unique_domain_data(args, with_developer, domain_map, whitelist_map)
    contexts_list = whitelist_map['missing_domain']

    whitelist_result = False
    notallow = history_data - contexts_list
    if len(notallow) > 0 :
        domain_list = []
        for v in group_map.values():
            domain_list.extend(v)
        whitelist_result = True
        print('\tCheck rule in {} mode failed: a process should be associated with a domain.'.format(
                "developer" if with_developer else "user"))
        print('\tViolation list (type):')
        for diff in sorted(list(notallow)):
            print('\t\t"{}",'.format(diff))
        print('\tThere are two solutions:\n',
            '\t1. Associate the types to one of domains:\n',
            "\t\t{}\n".format(", ".join(domain_list)),
            '\t2. Add the above list to "missing_domain" field under "{}" field in {} file.\n'.format(
            "developer" if with_developer else "user", WHITELIST_FILE_NAME))

    notallow = contexts_list - history_data
    if len(notallow) > 0 :
        whitelist_result = True
        print('\tCheck whitelist of "missing_domain" in {} mode failed.'.format( "developer" if with_developer else "user"))
        print('\tViolation list (type):')
        for diff in sorted(list(notallow)):
            print('\t\t"{}",'.format(diff))
        print('\tSolution: delete any unused data from "missing_domain" field under '
            '"{}" field in {} file.\n'.format(
            "developer" if with_developer else "user", WHITELIST_FILE_NAME))
    return whitelist_result | baseline_result | multiple_mapping_result


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
    print("check domain input_args: {}".format(input_args))
    result = check(input_args, False)
    if result:
        raise Exception(-1)
    result = check(input_args, True)
    if result:
        raise Exception(-1)
