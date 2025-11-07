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
import re
from collections import defaultdict
from check_common import read_json_file, traverse_file_in_each_type


WHITELIST_FILE_NAME = "file_contexts_typeattr_whitelist.json"


class ErrorInfo:
    def __init__(self, path, label, target_path, target_typeattr):
        self.path = path
        self.label = label
        self.target_path = target_path
        self.target_typeattr = target_typeattr


def simplify_string(string):
    return string.replace('(', '').replace(')', '').replace('\n', '').strip()


def deal_with_typeattributeset(cil_file, attributes_map):
    with open(cil_file, 'r', encoding='utf-8') as cil_read:
        for line in cil_read:
            if not line.startswith('(typeattributeset '):
                continue
            sub_string = simplify_string(line)
            elem_list = sub_string.split(' ')
            if len(elem_list) < 3:
                print("[ERROR] policy syntax failed.")
                continue
            attributes_map[elem_list[1]] += elem_list[2:]


def get_label_from_context(context):
    label = ''
    pattern = r"u:object_r:(.*):s0"
    m = re.search(pattern, context)
    if m:
        label = m.group(1)
    return label


def is_subpath(subpath, path):
    path = path.rstrip('/')
    # /system/lib64/123 and /system/lib64/
    if subpath.startswith(path + '/'):
        return True
    # check reg of subpath
    # /system/lib(64)?/ and /system/lib64
    sub_parts = subpath.split('/')
    parts = path.split('/')
    if len(sub_parts) >= len(parts):
        if len(parts) == 0:
            print("[ERROR] Unsupported check path of {}".format(path))
        for i in range(len(parts) - 1):
            if not sub_parts[i] == parts[i]:
                return False
        maybe_match_part = sub_parts[len(parts) - 1].strip("\(")
        try:
            if re.fullmatch(maybe_match_part, parts[-1]):
                return True
        except Exception as e:
            print("[ERROR] Unsupported check subpath of {}".format(subpath))
            return False
    return False


def print_blank():
    print("\n")


def print_merged_permissive_info(error_infos):
    merged = {}
    for error_info in error_infos:
        if error_info.target_path not in merged:
            merged[error_info.target_path] = []
        merged[error_info.target_path].append(error_info.path)
    for target_path, path_list in merged.items():
        print("\n\t\tmodify permissive_list of rules: {}".format(target_path))
        for path in path_list:
            print("\t\t\t\"{}\"".format(path))


def print_error_info(add_error_info, del_error_info, with_developer):
    print("[ERROR] check typeattributes of file_contexts access in {} mode failed:"
        .format('developer' if with_developer else 'user'))
    if add_error_info:
        print_blank()
        print("[Unsafe context] The following file_contexts check failed. The two solutions:")
        print("\t1: modify following types belong to target typeattribute: type, attribute (file)")
        for error_info in add_error_info:
            print("\t\t{}, {}\t({})" .format(
                    error_info.label, error_info.target_typeattr, error_info.path))
        print("\n\t2: add following path to permissive_list of releted requirement in {}".format(WHITELIST_FILE_NAME))
        print_merged_permissive_info(add_error_info)
    if del_error_info:
        print_blank()
        print("[Unused whitelist] The following path should be removed from permissive_list in {}"
            .format(WHITELIST_FILE_NAME))
        for target_path, path_list in del_error_info.items():
            print("\n\t\tmodify permissive_list of rules: {}".format(target_path))
            for path in path_list:
                print("\t\t\t\"{}\"".format(path))
        print_blank()
    print_blank()


def check_file_label_context_attr(file_path, file_label, config_dict, whitelist_dict, typeattributeset_dict):
    add_to_path_list = []
    violate_list = []

    for config in config_dict.values():
        target_path = config.get('path')
        target_typeattr = config.get('typeattr')
        permissive_list = whitelist_dict[target_path]
        if is_subpath(file_path, target_path):
            types_of_typeattr = typeattributeset_dict.get(target_typeattr)
            if not types_of_typeattr or not file_label in types_of_typeattr:
                # incorrect path
                if not file_path in permissive_list:
                    add_to_path_list.append(target_path)
                violate_list.append(target_path)

    return add_to_path_list, violate_list


def merge_error_info(cur_path, cur_label, error_path_list, configs, error_msg):
    for path in error_path_list:
        error_msg.append(ErrorInfo(cur_path, cur_label, path, configs[path]["typeattr"]))


def get_unused_withlist(withlist_dict, violate_map):
    unused_withlite = {}
    for path, whiltelist in withlist_dict.items():
        if path in violate_map:
            tmp = set(whiltelist) - violate_map[path]
            if tmp:
                unused_withlite[path] = tmp
    return unused_withlite


def check_file_contexts_with_typeset(config_dict, whitelist_dict, file_contexts_path, typeattributeset_dict):
    add_error_info = []
    del_error_info = []
    violate_map = defaultdict(set)
    with open(file_contexts_path, 'r', encoding='utf-8') as contexts:
        for file_path_label in contexts:
            file_path_label = file_path_label.strip()
            if not file_path_label or file_path_label.startswith('#'):
                continue
            file_path_label_list = file_path_label.split()
            if len(file_path_label_list) < 2:
                print("[ERROR] Unsupported file_context = {}".format(file_path_label))
                continue
            file_path = file_path_label_list[0]
            file_label = get_label_from_context(file_path_label_list[1].strip())

            add_to_path_list, violate_list = check_file_label_context_attr(
                file_path, file_label, config_dict, whitelist_dict, typeattributeset_dict)

            merge_error_info(file_path, file_label, add_to_path_list, config_dict, add_error_info)
            for path in violate_list:
                violate_map[path].add(file_path)
        del_error_info = get_unused_withlist(whitelist_dict, violate_map)
    return add_error_info, del_error_info


def filter_valid_config_dict(configs):
    filtered_configs = {}
    for config in configs:
        target_path = config["path"]
        if target_path in filtered_configs:
            print("[ERROR] duplicated path = {}".format(target_path))
            raise Exception(-1)
        # cannot use regex in checklist
        regex_special_chars = r'[\.\*\+\?\^\$\{\}$\]$\)\|]'
        if re.search(regex_special_chars, target_path):
            print("[ERROR] config is invalid for path = {}".format(target_path))
            raise Exception(-1)
        else:
            filtered_configs[target_path] = config
    return filtered_configs


def get_whitelist(args, with_developer):
    whitelist_file_list = traverse_file_in_each_type(args.policy_dir_list, WHITELIST_FILE_NAME)
    whitelist_dict = {}
    for path in whitelist_file_list:
        white_list_all = read_json_file(path)["whitelist"]
        for item in white_list_all:
            check_path = item["path"]
            if not check_path in whitelist_dict:
                whitelist_dict[check_path] = []
            whitelist_dict[check_path] += item["permissive_list"]["user"]
            if with_developer:
                whitelist_dict[check_path] += item["permissive_list"]["developer"]
    return whitelist_dict


def check_file_contexts_with_mode(input_args, with_developer=False):
    config_file = os.path.join(os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.realpath(__file__)))), input_args.config)
    config_all = read_json_file(config_file)
    config_dict = filter_valid_config_dict(config_all)

    cil_file_path = ''
    file_contexts_path = input_args.file_contexts
    typeattributeset_dict = defaultdict(list)

    if with_developer:
        cil_file_path = input_args.developer_cil_file
    else:
        cil_file_path = input_args.cil_file

    whitelist_dict = get_whitelist(input_args, with_developer)
    deal_with_typeattributeset(cil_file_path, typeattributeset_dict)
    add_error, del_error = check_file_contexts_with_typeset(config_dict, whitelist_dict, file_contexts_path, typeattributeset_dict)

    if add_error or del_error:
        print_error_info(add_error, del_error, with_developer)
        exit(1)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--cil_file', help='the cil file path', required=True)
    parser.add_argument('--file_contexts', help='the file contexts path', required=True)
    parser.add_argument('--developer_cil_file', help='the developer cil file path', required=True)
    parser.add_argument('--policy-dir-list', help='policy dirs need to be included', required=True)
    parser.add_argument('--config', help='the config file path', required=True)

    return parser.parse_args()


if __name__ == '__main__':
    input_args = parse_args()
    print("check system chipset input_args: {}".format(input_args))

    check_file_contexts_with_mode(input_args, False)
    check_file_contexts_with_mode(input_args, True)
