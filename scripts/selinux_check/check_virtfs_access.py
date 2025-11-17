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


WHITELIST_FILE_NAME = "virtfs_whitelist.json"


def print_error_info(add_path_to_virtfs, del_path_from_virtfs, with_developer, config_dict):
    print("\nCheck security context of filesystem in {} mode failed.\n"
        .format("developer" if with_developer else "user"))
    if add_path_to_virtfs:
        for virtfs, label_list in add_path_to_virtfs.items():
            print("The node mounted to \"{}\" should be associated with the attribute \"{}\""
                .format(virtfs, config_dict[virtfs]["typeattr"]))
            for label in label_list:
                print("\t{}".format(label))
        print("There are two solutions:")
        print("1. Associate types with the attribute {}.".format(config_dict[virtfs]["typeattr"]))
        print("2. Add types to \"{}\" field under \"permissive_list\" field of \"{}\" in {} file.\n".format(
                "developer" if with_developer else "user", virtfs, WHITELIST_FILE_NAME))

    if del_path_from_virtfs:
        for virtfs, label_list in del_path_from_virtfs.items():
            print("Delete any unused data from \"{}\" field under \"permissive_list\" of \"{}\" "
                "in {} file: ".format(
                "developer" if with_developer else "user", virtfs, WHITELIST_FILE_NAME))
            for label in label_list:
                print("\t{}".format(label))
        print("\n")

def simplify_string(string):
    return string.replace('(', '').replace(')', '').replace('\n', '').strip()


def deal_with_typeattributeset(cil_file_path, attributes_map):
    with open(cil_file_path, 'r', encoding='utf-8') as cil_read:
        for line in cil_read:
            if not line.startswith('(typeattributeset '):
                continue
            sub_string = simplify_string(line)
            elem_list = sub_string.split(' ')
            if len(elem_list) < 3:
                continue
            attributes_map[elem_list[1]] += elem_list[2:]


def deal_with_genfscon(cil_file_path, genfscon_dict, virtfs_list):
    with open(cil_file_path, 'r', encoding='utf-8') as cil_read:
        for line in cil_read:
            line = line.strip()
            if not line.startswith('(genfscon '):
                continue
            m = re.match(r'\(genfscon\s+(\S+)\s+"([^"]+)"\s+\(u\s+object_r\s+(\S+)\s+', line, flags = re.M|re.S)
            virtfs = m.group(1) # virtfs index
            label = m.group(3) # label index
            path = m.group(2) # path index
            if virtfs not in virtfs_list:
                continue
            if not virtfs in genfscon_dict:
                genfscon_dict[virtfs] = set()
            genfscon_dict[virtfs].add(label)


def check_virtfs_typeattr(config_dict, whitelist_dict, genfscon_dict, typeattributeset_dict):
    add_path_to_virtfs = defaultdict(set)
    del_path_from_virtfs = defaultdict(set)
    for config in config_dict.values():
        virtfs = config.get('virtfs')
        typeattr = config.get('typeattr')
        if not virtfs in genfscon_dict:
            continue
        labels = genfscon_dict[virtfs]
        incorrectlist = set()
        for label in labels:
            if not typeattr in typeattributeset_dict or \
                not label in typeattributeset_dict[typeattr]:
                # incorrect, see withlist
                if not label in whitelist_dict[virtfs]:
                    add_path_to_virtfs[virtfs].add(label)
                else:
                    incorrectlist.add(label)

        tmp = set(whitelist_dict[virtfs]) - incorrectlist
        if  tmp:
            del_path_from_virtfs[virtfs] = tmp

    return add_path_to_virtfs, del_path_from_virtfs


def get_whitelist(args, with_developer):
    whitelist_file_list = traverse_file_in_each_type(args.policy_dir_list, WHITELIST_FILE_NAME)
    whitelist_dict = defaultdict(list)
    for path in whitelist_file_list:
        white_list_all = read_json_file(path)["whitelist"]
        for item in white_list_all:
            check_path = item["virtfs"]
            whitelist_dict[check_path] += item["permissive_list"]["user"]
            if with_developer:
                whitelist_dict[check_path] += item["permissive_list"]["developer"]
    return whitelist_dict


def filter_valid_config_dict(configs):
    filtered_configs = {}
    for config in configs:
        target_path = config["virtfs"]
        if target_path in filtered_configs:
            print("[ERROR] duplicated path = {}".format(target_path))
            raise Exception(-1)
        filtered_configs[target_path] = config
    return filtered_configs


def check_virtfs(input_args, with_developer=False):
    config_path = os.path.join(os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.realpath(__file__)))), input_args.config)
    config_all = read_json_file(config_path)
    config_dict = filter_valid_config_dict(config_all)

    cil_file_path = ''
    typeattributeset_dict = defaultdict(list)
    genfscon_dict = defaultdict(list)

    if with_developer:
        cil_file_path = input_args.developer_cil_file
    else:
        cil_file_path = input_args.cil_file

    whitelist_dict = get_whitelist(input_args, with_developer)
    deal_with_typeattributeset(cil_file_path, typeattributeset_dict)
    deal_with_genfscon(cil_file_path, genfscon_dict, config_dict.keys())

    add_path_to_virtfs, del_path_from_virtfs = check_virtfs_typeattr(
        config_dict, whitelist_dict, genfscon_dict, typeattributeset_dict)

    if add_path_to_virtfs or del_path_from_virtfs:
        print_error_info(add_path_to_virtfs, del_path_from_virtfs, with_developer, config_dict)
        exit(1)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--cil_file', help='the cil file path', required=True)
    parser.add_argument('--developer_cil_file', help='the developer cil file path', required=True)
    parser.add_argument('--policy-dir-list', help='policy dirs need to be included', required=True)
    parser.add_argument('--config', help='the config file path', required=True)

    return parser.parse_args()


if __name__ == '__main__':
    input_args = parse_args()
    script_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
    print("check virtfs_context input_args: {}".format(input_args))

    check_virtfs(input_args, False)
    check_virtfs(input_args, True)
