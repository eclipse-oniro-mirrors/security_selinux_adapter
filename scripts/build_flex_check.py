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

import os
import re
import argparse
import sys
import shutil
import find

PUBLIC_CIL_FILES = ["public.cil", "public_common.cil"]
DEVELOPER_PUBLIC_CIL_FILES = [ "developer/public.cil" ]
DEVELOPER_SUB_PATH = "developer"


TYPE_VERSION_OLD = 0
TYPE_VERSION_NEW = 1


def get_type_set(cil_file_input):
    pattern_type = re.compile(r'^\(type (.*)\)$')
    type_set = set()
    with open(cil_file_input, 'r', encoding='utf-8') as cil_read:
        for line in cil_read:
            line = line.strip()
            if not line:
                continue
            match_type = pattern_type.match(line.strip())
            if match_type:
                type_set.add(match_type.group(1))
    return type_set


def get_types_in_mapping(cil_file_input):
    pattern_type = re.compile(r'^\(type (.*)\)$')
    pattern_typeattribute = re.compile(r'^\(typeattributeset\s+(.+)\s+\((.+?)\)\)')
    pub_type_pattern = re.compile(r'(.+)_\d+')
    type_set = set()
    types_in_attributes = set()
    pub_types = set()
    with open(cil_file_input, 'r', encoding='utf-8') as cil_read:
        for line in cil_read:
            line = line.strip()
            if not line:
                continue
            if line.startswith('(type '):
                match_type = pattern_type.match(line)
                if match_type:
                    type_set.add(match_type.group(1))
                else:
                    print("[ERROR] parse line = {}".format(line))
                    raise Exception(-1)
            elif line.startswith('(typeattributeset '):
                match_typeattribute = pattern_typeattribute.match(line)
                if match_typeattribute:
                    types_in_attributes.update(set(match_typeattribute.group(2).split()))
                    match_pub_type = pub_type_pattern.match(match_typeattribute.group(1))
                    if match_pub_type:
                        pub_types.add(match_pub_type.group(1))
                else:
                    print("[ERROR] parse line = {}".format(line))
                    raise Exception(-1)
    return type_set, types_in_attributes, pub_types


def compat_old_to_base(old_type_set, new_type_set, mapping):
    violators = []
    old_types = old_type_set - new_type_set
    for t in old_types:
        if t in mapping[2] and not t in mapping[0]:
            violators.append(t)
    return violators


def compat_base_to_old(old_type_set, new_type_set, mapping):
    violators = []
    new_types = new_type_set - old_type_set
    for t in new_types:
        if t not in mapping[1]:
            violators.append(t)
    return violators


def get_old_and_new_path(input_args, is_developer):
    if not is_developer:
        old_cill_file = os.path.join(
            input_args.compat_cil_path, "{}.cil".format(input_args.compat_version))
        new_cil_file = os.path.join(
            input_args.compat_cil_path, "{}_ignore.cil".format(input_args.compat_version))
    else:
        old_cill_file = os.path.join(input_args.compat_cil_path,
            DEVELOPER_SUB_PATH, "{}.cil".format(input_args.compat_version))
        new_cil_file = os.path.join(input_args.compat_cil_path,
            DEVELOPER_SUB_PATH, "{}_ignore.cil".format(input_args.compat_version))
    return old_cill_file, new_cil_file


def check_policy_flex_check(old_type_set, new_type_set, mapping,
    old_cill_file, new_cil_file):
    removed = compat_old_to_base(old_type_set, new_type_set, mapping)
    added = compat_base_to_old(old_type_set, new_type_set, mapping)

    if removed:
        print("The following types are removed from current version.")
        for t in removed:
            print("\t{}".format(t))

    if added:
        print("The following types are added in current version.")
        for t in added:
            print("\t{}".format(t))

    if removed or added:
        print("The solutions:")
        print("\t 1. add it to compatiable policies '{}' if it is a deleted or modified type"
            .format(old_cill_file))
        print("\t 2. add it to ignore policies {} if it is a new type"
            .format(new_cil_file))


def clear_and_make_dir(path):
    if os.path.isfile(path):
        with open(path, "w"):
            pass
    elif os.path.isdir(path):
        shutil.rmtree(path)
    os.makedirs(path)


def get_mapping_from_cil(old_cill_file, new_cil_file, mapping_file):
    mapping_dir = os.path.dirname(mapping_file)
    if not os.path.exists(mapping_dir) or os.path.isfile(mapping_dir):
        clear_and_make_dir(mapping_dir)

    with open(mapping_file, 'w', encoding='utf-8') as file, \
         open(old_cill_file, 'r', encoding='utf-8') as olds, \
         open(new_cil_file, 'r', encoding='utf-8') as bases:
        for old in olds:
            file.write(old)
        file.write('\n\n')
        for base in bases:
            file.write(base)


def generate_compatible_cil(input_args, old_type_set, new_type_set,
    is_developer, old_diff_cil_file):
    if os.path.exists(old_diff_cil_file):
        print("[INFO] Override file {}".format(old_diff_cil_file))
        os.remove(old_diff_cil_file)

    types_output = ''
    deleted_types = old_type_set - new_type_set
    for label in deleted_types:
        types_output += '(type {})\n'.format(label)
    with open(old_diff_cil_file, 'w', encoding='utf-8') as outfile:
        outfile.write('{}\n'.format(types_output))
        if deleted_types:
            outfile.write('\n')

    version_cil = None
    if is_developer:
        version_cil = os.path.join(input_args.system_compact_object,
            DEVELOPER_SUB_PATH, "compatible",
            "{}.cil".format(input_args.compat_version))
    else:
        version_cil = os.path.join(input_args.system_compact_object,
            "compatible", "{}.cil".format(input_args.compat_version))
    if os.path.exists(version_cil):
        with open(version_cil, 'r', encoding='utf-8') as infile, \
            open(old_diff_cil_file, 'a', encoding='utf-8') as outfile:
            for line in infile:
                outfile.write(line)
    else:
        print("[ERROR] cannot find path {}".format(version_cil))
        raise Exception(-1)


def generate_ignore_cil(input_args, old_type_set, new_type_set, new_cil_file):
    if os.path.exists(new_cil_file):
        print("[INFO] Override file {}".format(new_cil_file))
        os.remove(new_cil_file)
    new_types = new_type_set - old_type_set
    with open(new_cil_file, 'w', encoding='utf-8') as outfile:
        if new_types:
            outfile.write('(typeattribute new_objects)\n')
            outfile.write('(typeattributeset new_objects (')
            outfile.write(' '.join(new_types))
            outfile.write('))')
        else:
            print("[INFO] not object added")


def generate_compat_cil_file(input_args, old_type_set, new_type_set, is_developer):
    old_cill_file, new_cil_file = get_old_and_new_path(input_args, is_developer)
    base_dir = os.path.dirname(old_cill_file)
    if not os.path.exists(base_dir) or os.path.isfile(base_dir):
        clear_and_make_dir(base_dir)
    generate_compatible_cil(input_args, old_type_set, new_type_set,
        is_developer, old_cill_file)
    generate_ignore_cil(input_args, old_type_set, new_type_set,
        new_cil_file)


def get_intermediate_path(input_args):
    return os.path.join(input_args.output_path, "intermediate")


def check_compact_cil_file(input_args, old_type_set, new_type_set, is_developer):
    old_cill_file, new_cil_file = get_old_and_new_path(input_args, is_developer)
    if not os.path.exists(old_cill_file) or not os.path.exists(new_cil_file):
        print("[ERROR] {} or {} is not exists".format(old_cill_file, new_cil_file))
        raise Exception(-1)
    if is_developer:
        mapping_file = os.path.join(get_intermediate_path(input_args),
            DEVELOPER_SUB_PATH, 'mapping.cil')
    else:
        mapping_file = os.path.join(get_intermediate_path(input_args), 'mapping.cil')

    get_mapping_from_cil(old_cill_file, new_cil_file, mapping_file)
    mapping = get_types_in_mapping(mapping_file)

    check_policy_flex_check(old_type_set, new_type_set, mapping,
        old_cill_file, new_cil_file)



def get_compiled_file_path(input_args, version, is_developer, filename):
    path = ""
    if version == TYPE_VERSION_OLD:
        path = os.path.join(input_args.compat_policy_object, filename)
    elif version == TYPE_VERSION_NEW:
        path = os.path.join(input_args.latest_policy_object, filename)
    if os.path.exists(path):
        return path
    else:
        raise Exception(-1)


def flex_check(input_args, is_developer):
    old_type_set = set()
    new_type_set = set()

    old_file_path = input_args.compat_policy_object
    new_file_path = input_args.latest_policy_object

    if input_args.components == "default":
        if is_developer:
            old_file_path = os.path.join(old_file_path, DEVELOPER_SUB_PATH)
            new_file_path = os.path.join(new_file_path, DEVELOPER_SUB_PATH)
            if not os.path.exists(old_file_path) or not os.path.exists(new_file_path):
                print("[INFO] {} or {} no found, developer mode not supported.".format(
                    old_file_path, new_file_path))
        old_type_set = get_type_set(os.path.join(old_file_path, "system.cil"))
        new_type_set = get_type_set(os.path.join(new_file_path, "system.cil"))

        old_vendor_type_set = get_type_set(os.path.join(old_file_path, "vendor.cil"))
        new_vendor_type_set = get_type_set(os.path.join(new_file_path, "vendor.cil"))
        
        old_type_set = old_type_set & old_vendor_type_set
        new_type_set = new_type_set & new_vendor_type_set
    else:
        all_cil_files = []
        all_cil_files += PUBLIC_CIL_FILES
        if is_developer:
            all_cil_files += DEVELOPER_PUBLIC_CIL_FILES

        for cil_file in PUBLIC_CIL_FILES:
            old_policy_file = os.path.join(old_file_path, cil_file)
            new_policy_file = os.path.join(new_file_path, cil_file)

            if not os.path.exists(old_policy_file) or not os.path.exists(new_policy_file):
                print("[ERROR] {} or {} no found.".format(old_policy_file, new_policy_file))
                continue
            old_type_set.update(get_type_set(old_policy_file))
            new_type_set.update(get_type_set(new_policy_file))

    if input_args.use_mode == "generate":
        generate_compat_cil_file(input_args, old_type_set, new_type_set, is_developer)
    elif input_args.use_mode == "check":
        check_compact_cil_file(input_args, old_type_set, new_type_set, is_developer)
        print("check success")
    else:
        print("[ERROR] Unsupport use mode.")
        raise Exception(-1)


def parse_args():
    parser = argparse.ArgumentParser()

    # use for build framework
    parser.add_argument('--depfile', help='depfile')
    parser.add_argument('--output-file', help='output file')

    parser.add_argument(
        "--components", help="system or default", required=True
    )
    parser.add_argument(
        '--compat-policy-object', help='the compat policy output path', required=True)
    parser.add_argument(
        '--latest-policy-object', help='the latest compiled policy object', required=True)
    parser.add_argument(
        '--system-compact-object', help='the compiled system compatible policy object')
    parser.add_argument(
        '--compat-version', help='compat version', required=True)
    parser.add_argument('--use-mode',
                        help='generate or check campact policy', required=True)
    parser.add_argument(
        '--compat-cil-path', help='compatible cil path, input in check mode '\
        "and output in generation mode", required=True)
    parser.add_argument('--output-path',
                        help='output path for intermediate files and cils', required=True)
    
    return parser.parse_args()


def check_and_prepare(input_args):
    if input_args.use_mode == "generate" and not input_args.compat_policy_object:
        print("[ERROR] need --compat-policy-object in generation mode.")
        raise Exception(-1)
    # check output path
    if not os.path.exists(input_args.output_path):
        os.makedirs(input_args.output_path)

    if input_args.components == "vendor":
        print("no need to check flex")
        return

    interpath = os.path.join(input_args.output_path, "intermediate")
    clear_and_make_dir(interpath)


if __name__ == "__main__":
    input_args = parse_args()
    if input_args.depfile:
        dep_file = find.get_all_sepolicy_file(input_args.sepolicy_dir_lists)
        dep_file.sort()
        build_utils.write_depfile(input_args.depfile, input_args.output_file, dep_file, add_pydeps=False)
    
    check_and_prepare(input_args)
    flex_check(input_args, False)
    flex_check(input_args, True)