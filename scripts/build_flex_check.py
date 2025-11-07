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
import build_policy_api
import sys
sys.path.append(os.path.join(os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))), "build"))
from scripts.util import build_utils
import shutil
import find

CIL_FILES = ["public.cil", "public_common.cil", "developer/public.cil"]


TYPE_VERSION_OLD = 0
TYPE_VERSION_NEW = 1


def get_type_set(cil_file_input):
    pattern_type = re.compile(r'^\(type (.*)\)$')
    type_set = set()
    with open(cil_file_input, 'r', encoding='utf-8') as cil_read:
        for line in cil_read:
            match_type = pattern_type.match(line.strip())
            if match_type:
                type_set.add(match_type.group(1))
    return type_set


def get_types_in_mapping(cil_file_input):
    pattern_type = re.compile(r'^\(type (.*)\)$')
    pattern_typeattribute = re.compile(r'^\(typeattributeset\s+(.+?)\s+\((.+?)\)\)')
    type_set = set()
    with open(cil_file_input, 'r', encoding='utf-8') as cil_read:
        for line in cil_read:
            line = line.strip()
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
                    type_set.update(set(match_typeattribute.group(2).split()))
                else:
                    print("[ERROR] parse line = {}".format(line))
                    raise Exception(-1)
    return type_set


def compat_old_to_base(old_type_set, base_type_set, mapping):
    violators = []
    old_types = old_type_set - base_type_set
    for types in old_types:
        if types not in mapping:
            violators.append(types)
    return violators


def compat_base_to_old(old_type_set, base_type_set, mapping):
    violators = []
    base_types = base_type_set - old_type_set
    for types in base_types:
        if types not in mapping:
            violators.append(types)
    return violators



def check_policy_flex_test(old_type_set, base_type_set, mapping,
    old_diff_cill_file, base_diff_cil_file):
    removed = compat_old_to_base(old_type_set, base_type_set, mapping)
    added = compat_base_to_old(old_type_set, base_type_set, mapping)

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
            .format(old_diff_cill_file))
        print("\t 2. add it to ignore policies '{}' if it is a new type"
            .format(base_diff_cil_file))


def get_mapping_from_cil(old_diff_cill_file, base_diff_cil_file, mapping_dir):
    with open(mapping_dir, 'w', encoding='utf-8') as file, \
         open(old_diff_cill_file, 'r', encoding='utf-8') as olds, \
         open(base_diff_cil_file, 'r', encoding='utf-8') as bases:
        for old in olds:
            file.write(old)
        file.write('\n\n')
        for base in bases:
            file.write(base)


def generate_compatible_cil(input_args, old_type_set, base_type_set, old_diff_cil_file):
    if os.path.exists(old_diff_cil_file):
        print("[INFO] Override file {}".format(old_diff_cil_file))
        os.remove(old_diff_cil_file)

    types_output = ''
    deleted_types = old_type_set - base_type_set
    for label in deleted_types:
        types_output += '(type ' + label + ')\n'
    with open(old_diff_cil_file, 'w', encoding='utf-8') as outfile:
        outfile.write('\n' + types_output)

    version_cil = os.path.join(get_intermediate_path(input_args), "verison",
        "compatible", input_args.compat_version + '.cil')
    if os.path.exists(version_cil):
        with open(version_cil, 'r', encoding='utf-8') as infile, \
            open(old_diff_cil_file, 'a', encoding='utf-8') as outfile:
            for line in infile:
                outfile.write(line)
    else:
        print("[ERROR] cannot find path {}".format(version_cil))
        raise Exception(-1)


def generate_ignore_cil(input_args, old_type_set, base_type_set, base_diff_cil_file):
    if os.path.exists(base_diff_cil_file):
        print("[INFO] Override file {}".format(base_diff_cil_file))
        os.remove(base_diff_cil_file)
    new_types = base_type_set - old_type_set
    with open(base_diff_cil_file, 'w', encoding='utf-8') as outfile:
        outfile.write('(typeattribute new_objects)\n')
        outfile.write('(typeattributeset new_objects (')
        outfile.write(' '.join(new_types))
        outfile.write('))')


def generate_compat_cil_file(input_args, old_type_set, base_type_set, old_diff_cill_file, base_diff_cil_file):
    generate_compatible_cil(input_args, old_type_set, base_type_set, old_diff_cill_file)
    generate_ignore_cil(input_args, old_type_set, base_type_set, base_diff_cil_file)


def get_intermediate_path(input_args):
    return os.path.join(input_args.output_path, "intermediate")


def get_file_path(input_args, version, filename):
    path = ""
    if version == TYPE_VERSION_OLD:
        path = os.path.join(get_intermediate_path(input_args), "old", filename)
    elif version == TYPE_VERSION_NEW:
        path = os.path.join(os.path.dirname(input_args.latest_policy_object), filename)
    if os.path.exists(path):
        return path
    else:
        raise Exception(-1)


def flex_test(input_args):
    old_type_set = set()
    base_type_set = set()
    if input_args.components == "default":
        old_type_set = get_type_set(get_file_path(input_args, TYPE_VERSION_OLD, "system.cil"))
        base_type_set = get_type_set(get_file_path(input_args, TYPE_VERSION_NEW, "system.cil"))

        old_vendor_type_set = get_type_set(get_file_path(input_args, TYPE_VERSION_OLD, "vendor.cil"))
        base_vendor_type_set = get_type_set(get_file_path(input_args, TYPE_VERSION_NEW, "vendor.cil"))
        
        old_type_set = old_type_set & old_vendor_type_set
        base_type_set = base_type_set & base_vendor_type_set
    else:
        for cil_file in CIL_FILES:
            old_policy_file = get_file_path(input_args, TYPE_VERSION_OLD, cil_file)
            base_policy_file = get_file_path(input_args, TYPE_VERSION_NEW, cil_file)

            if not os.path.exists(old_policy_file) or not os.path.exists(base_policy_file):
                print("[ERROR] {} or {} no found.".format(old_policy_dir, base_policy_file))
                continue
            old_type_set.update(get_type_set(old_policy_file))
            base_type_set.update(get_type_set(base_policy_file))

    old_diff_cill_file = os.path.join(input_args.source_root_dir, 
            input_args.compat_cil_path, input_args.compat_version + ".cil")
    base_diff_cil_file = os.path.join(input_args.source_root_dir, 
        input_args.compat_cil_path, input_args.compat_version + "_ignore.cil")

    if input_args.use_mode == "generate":
        generate_compat_cil_file(input_args, old_type_set, base_type_set, old_diff_cill_file, base_diff_cil_file)
    elif input_args.use_mode == "check":
        if not os.path.exists(old_diff_cill_file) or not os.path.exists(base_diff_cil_file):
            print("[ERROR] {} or {} is not exists".format(old_diff_cill_file, base_diff_cil_file))
            raise Exception(-1)
        mapping_file = os.path.join(get_intermediate_path(input_args), 'mapping.cil')
        get_mapping_from_cil(old_diff_cill_file, base_diff_cil_file, mapping_file)
        mapping = get_types_in_mapping(mapping_file)

        check_policy_flex_test(old_type_set, base_type_set, mapping,
            old_diff_cill_file, base_diff_cil_file)

    else:
        print("[ERROR] Unsupport use mode.")
        raise Exception(-1)


def parse_args():
    parser = argparse.ArgumentParser()

    # argument to build policy
    parser.add_argument(
        '--dst-file', help='the policy dest path')
    parser.add_argument('--tool-path',
                        help='the policy tool bin path', required=True)
    parser.add_argument('--source-root-dir',
                        help='prj root path', required=True)
    parser.add_argument('--policy_dir_list',
                        help='policy dirs need to be included', required=True)
    parser.add_argument('--debug-version',
                        help='build for debug target', required=True)
    parser.add_argument('--updater-version',
                        help='build for updater target', required=True)
    parser.add_argument('--components',
                        help='system or vendor or default', required=True)
    parser.add_argument('--vendor-policy-version',
                        help='plat version of vendor policy', required=False)
    parser.add_argument('--product-args',
                        help='extra product macros for m4', required=False, action='append')
    parser.add_argument('--sepolicy-dir-lists',
                        help='sepolicy dir lists', required=True)

    # use for build framework
    parser.add_argument('--depfile', help='depfile')
    parser.add_argument('--output-file', help='output file')

    # use for compat policies build
    parser.add_argument('--policy-path',
                        help='use to build policy, no usage for input')
    parser.add_argument(
        '--compat-version-policy', help='the compat policy output path', required=True)
    parser.add_argument(
        '--compat-cil-path', help='compatible cil path, input in check mode '\
        "and output in generation mode", required=True)
    parser.add_argument(
        '--compat-version', help='compat version', required=True)
    parser.add_argument(
        '--latest-policy-object', help='the latest compiled policy object')
    parser.add_argument(
        '--latest-policy-path', help='the latest policy path')
    parser.add_argument('--use-mode',
                        help='generate or check campact policy', required=True)
    parser.add_argument('--output-path',
                        help='output path for intermediate files and cils', required=True)
    
    return parser.parse_args()


def clear_and_make_dir(path):
    if os.path.isfile(path):
        with open(path, "w"):
            pass
    elif os.path.isdir(path):
        shutil.rmtree(path)
    os.makedirs(path)


def to_compile_policy(policy_path, interpath, dirname):
    input_args.policy_path = policy_path
    policy_object_path = os.path.join(interpath, dirname)
    clear_and_make_dir(policy_object_path)
    input_args.dst_file = os.path.join(policy_object_path, "policy.31")
    build_policy_api.main(input_args)
    return input_args.dst_file


def check_and_prepare(input_args):
    # check output path
    if not os.path.exists(input_args.output_path):
        os.makedirs(input_args.output_path)

    interpath = os.path.join(input_args.output_path, "intermediate")
    clear_and_make_dir(interpath)

    # check and make lasted policy object
    if not input_args.latest_policy_object and not input_args.latest_policy_path:
        print("[ERROR] --latest-policy-object and --latest-policy-path must provide one")
        raise Exception(-1)
    else:
        if not input_args.latest_policy_object:
            input_args.latest_policy_object = to_compile_policy(
                input_args.latest_policy_path, interpath, "lasted")
    # compile old policy
    old_path = to_compile_policy(input_args.compat_version_policy, interpath, "old")

    #compile system policy of compatible
    if input_args.use_mode == "generate":
        current_components = input_args.components
        input_args.components = "system"
        input_args.vendor_policy_version = input_args.compat_version
        to_compile_policy(input_args.compat_version_policy, interpath, "verison")
        input_args.components = current_components


if __name__ == "__main__":
    input_args = parse_args()
    if input_args.depfile:
        dep_file = find.get_all_sepolicy_file(input_args.sepolicy_dir_lists)
        dep_file.sort()
        build_utils.write_depfile(input_args.depfile, input_args.output_file, dep_file, add_pydeps=False)
    
    check_and_prepare(input_args)
    flex_test(input_args)
