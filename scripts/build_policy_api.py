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

import os
import re
import shutil
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
import copy

SYSTEM_CIL_HASH = "system.cil.sha256"
PREBUILD_SEPOLICY_SYSTEM_CIL_HASH = "prebuild_sepolicy.system.cil.sha256"

# list of all macros and te for sepolicy build
SEPOLICY_TYPE_LIST = ["security_classes",
                      "initial_sids",
                      "access_vectors",
                      "glb_perm_def.spt",
                      "glb_never_def.spt",
                      "mls",
                      "policy_cap",
                      "glb_te_def.spt",
                      "attributes",
                      ".te",
                      "glb_roles.spt",
                      "users",
                      "initial_sid_contexts",
                      "fs_use",
                      "virtfs_contexts",
                      ]

POLICY_TYPE_LIST = ["allow", "auditallow", "dontaudit",
                    "allowx", "auditallowx", "dontauditx",
                    "neverallow", "neverallowx", ]


class PolicyDirList(object):
    def __init__(self, min_policy_dir_list, system_policy_dir_list, vendor_policy_dir_list, public_policy_dir_list):
        self.min_policy_dir_list = min_policy_dir_list
        self.system_policy_dir_list = system_policy_dir_list
        self.vendor_policy_dir_list = vendor_policy_dir_list
        self.public_policy_dir_list = public_policy_dir_list


class PolicyFileList(object):
    def __init__(self, min_policy_file_list, system_policy_file_list, vendor_policy_file_list, public_policy_file_list):
        self.min_policy_file_list = min_policy_file_list
        self.system_policy_file_list = system_policy_file_list
        self.vendor_policy_file_list = vendor_policy_file_list
        self.public_policy_file_list = public_policy_file_list


def traverse_folder_in_dir_name(search_dir, folder_suffix):
    folder_list = []
    for root, dirs, _ in sorted(os.walk(search_dir)):
        for dir_i in dirs:
            if dir_i == folder_suffix:
                folder_list.append(os.path.join(root, dir_i))
    return folder_list


def traverse_folder_in_type(search_dir, file_suffix, build_root):
    policy_file_list = []
    flag = 0
    for root, _, files in sorted(os.walk(search_dir)):
        for each_file in files:
            if each_file.endswith(file_suffix):
                path = os.path.join(root, each_file)
                rel_path = os.path.relpath(path, build_root)
                flag |= check_empty_row(rel_path)
                policy_file_list.append(rel_path)
    policy_file_list.sort()
    return policy_file_list, flag


def traverse_file_in_each_type(folder_list, sepolicy_type_list, build_root):
    policy_files_list = []
    err = 0
    for policy_type in sepolicy_type_list:
        for folder in folder_list:
            type_file_list, flag = traverse_folder_in_type(
                folder, policy_type, build_root)
            err |= flag
            if len(type_file_list) == 0:
                continue
            policy_files_list.extend(type_file_list)
    if err:
        raise Exception(err)
    return policy_files_list


def check_empty_row(policy_file):
    """
    Check whether the last line of te file is empty.
    :param policy_file: te file
    :return:
    """
    err = 0
    with open(policy_file, 'r') as fp:
        lines = fp.readlines()
        if len(lines) == 0:
            return 0
        last_line = lines[-1]
        if '\n' not in last_line:
            print("".join([policy_file, " : need an empty line at end\n"]))
            err = 1
    return err


def run_command(in_cmd):
    cmdstr = " ".join(in_cmd)
    ret = subprocess.run(cmdstr, shell=True).returncode
    if ret != 0:
        raise Exception(ret)


def build_conf(args, output_conf, file_list, with_developer=False):
    m4_args = ["-D", "build_with_debug=" + args.debug_version]
    m4_args += ["-D", "build_with_updater=" + args.updater_version]
    if with_developer:
        m4_args += ["-D", "build_with_developer=enable"]
    build_conf_cmd = ["m4", "-s", "--fatal-warnings"] + m4_args + file_list
    with open(output_conf, 'w') as fd:
        ret = subprocess.run(build_conf_cmd, shell=False, stdout=fd).returncode
        if ret != 0:
            raise Exception(ret)


def build_cil(args, output_cil, input_conf):
    check_policy_cmd = [os.path.join(args.tool_path, "checkpolicy"),
                        input_conf,
                        "-M -C -c 31",
                        "-o " + output_cil]
    run_command(check_policy_cmd)


def add_version(version, string):
    return "".join([string, "_", version])


def simplify_string(string):
    return string.replace('(', '').replace(')', '').replace('\n', '')


def deal_with_roletype(version, cil_write, elem_list, type_set, file, line):
    if len(elem_list) < 3:
        print('Error: invalid roletype in %s:%d' % (file, line))
        raise Exception(1)

    sub_string = simplify_string(elem_list[2])
    if sub_string in type_set:
        cil_write.write('(typeattribute ' + add_version(version, sub_string) + ')\n')
        elem_list[2] = elem_list[2].replace(
            sub_string, add_version(version, sub_string))
    cil_write.write(" ".join(elem_list))


def deal_with_typeattribute(version, cil_write, elem_list, type_set, file, line):
    if len(elem_list) < 2:
        print('Error: invalid typeattribute in %s:%d' % (file, line))
        raise Exception(1)

    sub_string = simplify_string(elem_list[1])
    if sub_string.startswith("base_typeattr_"):
        elem_list[1] = elem_list[1].replace(
            sub_string, add_version(version, sub_string))
    cil_write.write(" ".join(elem_list))


def deal_with_typeattributeset(version, cil_write, elem_list, type_set, file, line):
    if len(elem_list) < 2:
        print('Error: invalid typeattributeset in %s:%d' % (file, line))
        raise Exception(1)

    for index, elem in enumerate(elem_list[1:]):
        sub_string = simplify_string(elem)
        if sub_string.startswith("base_typeattr_") or sub_string in type_set:
            elem_list[index + 1] = elem.replace(sub_string, add_version(version, sub_string))
    cil_write.write(" ".join(elem_list))


def deal_with_policy(version, cil_write, elem_list, type_set, file, line):
    if len(elem_list) < 4:
        print('Error: invalid policy in %s:%d' % (file, line))
        raise Exception(1)

    for index, elem in enumerate(elem_list[1:3]):
        sub_string = simplify_string(elem)
        if sub_string.startswith("base_typeattr_") or sub_string in type_set:
            elem_list[index + 1] = elem.replace(sub_string, add_version(version, sub_string))
    cil_write.write(" ".join(elem_list))


def deal_with_type(version, cil_write, elem_list, file, line):
    if len(elem_list) < 2:
        print('Error: invalid type in %s:%d' % (file, line))
        raise Exception(1)

    sub_string = simplify_string(elem_list[1])
    cil_write.write(" ".join(['(typeattributeset', add_version(version, sub_string), '(', sub_string, '))\n']))
    cil_write.write(" ".join(['(expandtypeattribute', '(', add_version(version, sub_string), ') true)\n']))
    cil_write.write(" ".join(['(typeattribute', add_version(version, sub_string), ')\n']))


def build_version_cil(version, cil_file_input, cil_file_output, type_set):
    index = 0
    with open(cil_file_input, 'r') as cil_read, open(cil_file_output, 'w') as cil_write:
        for line in cil_read:
            index += 1
            if not line.startswith('('):
                continue

            elem_list = line.split(' ')
            if not elem_list:
                continue

            if elem_list[0] == '(type':
                cil_write.write(line)
            elif elem_list[0] == '(roletype':
                deal_with_roletype(version, cil_write, elem_list, type_set, cil_file_input, line)
            elif elem_list[0] == '(typeattribute':
                deal_with_typeattribute(version, cil_write, elem_list, type_set, cil_file_input, line)
            elif elem_list[0] == '(typeattributeset':
                deal_with_typeattributeset(version, cil_write, elem_list, type_set, cil_file_input, line)
            elif simplify_string(elem_list[0]) in POLICY_TYPE_LIST:
                deal_with_policy(version, cil_write, elem_list, type_set, cil_file_input, line)
            else:
                cil_write.write(line)


def build_type_version_cil(version, cil_file_input, cil_file_output):
    index = 0
    with open(cil_file_input, 'r') as cil_read, open(cil_file_output, 'w') as cil_write:
        for line in cil_read:
            index += 1
            if not line.startswith('('):
                continue

            elem_list = line.split(' ')
            if not elem_list:
                continue

            if elem_list[0] == '(type':
                deal_with_type(version, cil_write, elem_list, line, index)


def get_type_set(cil_file_input):
    pattern_type = re.compile(r'^\(type (.*)\)$')
    pattern_typeattribute = re.compile(r'^\(type_attribute (base_typeattr_[0-9]+)\)$')
    type_set = set()
    with open(cil_file_input, 'r') as cil_read:
        for line in cil_read:
            match_type = pattern_type.match(line)
            match_typeattribute = pattern_typeattribute.match(line)
            if match_type:
                type_set.add(match_type.group(1))
            elif match_typeattribute:
                type_set.add(match_typeattribute.group(1))
    return type_set


def add_base_typeattr_prefix(cil_file, prefix):
    with open(cil_file, 'r') as cil_read:
        data = cil_read.read()
        data = data.replace('base_typeattr_', '_'.join([prefix, 'base_typeattr_']))
        with open(cil_file, 'w') as cil_write:
            cil_write.write(data)


def build_binary_policy(tool_path, output_policy, check_neverallow, cil_list):
    build_policy_cmd = [os.path.join(tool_path, "secilc"),
                        " ".join(cil_list),
                        "-m -M true -G -c 31",
                        "-f /dev/null",
                        "-o " + output_policy]
    if not check_neverallow:
        build_policy_cmd.append("-N")
    run_command(build_policy_cmd)


def prepare_build_path(dir_list, root_dir, build_dir_list, sepolicy_path):
    build_policy_list = [os.path.join(sepolicy_path, "base"), os.path.join(sepolicy_path, "ohos_policy")]
    build_policy_list += dir_list.split(":")

    for i in build_policy_list:
        if i == "" or i == "default":
            continue
        path = os.path.join(root_dir, i)
        if (os.path.exists(path)):
            build_dir_list.append(path)
        else:
            print("following path not exists!! {}".format(path))
            exit(-1)


def get_policy_dir_list(args):
    sepolicy_path = os.path.join(args.source_root_dir, "base/security/selinux_adapter/sepolicy/")
    dir_list = []
    prepare_build_path(args.policy_dir_list, args.source_root_dir, dir_list, sepolicy_path)
    min_policy_dir_list = [os.path.join(sepolicy_path, "min")]
    system_policy = []
    public_policy = []
    vendor_policy = []

    for item in dir_list:
        public_policy += traverse_folder_in_dir_name(item, "public")
        system_policy += traverse_folder_in_dir_name(item, "system")
        vendor_policy += traverse_folder_in_dir_name(item, "vendor")

    # list of all policy folders
    system_policy_dir_list = public_policy + system_policy
    vendor_policy_dir_list = public_policy + vendor_policy + min_policy_dir_list
    public_policy_dir_list = public_policy + min_policy_dir_list

    # add temp dirs base/te folders
    system_policy_dir_list.append(os.path.join(sepolicy_path, "base/te"))
    vendor_policy_dir_list.append(os.path.join(sepolicy_path, "base/te"))
    public_policy_dir_list.append(os.path.join(sepolicy_path, "base/te"))

    return PolicyDirList(min_policy_dir_list, system_policy_dir_list, vendor_policy_dir_list, public_policy_dir_list)


def get_policy_file_list(args, dir_list_object):
    build_root = os.path.abspath(os.path.join(args.tool_path, "../../.."))
    # list of all policy files
    system_policy_file_list = traverse_file_in_each_type(
        dir_list_object.system_policy_dir_list, SEPOLICY_TYPE_LIST, build_root)
    vendor_policy_file_list = traverse_file_in_each_type(
        dir_list_object.vendor_policy_dir_list, SEPOLICY_TYPE_LIST, build_root)
    public_policy_file_list = traverse_file_in_each_type(
        dir_list_object.public_policy_dir_list, SEPOLICY_TYPE_LIST, build_root)
    min_policy_file_list = traverse_file_in_each_type(
        dir_list_object.min_policy_dir_list, SEPOLICY_TYPE_LIST, build_root)

    return PolicyFileList(min_policy_file_list, system_policy_file_list, vendor_policy_file_list,
                          public_policy_file_list)


def filter_out(pattern_file, input_file):
    with open(pattern_file, 'r', encoding='utf-8') as pat_file:
        patterns = set(pat_file)
        tmp_output = tempfile.NamedTemporaryFile()
        with open(input_file, 'r', encoding='utf-8') as in_file:
            tmp_output.writelines(line.encode(encoding='utf-8') for line in in_file.readlines()
                                if line not in patterns)
            tmp_output.write("\n".encode(encoding='utf-8'))
            tmp_output.flush()
        shutil.copyfile(tmp_output.name, input_file)


def generate_hash_file(input_file_list, output_file):
    build_policy_cmd = ["cat",
                        " ".join(input_file_list),
                        "| sha256sum",
                        "| cut -d' ' -f1",
                        ">",
                        output_file]
    run_command(build_policy_cmd)


def generate_version_file(args, output_file):
    cmd = ["echo", args.vendor_policy_version,
           ">", output_file]
    run_command(cmd)


def generate_default_policy(args, policy, cil_list, with_developer=False):
    if with_developer:
        output_path = os.path.join(os.path.abspath(os.path.dirname(args.dst_file)), "developer/")
        if not os.path.exists(output_path):
            os.makedirs(output_path)
    else:
        output_path = os.path.abspath(os.path.dirname(args.dst_file))
    system_output_conf = os.path.join(output_path, "system.conf")
    vendor_output_conf = os.path.join(output_path, "vendor.conf")
    min_output_conf = os.path.join(output_path, "min.conf")

    system_cil_path = os.path.join(output_path, "system.cil")
    vendor_cil_path = os.path.join(output_path, "vendor.cil")
    min_cil_path = os.path.join(output_path, "min.cil")

    # build system.conf
    build_conf(args, system_output_conf, policy.system_policy_file_list, with_developer)
    # build system.cil
    build_cil(args, system_cil_path, system_output_conf)

    # build vendor.conf
    build_conf(args, vendor_output_conf, policy.vendor_policy_file_list, with_developer)
    # build vendor.cil
    build_cil(args, vendor_cil_path, vendor_output_conf)
    add_base_typeattr_prefix(vendor_cil_path, 'vendor')

    # build min.conf
    build_conf(args, min_output_conf, policy.min_policy_file_list)
    # build min.cil
    build_cil(args, min_cil_path, min_output_conf)

    filter_out(min_cil_path, vendor_cil_path)

    cil_list += [vendor_cil_path, system_cil_path]


def generate_special_policy(args, policy, cil_list, with_developer=False):
    if with_developer:
        output_path = os.path.join(os.path.abspath(os.path.dirname(args.dst_file)), "developer/")
        if not os.path.exists(output_path):
            os.makedirs(output_path)
    else:
        output_path = os.path.abspath(os.path.dirname(args.dst_file))

    compatible_dir = os.path.join(output_path, "compatible/")
    if not os.path.exists(compatible_dir):
        os.makedirs(compatible_dir)

    system_output_conf = os.path.join(output_path, "system.conf")
    vendor_output_conf = os.path.join(output_path, "vendor.conf")
    public_output_conf = os.path.join(output_path, "public.conf")
    min_output_conf = os.path.join(output_path, "min.conf")

    vendor_origin_cil_path = os.path.join(output_path, "vendor_origin.cil")
    public_origin_cil_path = os.path.join(output_path, "public_origin.cil")
    min_cil_path = os.path.join(output_path, "min.cil")

    # output file
    system_cil_path = os.path.join(output_path, "system.cil")
    vendor_cil_path = os.path.join(output_path, "vendor.cil")
    public_version_cil_path = os.path.join(output_path, "public.cil")
    type_version_cil_path = os.path.join(output_path, "".join(["compatible/", args.vendor_policy_version, ".cil"]))

    # build system.conf
    build_conf(args, system_output_conf, policy.system_policy_file_list, with_developer)
    # build system.cil
    build_cil(args, system_cil_path, system_output_conf)

    # build min.cil
    build_conf(args, min_output_conf, policy.min_policy_file_list)
    build_cil(args, min_cil_path, min_output_conf)

    # build public.cil
    build_conf(args, public_output_conf, policy.public_policy_file_list, with_developer)
    build_cil(args, public_origin_cil_path, public_output_conf)
    type_set = get_type_set(public_origin_cil_path)
    filter_out(min_cil_path, public_origin_cil_path)
    build_version_cil(args.vendor_policy_version, public_origin_cil_path, public_version_cil_path, type_set)

    # build vendor.cil
    build_conf(args, vendor_output_conf, policy.vendor_policy_file_list, with_developer)
    build_cil(args, vendor_origin_cil_path, vendor_output_conf)
    filter_out(min_cil_path, vendor_origin_cil_path)
    build_version_cil(args.vendor_policy_version, vendor_origin_cil_path, vendor_cil_path, type_set)
    filter_out(public_version_cil_path, vendor_cil_path)

    build_type_version_cil(args.vendor_policy_version, public_origin_cil_path, type_version_cil_path)

    if args.components == "system":
        generate_hash_file([system_cil_path, type_version_cil_path],
                           os.path.join(output_path, SYSTEM_CIL_HASH))

    elif args.components == "vendor":
        generate_hash_file([system_cil_path, type_version_cil_path], os.path.join(
            output_path, PREBUILD_SEPOLICY_SYSTEM_CIL_HASH))

    version_file = os.path.join(output_path, "version")
    generate_version_file(args, version_file)

    cil_list += [vendor_cil_path, system_cil_path, type_version_cil_path, public_version_cil_path]


def compile_sepolicy(args):
    dir_list_object = get_policy_dir_list(args)
    file_list_object = get_policy_file_list(args, dir_list_object)
    cil_list = []
    developer_cil_list = []

    if args.updater_version == "enable":
        generate_default_policy(args, file_list_object, cil_list, False)
        build_binary_policy(args.tool_path, args.dst_file, True, cil_list)
        return

    with ThreadPoolExecutor(max_workers=2) as executor:
        if args.components == "default":
            normal_thread = executor.submit(generate_default_policy, args, file_list_object, cil_list, False)
            developer_thread = executor.submit(generate_default_policy, args, file_list_object,
                                                developer_cil_list, True)
        else:
            normal_thread = executor.submit(generate_special_policy, args, file_list_object, cil_list, False)
            developer_thread = executor.submit(generate_special_policy, args, file_list_object,
                                                developer_cil_list, True)

        for future in as_completed([normal_thread, developer_thread]):
            try:
                future.result()
            except Exception as e:
                raise e

    with ThreadPoolExecutor(max_workers=2) as executor:
        build_normal_thread = executor.submit(build_binary_policy, args.tool_path, args.dst_file, True, cil_list)
        developer_policy_path = os.path.join(os.path.abspath(os.path.dirname(args.dst_file)), "developer/policy.31")
        build_developer_thread = executor.submit(build_binary_policy, args.tool_path, developer_policy_path,
                                                    True, developer_cil_list)

        for future in as_completed([build_normal_thread, build_developer_thread]):
            try:
                future.result()
            except Exception as e:
                raise e


def copy_user_policy(args):
    if args.updater_version == "enable":
        return

    output_path = os.path.abspath(os.path.dirname(args.dst_file))
    if args.debug_version == "enable":
        src_dir = os.path.join(output_path, "pre_check/")
    else:
        src_dir = output_path

    src_policy_path = os.path.join(src_dir, "developer/policy.31")
    dest_policy_path = os.path.join(output_path, "developer/developer_policy")
    shutil.copyfile(src_policy_path, dest_policy_path)

    src_policy_path = os.path.join(src_dir, "policy.31")
    dest_policy_path = os.path.join(output_path, "user_policy")
    shutil.copyfile(src_policy_path, dest_policy_path)


def pre_check(args):
    output_path = os.path.join(os.path.abspath(os.path.dirname(args.dst_file)), "pre_check/")
    if not os.path.exists(output_path):
        os.makedirs(output_path)
    args.dst_file = os.path.join(output_path, "policy.31")

    if args.debug_version == "enable":
        args.debug_version = "disable"
    else:
        args.debug_version = "enable"

    compile_sepolicy(args)


def main(args):
    with ThreadPoolExecutor(max_workers=2) as executor:
        pre_check_args = copy.deepcopy(args)
        pre_check_thread = executor.submit(pre_check, pre_check_args)

        compile_args = copy.deepcopy(args)
        compile_thread = executor.submit(compile_sepolicy, compile_args)

        for future in as_completed([pre_check_thread, compile_thread]):
            try:
                future.result()
            except Exception as e:
                raise e

    copy_user_policy(args)
