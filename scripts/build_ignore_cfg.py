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

import os
import argparse


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dst-dir", help="the output dest path", required=True)
    parser.add_argument("--source-root-dir", help="project root path", required=True)
    parser.add_argument(
        "--policy-dir-list", help="policy dirs need to be included", required=True
    )
    parser.add_argument(
        "--components", help="system or vendor or default", required=True
    )
    return parser.parse_args()


def prepare_build_path(dir_list, root_dir, build_dir_list):
    build_ignore_cfg_list = [
        "base/security/selinux_adapter/sepolicy/base",
        "base/security/selinux_adapter/sepolicy/ohos_policy",
    ]
    build_ignore_cfg_list += dir_list.split(":")

    for i in build_ignore_cfg_list:
        if not i or i == "default":
            continue
        path = os.path.join(root_dir, i)
        if os.path.exists(path):
            build_dir_list.append(path)
        else:
            raise Exception(f"following path not exists!! {path}")


def check_ignore_file(ignore_file, err_msg):
    """
    Check the format of ignore_cfg file.
    :param ignore_file: ignore_file
    :return:
    """
    err = ""
    lines = []
    with open(ignore_file, "rb") as fp:
        lines = fp.readlines()
    if len(lines) == 0:
        return
    last_line = lines[-1]
    if b"\n" not in last_line:
        err = "".join((ignore_file, " : need an empty line at end "))
    for line in lines:
        strip_line = line.strip()
        if not strip_line:
            continue
        if line.endswith(b"\r\n") or line.endswith(b"\r"):
            err = "".join((ignore_file, " : must be unix format"))
            break
        if strip_line in [b"/", b"/*"]:
            err = "".join((ignore_file, " : line must not be only / or /*"))
            break
        if not (strip_line.endswith(b"/") or strip_line.endswith(b"/*")):
            err = "".join((ignore_file, " : line must end with / or /*"))
            break
    if err:
        err_msg.append(err)


def traverse_folder_in_type(search_dir_list, file_suffix):
    """
    for special folder search_dir, find all files endwith file_suffix.
    :param search_dir: path to search
    :param file_suffix: postfix of file name
    :return: file list
    """
    err_msg = []
    ignore_cfg_file_list = []
    for item in search_dir_list:
        for root, _, files in sorted(os.walk(item)):
            filtered_files = [f for f in files if f == file_suffix]
            for each_file in filtered_files:
                file_list_path = os.path.join(root, each_file)
                check_ignore_file(file_list_path, err_msg)
                ignore_cfg_file_list.append(file_list_path)
    if err_msg:
        err_str = "\n{}".format("\n".join(err_msg))
        raise Exception(err_str)
    ignore_cfg_file_list.sort()
    return ignore_cfg_file_list


def check_and_add_line(lines, line):
    line = line.strip()
    if not line:
        return
    for existing_line in lines[:]:
        if len(line) >= len(existing_line) and line.startswith(existing_line):
            return
        elif len(line) < len(existing_line) and existing_line.startswith(line):
            lines.remove(existing_line)
            lines.append(line)
            return
    lines.append(line)


def get_path_lines(ignore_cfg_list):
    lines = []
    for ignore_cfg in ignore_cfg_list:
        with open(ignore_cfg, "r") as src_file:
            for line in src_file:
                check_and_add_line(lines, line)
    return lines


def filter_and_write_to_dst(lines, dst_file):
    fd = os.open(dst_file, os.O_WRONLY | os.O_CREAT, 0o664)
    with os.fdopen(fd, "w") as dst_f:
        dst_f.truncate(0)
        for line in lines:
            if line and not line.startswith("#"):
                line = "".join([line, "\n"])
                dst_f.write(line)


def combine_ignore_cfg(ignore_cfg_list, combined_ignore_cfg):
    lines = get_path_lines(ignore_cfg_list)
    filter_and_write_to_dst(lines, combined_ignore_cfg)


def traverse_folder_in_dir_name(search_dir, folder_suffix):
    folder_list = []
    for root, dirs, _ in sorted(os.walk(search_dir)):
        for dir_i in dirs:
            if dir_i == folder_suffix:
                folder_list.append(os.path.join(root, dir_i))
    return folder_list


def build_ignore_cfg(output_path, folder_list):
    combined_ignore_cfg = os.path.join(output_path, "ignore_cfg")
    ignore_cfg_list = traverse_folder_in_type(folder_list, "ignore_cfg")
    combine_ignore_cfg(ignore_cfg_list, combined_ignore_cfg)


def main(args):
    output_path = args.dst_dir
    print("output_path: ", output_path)
    policy_path = []
    prepare_build_path(args.policy_dir_list, args.source_root_dir, policy_path)
    print("policy_path: ", policy_path)

    folder_list = []
    for item in policy_path:
        public_ = traverse_folder_in_dir_name(item, "public")
        if args.components == "system":
            system_policy = traverse_folder_in_dir_name(item, "system")
            folder_list += public_ + system_policy
        elif args.components == "vendor":
            vendor_policy = traverse_folder_in_dir_name(item, "vendor")
            folder_list += public_ + vendor_policy
        else:
            system_policy = traverse_folder_in_dir_name(item, "system")
            vendor_policy = traverse_folder_in_dir_name(item, "vendor")
            folder_list += public_ + system_policy + vendor_policy

    build_ignore_cfg(output_path, folder_list)
    print("build_ignore_cfg done")


if __name__ == "__main__":
    input_args = parse_args()
    main(input_args)
