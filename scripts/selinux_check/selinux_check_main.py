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
from check_common import read_json_file, run_command


def get_request_args(args, request):
    arg_list = request.split()
    request_args = []
    for arg in arg_list:
        if arg == "--file_contexts":
            request_args.append(arg)
            request_args.append(os.path.join(args.output_path, "file_contexts"))
        if arg == "--cil_file":
            request_args.append(arg)
            request_args.append(os.path.join(args.output_path, "all.cil"))
            request_args.append("--developer_cil_file")
            request_args.append(os.path.join(args.output_path, "developer/all.cil"))
    return request_args


def build_cil(args):
    check_policy_cmd = [os.path.join(args.tool_path, "checkpolicy"),
                        "-b", args.user_policy,
                        "-M", "-C", "-S", "-O",
                        "-o", os.path.join(args.output_path, "all.cil")]
    run_command(check_policy_cmd)
    check_policy_cmd = [os.path.join(args.tool_path, "checkpolicy"),
                        "-b", args.developer_policy,
                        "-M", "-C", "-S", "-O",
                        "-o", os.path.join(args.output_path, "developer/all.cil")]
    run_command(check_policy_cmd)


def get_policy_dir_list(args):
    path_list = ["base/security/selinux_adapter/sepolicy"]
    path_list += args.policy_dir_list.split(":")

    build_dir_list = []
    for i in path_list:
        if i == "" or i == "default":
            continue
        path = os.path.join(args.source_root_dir, i)
        if (os.path.exists(path)):
            build_dir_list.append(path)
        else:
            print("following path not exists {}".format(path))
            raise Exception(-1)

    return build_dir_list


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output-path', help='the selinux compile output path', required=True)
    parser.add_argument('--source-root-dir', help='the project root path', required=True)
    parser.add_argument('--selinux-check-config', help='the selinux check config file path', required=True)
    parser.add_argument('--user-policy', help='the user policy file', required=True)
    parser.add_argument('--developer-policy', help='the developer policy file', required=True)
    parser.add_argument('--tool-path', help='the policy tool bin path', required=True)
    parser.add_argument('--policy-dir-list', help='policy dirs need to be included', required=True)
    return parser.parse_args()


if __name__ == "__main__":
    input_args = parse_args()
    build_cil(input_args)
    policy_dir_list = get_policy_dir_list(input_args)
    check_config = read_json_file(os.path.join(input_args.source_root_dir, input_args.selinux_check_config))
    check_list = check_config.get("selinux_check")
    for check in check_list:
        script = os.path.join(input_args.source_root_dir, check.get("script"))
        cmd = ["python", script]
        cmd.extend(get_request_args(input_args, check.get("args")))
        extra_args = check.get("extra_args").split()
        if len(extra_args):
            cmd.extend(extra_args)
        cmd.extend(["--policy-dir-list", ":".join(policy_dir_list)])
        run_command(cmd)
