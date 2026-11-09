#!/usr/bin/env python
# coding: utf-8

"""
Copyright (c) 2023-2026 Huawei Device Co., Ltd.
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


def _relative_depfile_inputs(paths):
    result = []
    for path in paths:
        try:
            result.append(os.path.relpath(path))
        except ValueError:
            result.append(path)  # Different Windows drives cannot be rebased.
    return sorted(result)


def checker_dependencies(args, checks, policy_directories):
    """Track checker implementation/data without replacing its argument policy.

    Checkers may declare additional source-root-relative dependency paths in
    their optional ``inputs`` list. Existing configurations remain valid.
    """
    source_root = os.path.abspath(args.source_root_dir)
    dependencies = {
        os.path.join(source_root, args.selinux_check_config),
        os.path.abspath(args.user_policy), os.path.abspath(args.developer_policy),
        os.path.abspath(os.path.join(args.tool_path, "checkpolicy")),
    }
    roots = {os.path.dirname(os.path.abspath(__file__)), *policy_directories}
    for check in checks:
        script = os.path.join(source_root, check["script"])
        roots.add(os.path.dirname(script))
        dependencies.add(script)
        declared = check.get("inputs", [])
        if not isinstance(declared, list) or any(not isinstance(item, str) for item in declared):
            raise ValueError("checker inputs must be a list of dependency paths")
        for path in declared:
            path = os.path.join(source_root, path)
            if os.path.isdir(path):
                roots.add(path)
            else:
                dependencies.add(path)

    def fail(error):
        raise error

    for root in roots:
        for directory, children, files in os.walk(root, onerror=fail):
            children[:] = [name for name in children if name not in (".git", "__pycache__")]
            dependencies.add(directory)
            dependencies.update(os.path.join(directory, name) for name in files
                                if not name.endswith((".pyc", ".pyo")))
    # Context arguments are generated inputs, while all.cil is produced here.
    for name in ("file_contexts", "service_contexts", "hdf_service_contexts",
                 "parameter_contexts", "sehap_contexts"):
        path = os.path.join(args.output_path, "all_" + name)
        if not os.path.exists(path):
            path = os.path.join(args.output_path, name)
        if os.path.exists(path):
            dependencies.add(os.path.abspath(path))
    return dependencies


def append_file_contexts_args(args, request_args):
    request_args.append("--file_contexts")
    file_context_path = os.path.join(args.output_path, "all_file_contexts")
    if not os.path.exists(file_context_path):
        file_context_path = os.path.join(args.output_path, "file_contexts")
    request_args.append(file_context_path)


def append_cil_args(args, request_args):
    request_args.append("--cil_file")
    request_args.append(os.path.join(args.output_path, "all.cil"))
    request_args.append("--developer_cil_file")
    request_args.append(os.path.join(args.output_path, "developer/all.cil"))


def append_all_contexts_args(args, request_args):
    request_args.append("--all_contexts")
    all_contexts_list = []
    contexts_files = ["file_contexts", "service_contexts", "hdf_service_contexts",
                      "parameter_contexts", "sehap_contexts"]
    for contexts_file in contexts_files:
        contexts_path = os.path.join(args.output_path, "all_{}".format(contexts_file))
        if not os.path.exists(contexts_path):
            contexts_path = os.path.join(args.output_path, contexts_file)
        all_contexts_list.append(contexts_path)
    request_args.append(":".join(all_contexts_list))
    append_cil_args(args, request_args)


def get_request_args(args, request):
    arg_list = request.split()
    request_args = []
    for arg in arg_list:
        if arg == "--file_contexts":
            append_file_contexts_args(args, request_args)
        if arg == "--all_contexts":
            append_all_contexts_args(args, request_args)
        if arg == "--cil_file":
            append_cil_args(args, request_args)
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
    parser.add_argument('--dep-target', help='first GN output, relative to the Ninja build directory')
    # Keep previously generated Ninja commands usable until GN regenerates them.
    parser.add_argument('--stamp', help=argparse.SUPPRESS)
    parser.add_argument('--depfile')
    args = parser.parse_args()
    if args.dep_target and args.stamp:
        parser.error('--dep-target and legacy --stamp cannot be used together')
    args.dep_target = args.dep_target or args.stamp
    if args.depfile and not args.dep_target:
        parser.error('--dep-target is required with --depfile')
    return args


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

    if input_args.depfile:
        import sys
        sys.path.insert(0, os.path.join(input_args.source_root_dir, "build"))
        from scripts.util.build_utils import write_depfile
        dependencies = checker_dependencies(input_args, check_list, policy_dir_list)
        write_depfile(input_args.depfile, input_args.dep_target,
                      _relative_depfile_inputs(dependencies), add_pydeps=False)
    # New GN actions use real CIL outputs and never request a completion marker.
    if input_args.stamp:
        os.makedirs(os.path.dirname(os.path.abspath(input_args.stamp)), exist_ok=True)
        with open(input_args.stamp, 'w', encoding='utf-8'):
            pass
