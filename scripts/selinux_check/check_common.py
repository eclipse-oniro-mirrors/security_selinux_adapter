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

import json
import os
import subprocess


def read_json_file(input_file):
    data = None
    try:
        with open(input_file, 'r') as input_f:
            data = json.load(input_f)
    except json.decoder.JSONDecodeError:
        print('The file \'{}\' format is incorrect.'.format(input_file))
        raise
    except:
        print('read file \'{}\' failed.'.format(input_file))
        raise
    return data


def read_file(input_file):
    lines = []
    with open(input_file, 'r') as fp:
        for line in fp.readlines():
            lines.append(line.strip())
    return lines


def run_command(in_cmd):
    ret = subprocess.run(in_cmd, shell=False).returncode
    if ret != 0:
        raise Exception(ret)


def check_empty_row(policy_file):
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


def traverse_folder_in_type(search_dir, file_suffix):
    policy_file_list = []
    flag = 0
    for root, _, files in sorted(os.walk(search_dir)):
        for each_file in files:
            if each_file.endswith(file_suffix):
                path = os.path.join(root, each_file)
                flag |= check_empty_row(path)
                policy_file_list.append(path)
    policy_file_list.sort()
    return policy_file_list, flag


def traverse_file_in_each_type(dir_list, file_suffix):
    policy_files_list = []
    err = 0
    folder_list = dir_list.split(":")
    for folder in folder_list:
        type_file_list, flag = traverse_folder_in_type(
            folder, file_suffix)
        err |= flag
        if len(type_file_list) == 0:
            continue
        policy_files_list.extend(type_file_list)
    if err:
        raise Exception(err)
    return policy_files_list
