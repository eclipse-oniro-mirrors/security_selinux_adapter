#!/usr/bin/env python
# coding: utf-8

"""
Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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
import re
import subprocess
import tempfile
import shutil
import build_policy_api


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--dst-file', help='the policy dest path', required=True)
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
    return parser.parse_args()


if __name__ == "__main__":
    input_args = parse_args()
    build_policy_api.main(input_args)
