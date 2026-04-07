#!/usr/bin/env python
# coding: utf-8

"""
Copyright (c) 2026 Huawei Device Co., Ltd.
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
from check_common import read_json_file, traverse_file_in_each_type

VIRTFS_CONTEXTS = "virtfs_contexts"
FILE_CONTEXTS = "file_contexts"
SERVICE_CONTEXTS = "service_contexts"
HDF_SERVICE_CONTEXTS = "hdf_service_contexts"
PARAMETER_CONTEXTS = "parameter_contexts"
SEHAP_CONTEXTS = "sehap_contexts"
CONTEXT_LENGTH_WHITELIST = "context_length_whitelist.json"


class SehapContextEntry:
    def __init__(self, context, line):
        self.context = context
        self.line = line

    def __hash__(self):
        return hash((self.context, self.line))

    def __eq__(self, other):
        if not isinstance(other, SehapContextEntry):
            return False
        return self.context == other.context and self.line == other.line


file_contexts_set = set()
service_contexts_set = set()
hdf_service_contexts_set = set()
parameter_contexts_set = set()
sehap_contexts_set = set()
virtfs_contexts_set = set()

invalid_file_contexts = []
invalid_service_contexts = []
invalid_hdf_service_contexts = []
invalid_parameter_contexts = []
invalid_virtfs_contexts = []
invalid_sehap_contexts = []


def parse_file_contexts(path):
    global file_contexts_set
    if not os.path.exists(path):
        return
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            file_contexts_set.add(parts[-1])


def parse_service_contexts(path):
    global service_contexts_set
    if not os.path.exists(path):
        return
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            service_contexts_set.add(parts[-1])


def parse_hdf_service_contexts(path):
    global hdf_service_contexts_set
    if not os.path.exists(path):
        return
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            hdf_service_contexts_set.add(parts[-1])


def parse_parameter_contexts(path):
    global parameter_contexts_set
    if not os.path.exists(path):
        return
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            parameter_contexts_set.add(parts[-1])


def parse_sehap_contexts(path):
    global sehap_contexts_set
    if not os.path.exists(path):
        return
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if not line.startswith('apl='):
                continue
            parts = line.split()
            apl = None
            type_value = None
            levelFrom = None
            for part in parts:
                if part.startswith('apl='):
                    apl = part.split('=')[1]
                elif part.startswith('type='):
                    type_value = part.split('=')[1]
                elif part.startswith('levelFrom='):
                    levelFrom = part.split('=')[1]
            if not apl or not type_value:
                continue
            context = generate_sehap_context(type_value, levelFrom)
            entry = SehapContextEntry(context, line)
            sehap_contexts_set.add(entry)


def generate_sehap_context(type_value, levelFrom):
    """
    Generate sehap context based on type and levelFrom.
    Generation rules rules reference hap_restore::GetMCSLevel method.
    appId max: 200000, userId max: 65535
    c0=0-255, c1=256-511, c2=512-515, c3=768-1023, c4=1024-1279
    """
    level_map = {
        'app': 's0:x255,x511,x515',
        'user': 's0:x1023,x1279',
        'all': 's0:x255,x511,x515,x1023,x1279'
    }
    
    level = level_map.get(levelFrom, 's0')

    if type_value:
        return 'u:object_r:{}:{}'.format(type_value, level)
    
    return ''


def load_context_whitelist(input_args):
    config_file_list = traverse_file_in_each_type(input_args.policy_dir_list, CONTEXT_LENGTH_WHITELIST)
    context_map = {}
    for config_file in config_file_list:
        baseline_data = read_json_file(config_file)
        if 'whitelist' not in baseline_data:
            continue
        for context_type, items in baseline_data['whitelist'].items():
            if context_type not in context_map:
                context_map[context_type] = set()
            for item in items:
                if isinstance(item, str):
                    context_map[context_type].add(item)
                elif 'context' in item:
                    context_map[context_type].add(item['context'])
    return context_map


def get_virtfs_contexts_data(args):
    global virtfs_contexts_set
    virtfs_contexts_file_list = [input_args.developer_cil_file, input_args.cil_file]
    for path in virtfs_contexts_file_list:
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                if not line.startswith('(genfscon '):
                    continue
                m = re.match(r'\(genfscon\s+(\S+)\s+"([^"]+)"\s+\((\w+)\s+(\w+)\s+(\w+)\s+\(\((\w+)\)\s+\((\w+)\)\)', line)
                if m:
                    user = m.group(3)
                    role = m.group(4)
                    type_ = m.group(5)
                    level = m.group(7)
                    context = '{}:{}:{}:{}'.format(user, role, type_, level)
                    virtfs_contexts_set.add(context)


def parse_all_contexts(input_args):
    contexts_files = input_args.all_contexts.split(':')
    for contexts_file in contexts_files:
        filename = os.path.basename(contexts_file)
        if filename == FILE_CONTEXTS or filename == "all_" + FILE_CONTEXTS:
            parse_file_contexts(contexts_file)
        elif filename == SERVICE_CONTEXTS or filename == "all_" + SERVICE_CONTEXTS:
            parse_service_contexts(contexts_file)
        elif filename == HDF_SERVICE_CONTEXTS or filename == "all_" + HDF_SERVICE_CONTEXTS:
            parse_hdf_service_contexts(contexts_file)
        elif filename == PARAMETER_CONTEXTS or filename == "all_" + PARAMETER_CONTEXTS:
            parse_parameter_contexts(contexts_file)
        elif (filename == SEHAP_CONTEXTS or filename == "all_" + SEHAP_CONTEXTS):
            parse_sehap_contexts(contexts_file)
    
    get_virtfs_contexts_data(input_args)


def check_context_length(max_length, context_whitelist):
    global invalid_file_contexts, invalid_service_contexts, invalid_hdf_service_contexts
    global invalid_parameter_contexts, invalid_virtfs_contexts, invalid_sehap_contexts

    file_whitelist = context_whitelist.get(FILE_CONTEXTS, set())
    for entry in file_contexts_set:
        if len(entry) > max_length and entry not in file_whitelist:
            invalid_file_contexts.append(entry)
    
    service_whitelist = context_whitelist.get(SERVICE_CONTEXTS, set())
    for entry in service_contexts_set:
        if len(entry) > max_length and entry not in service_whitelist:
            invalid_service_contexts.append(entry)
    
    hdf_whitelist = context_whitelist.get(HDF_SERVICE_CONTEXTS, set())
    for entry in hdf_service_contexts_set:
        if len(entry) > max_length and entry not in hdf_whitelist:
            invalid_hdf_service_contexts.append(entry)
    
    param_whitelist = context_whitelist.get(PARAMETER_CONTEXTS, set())
    for entry in parameter_contexts_set:
        if len(entry) > max_length and entry not in param_whitelist:
            invalid_parameter_contexts.append(entry)
    
    virtfs_whitelist = context_whitelist.get(VIRTFS_CONTEXTS, set())
    for entry in virtfs_contexts_set:
        if len(entry) > max_length and entry not in virtfs_whitelist:
            invalid_virtfs_contexts.append(entry)
    
    sehap_whitelist = context_whitelist.get(SEHAP_CONTEXTS, set())
    for entry in sehap_contexts_set:
        if not entry.context:
            continue
        if len(entry.context) > max_length and entry.line not in sehap_whitelist:
            invalid_sehap_contexts.append(entry)


def check_unused_whitelist_entries(context_whitelist, max_length):
    """
    Check if there are unused entries in whitelist configuration.
    Unused entries are those not in actual used contexts or length not exceeding max_length.
    """
    err = False
    
    file_used = set(file_contexts_set)
    service_used = set(service_contexts_set)
    hdf_used = set(hdf_service_contexts_set)
    param_used = set(parameter_contexts_set)
    virtfs_used = set(virtfs_contexts_set)
    sehap_used = set(entry.line for entry in sehap_contexts_set)
    
    used_map = {
        FILE_CONTEXTS: file_used,
        SERVICE_CONTEXTS: service_used,
        HDF_SERVICE_CONTEXTS: hdf_used,
        PARAMETER_CONTEXTS: param_used,
        VIRTFS_CONTEXTS: virtfs_used,
        SEHAP_CONTEXTS: sehap_used
    }
    
    for context_type in [FILE_CONTEXTS, SERVICE_CONTEXTS, HDF_SERVICE_CONTEXTS,
                         PARAMETER_CONTEXTS, VIRTFS_CONTEXTS, SEHAP_CONTEXTS]:
        whitelist = context_whitelist.get(context_type, set())
        used = used_map.get(context_type, set())
        unused = set()
        for item in whitelist:
            if item not in used:
                unused.add(item)
                continue
            if context_type != SEHAP_CONTEXTS and len(item) <= max_length:
                unused.add(item)
        
        if len(unused) > 0:
            err = True
            print("Unused whitelist entries in {}:".format(context_type))
            print("Please check whitelist file: {}".format(CONTEXT_LENGTH_WHITELIST))
            if context_type == SEHAP_CONTEXTS:
                for item in sorted(unused):
                    print("  '{}'".format(item))
            else:
                for item in sorted(unused):
                    print("  Context: '{}' (length: {})".format(item, len(item)))
            print()
    
    return err


def print_invalid_contexts(max_length):
    err = False
    
    if (invalid_file_contexts or invalid_service_contexts or invalid_hdf_service_contexts or invalid_parameter_contexts
        or invalid_virtfs_contexts or invalid_sehap_contexts):
        print("Check context length failed.")

    if len(invalid_file_contexts) > 0:
        err = True
        print("file_contexts context length exceeds {}:".format(max_length))
        print("Please modify context or add to whitelist file: {}".format(CONTEXT_LENGTH_WHITELIST))
        for entry in invalid_file_contexts:
            print("  Context: '{}' (length: {})".format(entry, len(entry)))
        print()
    
    if len(invalid_service_contexts) > 0:
        err = True
        print("service_contexts context length exceeds {}:".format(max_length))
        print("Please modify context or add to whitelist file: {}".format(CONTEXT_LENGTH_WHITELIST))
        for entry in invalid_service_contexts:
            print("  Context: '{}' (length: {})".format(entry, len(entry)))
        print()
    
    if len(invalid_hdf_service_contexts) > 0:
        err = True
        print("hdf_service_contexts context length exceeds {}:".format(max_length))
        print("Please modify context or add to whitelist file: {}".format(CONTEXT_LENGTH_WHITELIST))
        for entry in invalid_hdf_service_contexts:
            print("  Context: '{}' (length: {})".format(entry, len(entry)))
        print()
    
    if len(invalid_parameter_contexts) > 0:
        err = True
        print("parameter_contexts context length exceeds {}:".format(max_length))
        print("Please modify context or add to whitelist file: {}".format(CONTEXT_LENGTH_WHITELIST))
        for entry in invalid_parameter_contexts:
            print("  Context: '{}' (length: {})".format(entry, len(entry)))
        print()
    
    if len(invalid_virtfs_contexts) > 0:
        err = True
        print("virtfs_contexts context length exceeds {}:".format(max_length))
        print("Please modify context or add to whitelist file: {}".format(CONTEXT_LENGTH_WHITELIST))
        for entry in invalid_virtfs_contexts:
            print("  Context: '{}' (length: {})".format(entry, len(entry)))
        print()
    
    if len(invalid_sehap_contexts) > 0:
        err = True
        print("sehap_contexts context length exceeds {}:".format(max_length))
        print("Please modify context or add to whitelist file: {}".format(CONTEXT_LENGTH_WHITELIST))
        for entry in invalid_sehap_contexts:
            print("  Line: '{}', Context: '{}' (length: {})".format(
                entry.line, entry.context, len(entry.context)))
        print()
    
    return err


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--all_contexts', help='the all contexts file path', required=True)
    parser.add_argument('--cil_file', help='the cil file path', required=True)
    parser.add_argument('--developer_cil_file', help='the developer cil file path', required=True)
    parser.add_argument('--policy-dir-list', help='policy dirs need to be included', required=True)
    parser.add_argument('--max-length', help='maximum context length', type=int, default=48)
    return parser.parse_args()


if __name__ == "__main__":
    input_args = parse_args()
    
    parse_all_contexts(input_args)
    context_whitelist = load_context_whitelist(input_args)
    check_context_length(input_args.max_length, context_whitelist)
    check_result = print_invalid_contexts(input_args.max_length)
    unused_result = check_unused_whitelist_entries(context_whitelist, input_args.max_length)
    
    if check_result or unused_result:
        raise Exception(-1)