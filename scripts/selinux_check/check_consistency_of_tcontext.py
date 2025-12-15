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
from check_common import read_json_file


def format_allow(rulename, contexts, tcontext, access_vector):
    if isinstance(access_vector, set):
        access_vector_str = " ".join(access_vector)
    else:
        access_vector_str = access_vector
    return "({} {} {} ({} ({})))".format(rulename, contexts[0], tcontext,
        contexts[1], access_vector_str)


def format_typeattribute(typename, typeattributename):
    return "typeattribute {} {};".format(typename, typeattributename)


def check_access_vector(base_map, extend_map):
    for key, value in base_map.items():
        if not key in extend_map:
            return key, value, None

        if value != extend_map[key]:
            return key, value, extend_map[key]

    return None, None, None


def simplify_string(string):
    return string.strip().replace('(', '').replace(')', '').split()


class PolicyMap:
    def __init__(self, tcontext):
        self.name = tcontext
        self.associated_typeattribute = set()
        # key = (scontext, tclass), value = set(access_vector)
        self.allow_map = {}
        # key = (scontext, tclass), value = set(access_vector)
        self.auditallow_map = {}
        # key = (scontext, tclass), value = cmd_str
        self.allowx_map = {}


    def add_allow_map(self, rulename, scontext, tclass, access_vector_set):
        if rulename == "auditallow":
            self.auditallow_map[(scontext, tclass)] = access_vector_set
        elif rulename == "allow":
            self.allow_map[(scontext, tclass)] = access_vector_set
        elif rulename == "allowx":
            self.allowx_map[(scontext, tclass)] = access_vector_set
        else:
            raise Exception(-1)


    def add_typeattribute(self, typeattribute):
        self.associated_typeattribute.add(typeattribute)


    def check_typeattributes(self, other):
        missing_attrs = self.associated_typeattribute - other.associated_typeattribute
        not_found = []
        for attr in missing_attrs:
            base_policy = format_typeattribute(self.name, attr)
            not_found.append(base_policy)
        return not_found


    def check_allow(self, rulename, other, not_found, inconsistent):
        if rulename == "allow":
            contexts, base_policy, extend_policy = check_access_vector(
                self.allow_map, other.allow_map)
        elif rulename == "auditallow":
            contexts, base_policy, extend_policy = check_access_vector(
                self.auditallow_map, other.auditallow_map)
        elif rulename == "allowx":
            contexts, base_policy, extend_policy = check_access_vector(
                self.allowx_map, other.allowx_map)

        # no difference
        if not contexts:
            return
        # not found policy in extend
        elif not extend_policy:
            basepolicy_str = format_allow(rulename, contexts, self.name, base_policy)
            not_found.append(basepolicy_str)
        else:
            # access vector is different
            basepolicy_str = format_allow(rulename, contexts, self.name, base_policy)
            targetpolicy_str = format_allow(rulename, contexts, other.name, extend_policy)
            inconsistent.append((basepolicy_str, targetpolicy_str))


    def print_error_header(self, other, with_developer):
        print("[Error] Check consistency of '{}' and '{}' failed in {} mode.".format(
            self.name, other.name, "developer" if with_developer else "user"))


    def check_consistency(self, other, with_developer):
        error = False
        not_found = []
        inconsistent = []
        self.check_allow("allow", other, not_found, inconsistent)
        self.check_allow("auditallow", other, not_found, inconsistent)
        self.check_allow("allowx", other, not_found, inconsistent)

        if not_found or inconsistent:
            error = True
            self.print_error_header(other, with_developer)

        if not_found:
            print("Violate list (policy)")
            for allow in not_found:
                print("\t{}".format(allow))
            print("Solution: add the above policy to '{}'.\n".format(other.name))

        if inconsistent:
            print("Violate list (policy)")
            for base, target in inconsistent:
                print("\t{}: {}".format(self.name, base))
                print("\t{}: {}".format(other.name, target))
                print("")
            print("Solution: the above policy should be consisent.\n")

        not_found = self.check_typeattributes(other)
        if not_found:
            if not error:
                error = True
                self.print_error_header(other, with_developer)

            print("Violate list (types)")
            for allow in not_found:
                print("\t{}".format(allow))
            print("Solution: add the above typeattribute to '{}'.\n".format(other.name))

        return error


class TclassPolicyParser:
    def __init__(self):
        self.policy_map = {}
        self.check_pairs = []


    def add_target_subject(self, subject):
        self.policy_map[subject] = PolicyMap(subject)


    def add_check_pairs(self, base, extend):
        self.add_target_subject(base)
        self.add_target_subject(extend)
        self.check_pairs.append((base, extend))


    def parse_typeattributeset(self, line):
        elem_list = simplify_string(line)
        if len(elem_list) < 3:
            print("[ERROR] parse line = {}".format(line))
            raise Exception(-1)

        # (typeattributeset data_file_attr (normal_hap_data_file appdat))
        rulename = elem_list[0]
        attribute_name = elem_list[1]
        type_set = set(elem_list[2:])
        for typename in type_set:
            if typename in self.policy_map:
                self.policy_map[typename].add_typeattribute(attribute_name)


    def parse_allow(self, line):
        # (allow scontext tcontext (tclass (read opend)))
        elem_list = simplify_string(line)
        if len(elem_list) < 4:
            print("[ERROR] parse line = {}".format(line))
            raise Exception(-1)
        rulename = elem_list[0]
        scontext = elem_list[1]
        tcontext = elem_list[2]
        tclass = elem_list[3]
        if tcontext in self.policy_map:
            self.policy_map[tcontext].add_allow_map(rulename, scontext, tclass, set(elem_list[4:]))


    def parse_allowx(self, line):
        # (allowx normal_hap_attr normal_hap_data_file (ioctl file (((range 0xf501 0xf502) 0xf50c))))
        pattern = re.compile(r'^\(allowx\s+([^\s]+)\s+([^\s]+)\s+\(([^\s]+)\s+([^\s]+)\s+\((.*)\)\)\)')
        match = pattern.match(line)
        if match:
            scontext = match.group(1)
            tcontext = match.group(2)
            tclass = match.group(4)
            cmd_str = match.group(5)
            if tcontext in self.policy_map:
                self.policy_map[tcontext].add_allow_map("allowx", scontext, tclass, cmd_str)
        else:
            print("[ERROR] parse line = {}".format(line))
            raise Exception(-1)


    def check_consistency(self, with_developer):
        error = False
        for base, extend in self.check_pairs:
            error |= self.policy_map[base].check_consistency(
                self.policy_map[extend], with_developer)
        if error:
            raise Exception(-1)


    def parse_file(self, path):
        with open(path, 'r', encoding='utf-8') as cil_read:
            lines = cil_read.readlines()
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                if line.startswith("(allowx"):
                    self.parse_allowx(line)
                elif line.startswith("(auditallow") or line.startswith("(allow"):
                    self.parse_allow(line)
                elif line.startswith('(typeattributeset '):
                    self.parse_typeattributeset(line)


def prepare_tclass_parser(configs):
    pair_list = configs["checks"]
    parser = TclassPolicyParser()
    for config in pair_list:
        parser.add_check_pairs(config["base"], config["extend"])

    return parser


def check_tcontext(input_args, with_developer=False):
    config_path = os.path.join(os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.realpath(__file__)))), input_args.config)
    config_all = read_json_file(config_path)
    parser = prepare_tclass_parser(config_all)

    cil_file_path = ''

    if with_developer:
        cil_file_path = input_args.developer_cil_file
    else:
        cil_file_path = input_args.cil_file
    parser.parse_file(cil_file_path)

    parser.check_consistency(with_developer)


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
    print("check tcontext input_args: {}".format(input_args))

    check_tcontext(input_args, False)
    check_tcontext(input_args, True)