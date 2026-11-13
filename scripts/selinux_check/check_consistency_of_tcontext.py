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
from check_common import read_json_file, traverse_file_in_each_type

CHECK_TYPE_TCONTEXT = "tcontext"
CHECK_TYPE_SCONTEXT = "scontext"
CHECK_TYPE_ALL = "all"
VALID_CHECK_TYPES = (CHECK_TYPE_TCONTEXT, CHECK_TYPE_SCONTEXT, CHECK_TYPE_ALL)
IOCTL_TOKEN_PATTERN = re.compile(r'\(range\s+(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\)|(0x[0-9a-fA-F]+)')


def parse_ioctl_ranges(cmd_str):
    intervals = []
    for match in IOCTL_TOKEN_PATTERN.finditer(cmd_str):
        if match.group(1) and match.group(2):
            start = int(match.group(1), 16)
            end = int(match.group(2), 16)
        else:
            start = int(match.group(3), 16)
            end = start
        intervals.append((start, end))
    return merge_ioctl_ranges(intervals)


def merge_ioctl_ranges(intervals):
    if not intervals:
        return tuple()
    sorted_intervals = sorted(intervals)
    merged = [sorted_intervals[0]]
    for start, end in sorted_intervals[1:]:
        last_start, last_end = merged[-1]
        if start <= last_end + 1:
            merged[-1] = (last_start, max(last_end, end))
        else:
            merged.append((start, end))
    return tuple(merged)


def format_ioctl_ranges(intervals):
    formatted = []
    for start, end in intervals:
        if start == end:
            formatted.append(hex(start))
        else:
            formatted.append("(range {} {})".format(hex(start), hex(end)))
    return "({})".format(" ".join(formatted))


def format_allow(rulename, contexts, target_context, access_vector, check_type):
    if check_type == CHECK_TYPE_SCONTEXT:
        scontext = target_context
        tcontext = contexts[0]
    else:
        scontext = contexts[0]
        tcontext = target_context
    if rulename == "allowx":
        if isinstance(access_vector, tuple):
            access_vector = format_ioctl_ranges(access_vector)
        return "({} {} {} (ioctl {} ({})))".format(
            rulename, scontext, tcontext, contexts[1], access_vector)
    if isinstance(access_vector, set):
        access_vector_str = " ".join(access_vector)
    else:
        access_vector_str = access_vector
    return "({} {} {} ({} ({})))".format(
        rulename, scontext, tcontext, contexts[1], access_vector_str)


def format_typeattribute(typename, typeattributename):
    return "typeattribute {} {};".format(typename, typeattributename)


def check_access_vector(base_map, extend_map):
    not_found = []
    inconsistent = []
    for key, value in base_map.items():
        if not key in extend_map:
            not_found.append((key, value))
            continue

        if value != extend_map[key]:
            inconsistent.append((key, value, extend_map[key]))

    return not_found, inconsistent


def simplify_string(string):
    return string.strip().replace('(', '').replace(')', '').split()


class PolicyMap:
    def __init__(self, context, check_type):
        self.name = context
        self.check_type = check_type
        self.associated_typeattribute = set()
        # tcontext mode: key = (scontext, tclass)
        # scontext mode: key = (tcontext, tclass)
        self.allow_map = {}
        self.auditallow_map = {}
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


    def get_rule_map(self, rulename):
        if rulename == "allow":
            return self.allow_map
        if rulename == "auditallow":
            return self.auditallow_map
        if rulename == "allowx":
            return self.allowx_map
        raise ValueError("invalid rulename '{}'".format(rulename))


    def merge_policy_value(self, current_policy, new_policy):
        if new_policy is None:
            return current_policy
        if current_policy is None:
            if isinstance(new_policy, set):
                return set(new_policy)
            return new_policy
        if isinstance(current_policy, set) and isinstance(new_policy, set):
            merged = set(current_policy)
            merged.update(new_policy)
            return merged
        if isinstance(current_policy, tuple) and isinstance(new_policy, tuple):
            return merge_ioctl_ranges(list(current_policy) + list(new_policy))
        return new_policy


    def build_effective_rule_map(self, rulename, other, policy_resolver):
        source_map = other.get_rule_map(rulename)
        effective_map = {}
        for key, value in source_map.items():
            effective_map[key] = self.merge_policy_value(effective_map.get(key), value)

        attr_rule_map_group = policy_resolver.rule_maps[self.check_type][rulename]
        for attr in other.associated_typeattribute:
            attr_rule_map = attr_rule_map_group.get(attr, {})
            for key, value in attr_rule_map.items():
                effective_map[key] = self.merge_policy_value(effective_map.get(key), value)
                peer_context, tclass = key
                if self.check_type == CHECK_TYPE_SCONTEXT and \
                        (peer_context == other.name or peer_context in other.associated_typeattribute):
                    alias_key = ("self", tclass)
                    effective_map[alias_key] = self.merge_policy_value(effective_map.get(alias_key), value)
        return effective_map


    def is_policy_covered(self, base_policy, candidate_policy):
        if candidate_policy is None:
            return False
        if isinstance(base_policy, set) and isinstance(candidate_policy, set):
            return base_policy.issubset(candidate_policy)
        if isinstance(base_policy, tuple) and isinstance(candidate_policy, tuple):
            candidate_index = 0
            for base_start, base_end in base_policy:
                while candidate_index < len(candidate_policy) and candidate_policy[candidate_index][1] < base_start:
                    candidate_index += 1
                if candidate_index >= len(candidate_policy):
                    return False
                candidate_start, candidate_end = candidate_policy[candidate_index]
                if candidate_start > base_start or candidate_end < base_end:
                    return False
            return True
        return base_policy == candidate_policy


    def get_effective_policy(self, effective_map, contexts, policy_resolver, other):
        peer_context, tclass = contexts
        candidate_policy = effective_map.get((peer_context, tclass))
        if self.check_type == CHECK_TYPE_TCONTEXT:
            for attr in policy_resolver.typeattributes_map.get(peer_context, set()):
                attr_policy = effective_map.get((attr, tclass))
                candidate_policy = self.merge_policy_value(candidate_policy, attr_policy)
        elif self.check_type == CHECK_TYPE_SCONTEXT and \
                (peer_context == 'self' or peer_context == self.name):
            # scontext mode: 'self', the extend domain's own type and every
            # attribute the extend domain belongs to are aliases of the same
            # self-reference rule, e.g. base 'allow A self:file read' is
            # covered by extend 'allow B B:file read' / 'allow B b_attr:file
            # read' (B in b_attr), and base 'allow A A:file read' is covered
            # by extend 'allow B self:file read'
            alias_contexts = {'self', other.name}
            alias_contexts.update(other.associated_typeattribute)
            for alias_context in alias_contexts:
                alias_policy = effective_map.get((alias_context, tclass))
                candidate_policy = self.merge_policy_value(candidate_policy, alias_policy)
        return candidate_policy is not None, candidate_policy


    def check_allow(self, rulename, other, not_found, inconsistent, effective_map, policy_resolver):
        if rulename == "allow":
            missing_list, inconsistent_list = check_access_vector(
                self.allow_map, other.allow_map)
        elif rulename == "auditallow":
            missing_list, inconsistent_list = check_access_vector(
                self.auditallow_map, other.auditallow_map)
        elif rulename == "allowx":
            missing_list, inconsistent_list = check_access_vector(
                self.allowx_map, other.allowx_map)

        for contexts, base_policy in missing_list:
            has_extend_policy, extend_policy = self.get_effective_policy(
                effective_map, contexts, policy_resolver, other)
            if has_extend_policy:
                if not self.is_policy_covered(base_policy, extend_policy):
                    basepolicy_str = format_allow(rulename, contexts, self.name, base_policy, self.check_type)
                    targetpolicy_str = format_allow(
                        rulename, contexts, other.name, extend_policy, self.check_type)
                    inconsistent.append((basepolicy_str, targetpolicy_str))
                continue
            basepolicy_str = format_allow(rulename, contexts, self.name, base_policy, self.check_type)
            not_found.append(basepolicy_str)

        for contexts, base_policy, extend_policy in inconsistent_list:
            has_combined_policy, combined_policy = self.get_effective_policy(
                effective_map, contexts, policy_resolver, other)
            if self.is_policy_covered(base_policy, combined_policy):
                continue
            basepolicy_str = format_allow(rulename, contexts, self.name, base_policy, self.check_type)
            effective_policy = combined_policy if has_combined_policy else extend_policy
            targetpolicy_str = format_allow(
                rulename, contexts, other.name, effective_policy, self.check_type)
            inconsistent.append((basepolicy_str, targetpolicy_str))


    def print_error_header(self, other, with_developer):
        print("[Error] Check consistency of '{}' and '{}' by {} failed in {} mode.".format(
            self.name, other.name, self.check_type,
            "developer" if with_developer else "user"))

    def print_violations(self, not_found, inconsistent, missing_attrs, other_name):
        if not_found:
            print("Violate list (policy)")
            for allow in not_found:
                print("\t{}".format(allow))
            print("Solution: add the above policy to '{}'.\n".format(other_name))

        if inconsistent:
            print("Violate list (policy)")
            for base, target in inconsistent:
                print("\t{}: {}".format(self.name, base))
                print("\t{}: {}".format(other_name, target))
                print("")
            print("Solution: the above policy should be consisent.\n")

        if missing_attrs:
            print("Violate list (types)")
            for allow in missing_attrs:
                print("\t{}".format(allow))
            print("Solution: add the above typeattribute to '{}'.\n".format(other_name))

    def check_consistency(self, other, with_developer, policy_resolver, ignored_issues=None):
        if ignored_issues is None:
            ignored_issues = set()

        not_found = []
        inconsistent = []
        effective_allow_map = self.build_effective_rule_map("allow", other, policy_resolver)
        effective_auditallow_map = self.build_effective_rule_map("auditallow", other, policy_resolver)
        effective_allowx_map = self.build_effective_rule_map("allowx", other, policy_resolver)
        self.check_allow("allow", other, not_found, inconsistent, effective_allow_map, policy_resolver)
        self.check_allow("auditallow", other, not_found, inconsistent, effective_auditallow_map, policy_resolver)
        self.check_allow("allowx", other, not_found, inconsistent, effective_allowx_map, policy_resolver)

        filtered_not_found = []
        for allow in not_found:
            issue_key = ("policy_not_found", self.check_type, self.name, other.name, allow)
            if issue_key not in ignored_issues:
                filtered_not_found.append(allow)

        filtered_inconsistent = []
        for base, target in inconsistent:
            issue_key = ("policy_inconsistent", self.check_type, self.name, other.name, base, target)
            if issue_key not in ignored_issues:
                filtered_inconsistent.append((base, target))

        not_found = filtered_not_found
        inconsistent = filtered_inconsistent

        missing_attrs = self.check_typeattributes(other)
        filtered_missing_attrs = []
        for allow in missing_attrs:
            issue_key = ("typeattribute_not_found", self.check_type, self.name, other.name, allow)
            if issue_key not in ignored_issues:
                filtered_missing_attrs.append(allow)
        missing_attrs = filtered_missing_attrs

        issue_keys = set()
        for allow in not_found:
            issue_keys.add(("policy_not_found", self.check_type, self.name, other.name, allow))
        for base, target in inconsistent:
            issue_keys.add(("policy_inconsistent", self.check_type, self.name, other.name, base, target))
        for allow in missing_attrs:
            issue_keys.add(("typeattribute_not_found", self.check_type, self.name, other.name, allow))

        error = bool(issue_keys)
        if error:
            self.print_error_header(other, with_developer)

        self.print_violations(not_found, inconsistent, missing_attrs, other.name)

        return error, issue_keys


class TclassPolicyParser:
    def __init__(self):
        self.policy_map = {}
        self.check_pairs = []
        self.typeattributes_map = {}
        self.rule_maps = {
            CHECK_TYPE_TCONTEXT: {"allow": {}, "auditallow": {}, "allowx": {}},
            CHECK_TYPE_SCONTEXT: {"allow": {}, "auditallow": {}, "allowx": {}},
        }


    def add_global_rule(self, check_type, rulename, context, peer_context, tclass, access_vector):
        rule_map = self.rule_maps[check_type][rulename]
        if context not in rule_map:
            rule_map[context] = {}
        rule_map[context][(peer_context, tclass)] = access_vector


    def has_matching_rule(self, check_type, rulename, context, contexts, access_vector, owner_context=None):
        matched, _ = self.get_matching_rule_policy(
            check_type, rulename, context, contexts, owner_context, access_vector)
        return matched


    def get_matching_rule_policy(self, check_type, rulename, context, contexts, owner_context=None, access_vector=None):
        rule_map = self.rule_maps[check_type][rulename].get(context, {})
        peer_context, tclass = contexts
        candidate = rule_map.get((peer_context, tclass))
        if candidate is None:
            return False, None
        if access_vector is None:
            return True, candidate
        if isinstance(access_vector, set) and isinstance(candidate, set):
            if access_vector.issubset(candidate):
                return True, candidate
        elif access_vector == candidate:
            return True, candidate
        return False, None


    def add_target_subject(self, subject, check_type):
        key = (subject, check_type)
        if key not in self.policy_map:
            self.policy_map[key] = PolicyMap(subject, check_type)


    def add_check_pairs(self, base, extend, check_type):
        self.add_target_subject(base, check_type)
        self.add_target_subject(extend, check_type)
        self.check_pairs.append((base, extend, check_type))


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
            if typename not in self.typeattributes_map:
                self.typeattributes_map[typename] = set()
            self.typeattributes_map[typename].add(attribute_name)
            for check_type in (CHECK_TYPE_TCONTEXT, CHECK_TYPE_SCONTEXT):
                policy_key = (typename, check_type)
                if policy_key in self.policy_map:
                    self.policy_map[policy_key].add_typeattribute(attribute_name)


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
        access_vector = set(elem_list[4:])
        self.add_global_rule(CHECK_TYPE_TCONTEXT, rulename, tcontext, scontext, tclass, access_vector)
        self.add_global_rule(CHECK_TYPE_SCONTEXT, rulename, scontext, tcontext, tclass, access_vector)
        if (tcontext, CHECK_TYPE_TCONTEXT) in self.policy_map:
            self.policy_map[(tcontext, CHECK_TYPE_TCONTEXT)].add_allow_map(
                rulename, scontext, tclass, access_vector)
        if (scontext, CHECK_TYPE_SCONTEXT) in self.policy_map:
            self.policy_map[(scontext, CHECK_TYPE_SCONTEXT)].add_allow_map(
                rulename, tcontext, tclass, access_vector)


    def parse_allowx(self, line):
        # (allowx normal_hap_attr normal_hap_data_file (ioctl file (((range 0xf501 0xf502) 0xf50c))))
        pattern = re.compile(r'^\(allowx\s+([^\s]+)\s+([^\s]+)\s+\(([^\s]+)\s+([^\s]+)\s+\((.*)\)\)\)')
        match = pattern.match(line)
        if match:
            scontext = match.group(1)
            tcontext = match.group(2)
            tclass = match.group(4)
            cmd_str = parse_ioctl_ranges(match.group(5))
            self.add_global_rule(CHECK_TYPE_TCONTEXT, "allowx", tcontext, scontext, tclass, cmd_str)
            self.add_global_rule(CHECK_TYPE_SCONTEXT, "allowx", scontext, tcontext, tclass, cmd_str)
            if (tcontext, CHECK_TYPE_TCONTEXT) in self.policy_map:
                self.policy_map[(tcontext, CHECK_TYPE_TCONTEXT)].add_allow_map(
                    "allowx", scontext, tclass, cmd_str)
            if (scontext, CHECK_TYPE_SCONTEXT) in self.policy_map:
                self.policy_map[(scontext, CHECK_TYPE_SCONTEXT)].add_allow_map(
                    "allowx", tcontext, tclass, cmd_str)
        else:
            print("[ERROR] parse line = {}".format(line))
            raise Exception(-1)


    def check_consistency(self, with_developer, ignored_issues=None):
        error = False
        issue_keys = set()
        for base, extend, check_type in self.check_pairs:
            pair_error, pair_issue_keys = self.policy_map[(base, check_type)].check_consistency(
                self.policy_map[(extend, check_type)], with_developer, self, ignored_issues)
            error |= pair_error
            issue_keys.update(pair_issue_keys)
        if error:
            return issue_keys
        return issue_keys


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
    seen_pairs = set()
    for config in pair_list:
        check_type = config.get("check_type", CHECK_TYPE_TCONTEXT)
        if check_type == CHECK_TYPE_ALL:
            expanded_check_types = (CHECK_TYPE_TCONTEXT, CHECK_TYPE_SCONTEXT)
        else:
            expanded_check_types = (check_type,)
        for expanded_check_type in expanded_check_types:
            pair = (config["base"], config["extend"], expanded_check_type)
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)
            parser.add_check_pairs(config["base"], config["extend"], expanded_check_type)

    return parser


def load_check_pair_config(config_path):
    config = read_json_file(config_path)
    pair_list = []
    for pair in config.get("checks", []):
        check_type = pair.get("check_type", CHECK_TYPE_TCONTEXT)
        if check_type not in VALID_CHECK_TYPES:
            raise ValueError("invalid check_type '{}' in '{}'".format(check_type, config_path))
        pair_list.append(pair)
    return pair_list


def get_check_pair_config(input_args):
    script_dir = os.path.dirname(os.path.realpath(__file__))
    config_path = os.path.join(script_dir, input_args.config)
    if not os.path.exists(config_path):
        repo_dir = os.path.dirname(
            os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
        config_path = os.path.join(repo_dir, input_args.config)
    pair_list = []
    seen_pairs = set()

    for config in load_check_pair_config(config_path):
        pair = (config["base"], config["extend"], config.get("check_type", CHECK_TYPE_TCONTEXT))
        if pair in seen_pairs:
            continue
        seen_pairs.add(pair)
        pair_list.append(config)

    extra_config_name = os.path.basename(input_args.config)
    extra_config_list = traverse_file_in_each_type(
        input_args.policy_dir_list, extra_config_name)
    for path in extra_config_list:
        for config in load_check_pair_config(path):
            pair = (config["base"], config["extend"], config.get("check_type", CHECK_TYPE_TCONTEXT))
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)
            pair_list.append(config)

    return {"checks": pair_list}


def check_tcontext(input_args, with_developer=False, ignored_issues=None):
    config_all = get_check_pair_config(input_args)
    parser = prepare_tclass_parser(config_all)

    cil_file_path = ''

    if with_developer:
        cil_file_path = input_args.developer_cil_file
    else:
        cil_file_path = input_args.cil_file
    parser.parse_file(cil_file_path)

    return parser.check_consistency(with_developer, ignored_issues)


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

    user_issue_keys = check_tcontext(input_args, False)
    developer_issue_keys = check_tcontext(input_args, True, user_issue_keys)
    developer_unique_issue_keys = developer_issue_keys - user_issue_keys
    if user_issue_keys or developer_unique_issue_keys:
        raise Exception(-1)
