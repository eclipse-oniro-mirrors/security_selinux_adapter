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
from check_common import read_json_file, traverse_file_in_each_type, load_json_objects_in_dir_list
from te_scanner import get_tokens, normalize_rule_text, scan_te_policy_dir_list, strip_comment

WHITELIST_FILE_NAME = "restricted_common_type_whitelist.txt"


def get_restricted_tokens(text, restricted_types):
    result = []
    for token in get_tokens(text):
        if token in restricted_types and token not in result:
            result.append(token)
    return result


def load_restricted_type_config(config_path):
    config = read_json_file(config_path)
    restricted_types = set(config.get("restricted_types", []))
    suggestions = config.get("suggestions", {})
    return restricted_types, suggestions


def get_restricted_type_config(args):
    script_dir = os.path.dirname(os.path.realpath(__file__))
    config_path = os.path.join(script_dir, args.config)
    restricted_types, suggestions = load_restricted_type_config(config_path)

    extra_config_name = os.path.basename(args.config)
    for path, _ in load_json_objects_in_dir_list(args.policy_dir_list, extra_config_name):
        extra_restricted_types, extra_suggestions = load_restricted_type_config(path)
        restricted_types.update(extra_restricted_types)
        suggestions.update(extra_suggestions)
    return restricted_types, suggestions


def get_rule_suggestions(restricted_tokens, suggestions):
    suggestion_list = []
    for token in restricted_tokens:
        if token in suggestions:
            suggestion_list.append("{} -> {}".format(token, suggestions[token]))
    return suggestion_list


def record_violation(violations, policy_file, line_no, rule_type, text, restricted_tokens):
    violations.append({
        "file": policy_file,
        "line": line_no,
        "rule_type": rule_type,
        "text": normalize_rule_text(text),
        "restricted_tokens": restricted_tokens,
    })


def collect_auth_rule(statement, start_line_no, policy_file, restricted_types, violations):
    restricted_tokens = get_restricted_tokens(statement, restricted_types)
    if restricted_tokens:
        rule_name = statement.strip().split(None, 1)[0]
        record_violation(violations, policy_file, start_line_no, rule_name, statement, restricted_tokens)


def collect_violations(policy_dir_list, restricted_types):
    violations = []
    for statement in scan_te_policy_dir_list(policy_dir_list):
        if statement.kind == "auth_rule":
            collect_auth_rule(statement.raw_text, statement.start_line,
                              statement.policy_file, restricted_types, violations)
            continue
        if statement.kind == "macro_call":
            restricted_tokens = get_restricted_tokens(statement.args_text or "", restricted_types)
            if restricted_tokens:
                record_violation(violations, statement.policy_file, statement.start_line,
                                 statement.macro_name, statement.raw_text, restricted_tokens)
    return violations


def load_whitelist(policy_dir_list):
    whitelist = set()
    whitelist_files = traverse_file_in_each_type(policy_dir_list, WHITELIST_FILE_NAME)
    for whitelist_file in whitelist_files:
        with open(whitelist_file, 'r', encoding='utf-8') as whitelist_read:
            for line in whitelist_read:
                text = normalize_rule_text(strip_comment(line).strip())
                if text:
                    whitelist.add(text)
    return whitelist


def filter_whitelist(violations, whitelist):
    if not whitelist:
        return violations
    return [violation for violation in violations if violation["text"] not in whitelist]


def check_restricted_types(args, restricted_types, config_suggestions):
    violations = collect_violations(args.policy_dir_list, restricted_types)
    whitelist = load_whitelist(args.policy_dir_list)
    violations = filter_whitelist(violations, whitelist)
    if not violations:
        return False

    print("Check restricted type in te files failed.")
    print("The following te rules use restricted types directly:")
    for violation in violations:
        print("\t{}:{}: {}".format(
            violation["file"], violation["line"], violation["text"]))
        suggestion_list = get_rule_suggestions(violation["restricted_tokens"], config_suggestions)
        if suggestion_list:
            print("\t\tsuggestion: {}".format(", ".join(suggestion_list)))
    print("solution:")
    print("\t1. move the direct type in the rule to the corresponding attribute.")
    print("\t2. if the direct type must be kept, add the te rule text to {}.".format(WHITELIST_FILE_NAME))
    return True


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--cil_file', help='unused, kept for compatibility', required=False)
    parser.add_argument('--developer_cil_file', help='unused, kept for compatibility', required=False)
    parser.add_argument('--config', help='the config file path', required=True)
    parser.add_argument('--policy-dir-list', help='policy dirs need to be included', required=True)
    return parser.parse_args()


if __name__ == '__main__':
    input_args = parse_args()
    restricted_types, suggestions = get_restricted_type_config(input_args)

    if check_restricted_types(input_args, restricted_types, suggestions):
        raise Exception(-1)
