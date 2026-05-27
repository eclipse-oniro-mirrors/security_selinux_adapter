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

import re
from check_common import traverse_file_in_each_type

AUTH_RULE_NAMES = ("allow", "allowxperm", "auditallow", "auditallowxperm")
AUTH_RULE_PATTERN = re.compile(r'^\s*({})\b'.format("|".join(AUTH_RULE_NAMES)))
MACRO_CALL_PATTERN = re.compile(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*\(')
TOKEN_PATTERN = re.compile(r'-?[A-Za-z_][A-Za-z0-9_]*')


class TeStatement:
    def __init__(self, kind, policy_file, start_line, end_line, raw_text,
                 normalized_text, macro_name=None, args_text=None):
        self.kind = kind
        self.policy_file = policy_file
        self.start_line = start_line
        self.end_line = end_line
        self.raw_text = raw_text
        self.normalized_text = normalized_text
        self.macro_name = macro_name
        self.args_text = args_text


def strip_comment(line):
    return line.split("#", 1)[0]


def normalize_rule_text(text):
    return " ".join(text.split())


def get_tokens(text):
    return [token.lstrip("-") for token in TOKEN_PATTERN.findall(text)]


def clean_macro_body_text(text):
    return text.replace("`", " ").replace("'", " ").strip()


def find_matching_right_paren(line, left_paren_index):
    depth = 0
    for index in range(left_paren_index, len(line)):
        if line[index] == "(":
            depth += 1
        elif line[index] == ")":
            depth -= 1
            if depth == 0:
                return index
    return -1


def create_statement(kind, policy_file, start_line, end_line, raw_text,
                     macro_name=None, args_text=None):
    return TeStatement(kind, policy_file, start_line, end_line, raw_text,
                       normalize_rule_text(raw_text), macro_name, args_text)


def parse_inline_policy_text(text, line_no, policy_file):
    statements = []
    body = clean_macro_body_text(text)
    for statement in body.split(";"):
        statement = statement.strip()
        if not statement:
            continue
        statement_text = "{};".format(statement)
        if AUTH_RULE_PATTERN.match(statement):
            statements.append(create_statement(
                "auth_rule", policy_file, line_no, line_no, statement_text))
            continue
        statements.extend(parse_macro_calls(statement_text, line_no, policy_file))
    return statements


def parse_macro_calls(line, line_no, policy_file):
    statements = []
    skip_until = -1
    for macro_match in MACRO_CALL_PATTERN.finditer(line):
        if macro_match.start() < skip_until:
            continue
        macro_name = macro_match.group(1)
        if macro_name in AUTH_RULE_NAMES:
            continue
        args_start = macro_match.end()
        left_paren_index = args_start - 1
        args_end = find_matching_right_paren(line, left_paren_index)
        if args_end == -1:
            args_text = line[args_start:]
            skip_until = len(line)
        else:
            args_text = line[args_start:args_end]
            skip_until = args_end + 1
        if macro_name.endswith("_only"):
            statements.extend(parse_inline_policy_text(args_text, line_no, policy_file))
            continue
        statements.append(create_statement(
            "macro_call", policy_file, line_no, line_no, line.strip(),
            macro_name=macro_name, args_text=args_text))
    return statements


def scan_te_file(policy_file):
    statements = []
    in_auth_rule = False
    auth_rule_lines = []
    auth_rule_start_line = 0

    with open(policy_file, 'r', encoding='utf-8') as policy_read:
        for line_no, raw_line in enumerate(policy_read, 1):
            line = strip_comment(raw_line).strip()
            if not line:
                continue
            if in_auth_rule:
                auth_rule_lines.append(line)
                if ";" in line:
                    statement_text = " ".join(auth_rule_lines)
                    statements.append(create_statement(
                        "auth_rule", policy_file, auth_rule_start_line, line_no, statement_text))
                    in_auth_rule = False
                    auth_rule_lines = []
                continue

            if AUTH_RULE_PATTERN.match(line):
                in_auth_rule = True
                auth_rule_start_line = line_no
                auth_rule_lines = [line]
                if ";" in line:
                    statements.append(create_statement(
                        "auth_rule", policy_file, line_no, line_no, line))
                    in_auth_rule = False
                    auth_rule_lines = []
                continue

            statements.extend(parse_macro_calls(line, line_no, policy_file))

    if in_auth_rule:
        statement_text = " ".join(auth_rule_lines)
        statements.append(create_statement(
            "auth_rule", policy_file, auth_rule_start_line, auth_rule_start_line, statement_text))
    return statements


def scan_te_policy_dir_list(policy_dir_list):
    statements = []
    for policy_file in traverse_file_in_each_type(policy_dir_list, ".te"):
        statements.extend(scan_te_file(policy_file))
    return statements
