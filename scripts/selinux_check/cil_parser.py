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

from collections import defaultdict


class PolicyDb:
    def __init__(self, attributes_map, class_map, allow_pair_map, allow_source_map):
        self.attributes_map = attributes_map
        self.class_map = class_map
        self.allow_map = allow_pair_map
        self.allow_by_source = allow_source_map


def simplify_string(string):
    return string.strip().replace('(', '').replace(')', '')


def _parse_cil_file(cil_file):
    attributes_map = defaultdict(set)
    common_map = defaultdict(set)
    class_map = defaultdict(set)
    allow_rules = []
    with open(cil_file, 'r', encoding='utf-8') as cil_read:
        for raw_line in cil_read:
            line = raw_line.strip()
            if not line:
                continue
            # (typeattributeset chip_ckm_file_attr (chip_ckm_file))
            if line.startswith('(typeattributeset '):
                elem_list = simplify_string(line).split()
                if len(elem_list) >= 3:
                    attributes_map[elem_list[1]].update(elem_list[2:])
                continue
            # (common ipc (create destroy getattr setattr read write associate unix_read unix_write))
            if line.startswith('(common '):
                elem_list = simplify_string(line).split()
                if len(elem_list) >= 3:
                    common_map[elem_list[1]].update(elem_list[2:])
                continue
            # (class fd (use))
            if line.startswith('(class '):
                elem_list = simplify_string(line).split()
                if len(elem_list) >= 3:
                    class_map[elem_list[1]].update(elem_list[2:])
                continue

            # (allow SP_daemon data_app_file (dir (search)))

            if line.startswith('(allow ') or line.startswith('(auditallow '):
                elem_list = simplify_string(line).split()
                if len(elem_list) >= 5:
                    allow_rules.append(elem_list)

    with open(cil_file, 'r', encoding='utf-8') as cil_read:
        for line in cil_read:
            # (classcommon capability cap)
            if not line.startswith('(classcommon '):
                continue
            sub_string = simplify_string(line)
            elem_list = sub_string.split(' ')
            if len(elem_list) < 3:
                continue
            class_map[elem_list[1]].update(common_map[elem_list[2]])

    return attributes_map, class_map, allow_rules


def _expand_allow_rule(elem_list, attributes_map, allow_pair_map, allow_source_map):
    scontext = elem_list[1]
    tcontext = elem_list[2]
    tclass = elem_list[3]
    perms = set(elem_list[4:])
    source_contexts = attributes_map.get(scontext)
    if not source_contexts:
        source_contexts = {scontext}

    for source in source_contexts:
        if tcontext == 'self':
            target_contexts = {source}
        else:
            target_contexts = attributes_map.get(tcontext)
            if not target_contexts:
                target_contexts = {tcontext}
        for target in target_contexts:
            allow_pair_map[(source, target)][tclass].update(perms)
            allow_source_map[source][(target, tclass)].update(perms)


def parse_policy_db(cil_file):
    attributes_map, class_map, allow_rules = _parse_cil_file(cil_file)
    allow_pair_map = defaultdict(lambda: defaultdict(set))
    allow_source_map = defaultdict(lambda: defaultdict(set))
    for elem_list in allow_rules:
        _expand_allow_rule(elem_list, attributes_map, allow_pair_map, allow_source_map)
    return PolicyDb(attributes_map, class_map, allow_pair_map, allow_source_map)
