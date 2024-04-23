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
from collections import defaultdict
import subprocess
from check_common import read_json_file, traverse_file_in_each_type

BASELINE_SUFFIX = ".baseline"


class PolicyDb(object):
    def __init__(self, attributes_map, allow_map, class_map):
        self.attributes_map = attributes_map
        self.allow_map = allow_map
        self.class_map = class_map


def simplify_string(string):
    return string.replace('(', '').replace(')', '').replace('\n', '').strip()


def deal_with_allow(cil_file, allow_map, attributes_map):
    with open(cil_file, 'r', encoding='utf-8') as cil_read:
        for line in cil_read:
            line = line.strip()
            if not line.startswith('(allow ') and not line.startswith('(auditallow '):
                continue
            sub_string = simplify_string(line)
            elem_list = sub_string.split(' ')
            # (allow A B (dir (getattr)))
            if len(elem_list) < 5:
                continue
            split_attribute(elem_list, allow_map, attributes_map)


def split_attribute(elem_list, allow_map, attributes_map):
    scontext = elem_list[1]
    tcontext = elem_list[2]
    tclass = elem_list[3]
    perm = elem_list[4:]
    if scontext not in attributes_map:
        # allow type self
        if tcontext == 'self':
            allow_map[scontext][(scontext, tclass)] += perm
        # allow type attribute
        elif tcontext in attributes_map:
            for tcon in attributes_map[tcontext]:
                allow_map[scontext][(tcon, tclass)] += perm
        # allow type type
        else:
            allow_map[scontext][(tcontext, tclass)] += perm
        return

    for scon in attributes_map[scontext]:
        # allow attribute self
        if tcontext == 'self':
            allow_map[scon][(scon, tclass)] += perm
        # allow attribute attribute
        elif tcontext in attributes_map:
            for tcon in attributes_map[tcontext]:
                allow_map[scon][(tcon, tclass)] += perm
        # allow attribute type
        else:
            allow_map[scon][(tcontext, tclass)] += perm


def deal_with_typeattributeset(cil_file, attributes_map):
    with open(cil_file, 'r', encoding='utf-8') as cil_read:
        for line in cil_read:
            if not line.startswith('(typeattributeset '):
                continue
            sub_string = simplify_string(line)
            elem_list = sub_string.split(' ')
            if len(elem_list) < 3:
                continue
            attributes_map[elem_list[1]] += elem_list[2:]


def deal_with_class(cil_file, class_map):
    with open(cil_file, 'r', encoding='utf-8') as cil_read:
        common_map = defaultdict(list)
        for line in cil_read:
            if not line.startswith('(common '):
                continue
            sub_string = simplify_string(line)
            elem_list = sub_string.split(' ')
            if len(elem_list) < 3:
                continue
            common_map[elem_list[1]] += elem_list[2:]

    with open(cil_file, 'r', encoding='utf-8') as cil_read:
        for line in cil_read:
            if not line.startswith('(class '):
                continue
            sub_string = simplify_string(line)
            elem_list = sub_string.split(' ')
            if len(elem_list) > 2:
                class_map[elem_list[1]] += elem_list[2:]

    with open(cil_file, 'r', encoding='utf-8') as cil_read:
        for line in cil_read:
            if not line.startswith('(classcommon '):
                continue
            sub_string = simplify_string(line)
            elem_list = sub_string.split(' ')
            if len(elem_list) < 3:
                continue
            class_map[elem_list[1]] += common_map[elem_list[2]]


def generate_database(cil_file):
    attributes_map = defaultdict(list)
    class_map = defaultdict(list)
    allow_map = defaultdict(lambda: defaultdict(list))
    deal_with_typeattributeset(cil_file, attributes_map)
    deal_with_allow(cil_file, allow_map, attributes_map)
    deal_with_class(cil_file, class_map)
    return PolicyDb(attributes_map, allow_map, class_map)


def build_conf(output_conf, file_list, with_developer=False):
    m4_args = []
    if with_developer:
        m4_args += ["-D", "build_with_developer=enable"]
    build_conf_cmd = ["m4", "-s", "--fatal-warnings"] + m4_args + file_list
    with open(output_conf, 'w', encoding="utf-8") as fd:
        ret = subprocess.run(build_conf_cmd, shell=False, stdout=fd).returncode
        if ret != 0:
            raise Exception(ret)


def get_baseline_file(args):
    script_path = os.path.dirname(os.path.realpath(__file__))
    baseline_file_list = [os.path.join(script_path, "config/glb_def.txt")]
    baseline_file_list += traverse_file_in_each_type(args.policy_dir_list, BASELINE_SUFFIX)
    return baseline_file_list


def generate_baseline_database(args, domain, attributes_map, with_developer):
    baseline_file_list = get_baseline_file(args)
    output_path = os.path.dirname(os.path.realpath(args.developer_cil_file if with_developer else args.cil_file))
    output_baseline = os.path.join(output_path, domain + BASELINE_SUFFIX)
    build_conf(output_baseline, baseline_file_list, with_developer)
    baseline_map = defaultdict(lambda: defaultdict(list))
    deal_with_allow(output_baseline, baseline_map, attributes_map)
    return baseline_map[domain]


def check_baseline(args, domain, policy_db, with_developer):
    baseline_map = generate_baseline_database(args, domain, policy_db.attributes_map, with_developer)
    none_baseline_list = set()
    domain_policy = policy_db.allow_map[domain]
    baseline_diff = domain_policy.keys() ^ baseline_map.keys()
    for diff in baseline_diff:
        expect_perm = ''.join(['(', ' '.join(set(baseline_map.get(diff, ''))), ')))'])
        expect = ' '.join(['expect rule: (allow', domain, ' ('.join(diff), expect_perm])
        actual_perm = ''.join(['(', ' '.join(set(domain_policy.get(diff, ''))), ')))'])
        actual = ' '.join(['actual rule: (allow', domain, ' ('.join(diff), actual_perm])
        none_baseline_list.add('; '.join([expect, actual]))

    for contexts in domain_policy.keys():
        if set(baseline_map.get(contexts, '')) != set(domain_policy.get(contexts, '')):
            expect_perm = ''.join(['(', ' '.join(set(baseline_map.get(contexts, ''))), ')))'])
            expect = ' '.join(['expect rule: (allow', domain, ' ('.join(contexts), expect_perm])
            actual_perm = ''.join(['(', ' '.join(set(domain_policy.get(contexts, ''))), ')))'])
            actual = ' '.join(['actual rule: (allow', domain, ' ('.join(contexts), actual_perm])
            none_baseline_list.add('; '.join([expect, actual]))

    if len(none_baseline_list):
        print('\tcheck \'{}\' baseline in {} mode failed'.format(domain, "developer" if with_developer else "user"))
        for violation in none_baseline_list:
            print('\t\t{}'.format(violation))
        print('\tThere are two solutions:\n',
            '\t1. Add the above actual rule to baseline file \'{}\' under \'{}\'{}\n'.format(
                domain + BASELINE_SUFFIX, args.policy_dir_list, " and add developer_only" if with_developer else ""),
            '\t2. Change the policy to satisfy expect rule\n')
        return True
    return False


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--cil_file', help='the cil file path', required=True)
    parser.add_argument(
        '--developer_cil_file', help='the developer cil file path', required=True)
    parser.add_argument(
        '--config', help='the config file path', required=True)
    parser.add_argument(
        '--policy-dir-list', help='the policy dir list', required=True)
    return parser.parse_args()


if __name__ == '__main__':
    input_args = parse_args()
    script_dir = os.path.dirname(os.path.realpath(__file__))

    user_policy_db = generate_database(input_args.cil_file)
    developer_policy_db = generate_database(input_args.developer_cil_file)
    baselines = read_json_file(os.path.join(script_dir, input_args.config)).get('baseline')
    check_result = False
    for label_name in baselines:
        check_result |= check_baseline(input_args, label_name, user_policy_db, False)
        check_result |= check_baseline(input_args, label_name, developer_policy_db, True)
    if check_result:
        raise Exception(-1)
