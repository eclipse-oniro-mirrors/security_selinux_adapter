#!/usr/bin/env python3
# Copyright (c) 2026 Huawei Device Co., Ltd.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Exercise the production action with GN/Ninja and controlled policy tools."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[5]
REPOSITORY = ROOT / 'base/security/selinux_adapter'
GN = ROOT / 'prebuilts/build-tools/linux-x86/bin/gn'
NINJA = ROOT / 'prebuilts/build-tools/linux-x86/bin/ninja'


def production_action():
    source = (REPOSITORY / 'BUILD.gn').read_text()
    start = source.index('action("selinux_check") {')
    position = source.index('{', start)
    depth = 1
    while depth:
        position += 1
        depth += (source[position] == '{') - (source[position] == '}')
    return source[start:position + 1]


class SelinuxCheckIncrementalTest(unittest.TestCase):
    def setUp(self):
        if not GN.is_file() or not NINJA.is_file():
            self.skipTest('workspace GN and Ninja prebuilts are required')
        self.temporary = tempfile.TemporaryDirectory(prefix='selinux-check-output-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / 'workspace'
        self.root.mkdir()
        self.env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
        self.log = []
        self.ninja_prefix = []
        self.scriptdir = self.root / 'base/security/selinux_adapter/scripts/selinux_check'
        self.scriptdir.mkdir(parents=True)
        for name in ('selinux_check_main.py', 'check_common.py'):
            shutil.copy2(REPOSITORY / 'scripts/selinux_check' / name, self.scriptdir / name)
        (self.root / 'base/security/selinux_adapter/sepolicy').mkdir()
        (self.root / 'vendor/probe').mkdir(parents=True)
        (self.root / 'build').symlink_to(ROOT / 'build', target_is_directory=True)
        self.checker = self.scriptdir / 'fixture_check.py'
        self.checker.write_text('''import argparse
from pathlib import Path
p = argparse.ArgumentParser()
p.add_argument('--cil_file')
p.add_argument('--developer_cil_file')
p.add_argument('--policy-dir-list')
p.add_argument('--mode')
a = p.parse_args()
assert Path(a.cil_file).read_bytes().startswith(b'CIL:')
assert Path(a.developer_cil_file).read_bytes().startswith(b'CIL:')
with open('checks-ran.log', 'a') as output:
    output.write(a.mode + '\\n')
raise SystemExit(43 if a.mode == 'fail' else 0)
''')
        self.master = self.root / 'checks.json'
        self.set_mode('ok')
        (self.root / 'user.policy').write_text('user payload')
        (self.root / 'developer.policy').write_text('developer payload')
        tools = self.root / 'tools'
        tools.mkdir()
        (tools / 'python').symlink_to(sys.executable)
        self.env['PATH'] = str(tools) + os.pathsep + self.env['PATH']
        policy = tools / 'checkpolicy'
        policy.write_text('#!' + sys.executable + '''
from pathlib import Path
import sys
value = Path(sys.argv[sys.argv.index('-b') + 1]).read_bytes()
if value == b'BAD':
    raise SystemExit(17)
output = Path(sys.argv[sys.argv.index('-o') + 1])
output.parent.mkdir(parents=True, exist_ok=True)
output.write_bytes(b'CIL:' + value)
''')
        policy.chmod(0o755)
        (self.root / 'copy_policy.py').write_text('''from pathlib import Path
import sys
for source, target in zip(sys.argv[1::2], sys.argv[2::2]):
    output = Path(target)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(Path(source).read_bytes())
''')
        (self.root / '.gn').write_text('buildconfig = "//BUILDCONFIG.gn"\n'
                                      'script_executable = ' + json.dumps(sys.executable) + '\n')
        (self.root / 'BUILDCONFIG.gn').write_text('set_default_toolchain("//:host")\n')
        prelude = '''toolchain("host") {
  tool("stamp") { command = "touch {{output}}" }
  tool("copy") { command = "cp {{source}} {{output}}" }
  tool("action") { }
}
selinux_adapter_check_extend_list = "default"
selinux_adapter_build_path = "default"
OHOS_PRODUCT_DIR = "vendor/probe"
special_selinux_check_config = "checks.json"
tool_path = rebase_path("//tools", root_build_dir)
action("build_policy") {
  script = "//copy_policy.py"
  inputs = [ "//user.policy", "//developer.policy" ]
  outputs = [ "$target_out_dir/user_policy", "$target_out_dir/developer/developer_policy" ]
  args = [ rebase_path(inputs[0], root_build_dir), rebase_path(outputs[0], root_build_dir),
           rebase_path(inputs[1], root_build_dir), rebase_path(outputs[1], root_build_dir) ]
}
group("build_contexts") { }
'''
        toolchain, variables = prelude.split('selinux_adapter_check_extend_list', 1)
        (self.root / 'BUILD.gn').write_text(toolchain + '\n' + '''group("default") {
  deps = [ "//base/security/selinux_adapter:selinux_check" ]
}
''')
        (self.root / 'base/security/selinux_adapter/BUILD.gn').write_text(
            'selinux_adapter_check_extend_list' + variables + production_action() + '\n')
        self.command([GN, 'gen', 'out/probe'])
        description = json.loads(self.command([GN, 'desc', 'out/probe',
                                               '//base/security/selinux_adapter:selinux_check',
                                               '--format=json']))
        target = next(iter(description.values()))
        self.outputs = [path[2:] if path.startswith('//') else path for path in target['outputs']]
        args = target['args']
        self.action_args = args
        self.depfile = args[args.index('--depfile') + 1]
        self.dep_target = args[args.index('--dep-target') + 1]

    def command(self, arguments, expected=0):
        if arguments[0] == NINJA:
            arguments = self.ninja_prefix + arguments
        result = subprocess.run([str(value) for value in arguments], cwd=self.root,
                                env=self.env, text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT)
        self.log.append((arguments, result.returncode, result.stdout))
        self.assertEqual(result.returncode, expected, result.stdout)
        return result.stdout

    def build(self, expected=0):
        return self.command([NINJA, '-C', 'out/probe', 'selinux_check'], expected)

    def set_mode(self, mode):
        self.master.write_text(json.dumps({'selinux_check': [{
            'script': str(self.checker.relative_to(self.root)),
            'args': '--cil_file', 'extra_args': '--mode ' + mode}]}))

    def assert_no_work(self):
        self.assertIn('no work to do', self.build())

    def assert_payloads(self, user=b'user payload', developer=b'developer payload'):
        self.assertEqual((self.root / self.outputs[0]).read_bytes(), b'CIL:' + user)
        self.assertEqual((self.root / self.outputs[1]).read_bytes(), b'CIL:' + developer)

    def test_real_outputs_and_relative_depfile(self):
        self.build()
        self.assert_payloads()
        self.assertEqual(len(self.outputs), 2)
        self.assertTrue(self.outputs[0].endswith('/all.cil'))
        self.assertTrue(self.outputs[1].endswith('/developer/all.cil'))
        text = (self.root / 'out/probe' / self.depfile).read_text()
        target, inputs = text.split(': ', 1)
        self.assertEqual(target, self.dep_target)
        self.assertTrue(all(not os.path.isabs(value) for value in inputs.split()))
        self.assertEqual(list(self.root.rglob('*.complete')), [])
        self.assert_no_work()

    def test_policy_change_rebuilds_and_converges(self):
        self.build()
        (self.root / 'user.policy').write_text('updated user')
        self.assertNotIn('no work to do', self.build())
        self.assert_payloads(user=b'updated user')
        self.assert_no_work()

    def test_checker_script_change_rebuilds_and_converges(self):
        self.build()
        self.checker.write_text(self.checker.read_text() + '\n# changed checker\n')
        self.assertNotIn('no work to do', self.build())
        self.assert_no_work()

    def test_either_real_output_loss_is_repaired(self):
        self.build()
        for output in self.outputs:
            with self.subTest(output=output):
                (self.root / output).unlink()
                self.assertNotIn('no work to do', self.build())
                self.assert_payloads()
                self.assert_no_work()

    def test_validation_failure_retries_and_recovers(self):
        self.build()
        depfile = self.root / 'out/probe' / self.depfile
        previous = (depfile.read_bytes(), depfile.stat().st_mtime_ns)
        self.set_mode('fail')
        self.build(expected=1)
        self.assert_payloads()
        self.assertEqual((depfile.read_bytes(), depfile.stat().st_mtime_ns), previous)
        self.build(expected=1)
        self.set_mode('ok')
        self.build()
        self.assert_no_work()

    def test_policy_compiler_failure_retries_and_recovers(self):
        self.build()
        (self.root / 'developer.policy').write_text('BAD')
        self.build(expected=1)
        self.build(expected=1)
        (self.root / 'developer.policy').write_text('repaired developer')
        self.build()
        self.assert_payloads(developer=b'repaired developer')
        self.assert_no_work()

    def test_first_validation_failure_has_no_success_depfile(self):
        self.set_mode('fail')
        self.build(expected=1)
        self.assertFalse((self.root / 'out/probe' / self.depfile).exists())
        self.build(expected=1)
        self.set_mode('ok')
        self.build()
        self.assert_payloads()
        self.assert_no_work()

    def test_migration_keeps_relative_action_and_real_changes(self):
        bwrap = shutil.which('bwrap')
        if not bwrap:
            self.skipTest('bubblewrap is required for canonical path mapping')
        self.build()
        self.assert_no_work()
        canonical = self.root
        moved = self.root.with_name('renamed-workspace')
        self.root.rename(moved)
        self.root = moved
        spec = importlib.util.spec_from_file_location(
            'incremental_workspace', ROOT / 'build/scripts/incremental_workspace.py')
        workspace = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(workspace)
        self.ninja_prefix = [bwrap, '--die-with-parent', '--bind', '/', '/',
                             *workspace.private_mountpoint(canonical),
                             '--proc', '/proc', '--dev-bind', '/dev', '/dev',
                             '--bind', str(moved), str(canonical),
                             '--chdir', str(canonical), '--']
        self.assert_no_work()
        self.checker = moved / self.checker.relative_to(canonical)
        self.checker.write_text(self.checker.read_text() + '\n# edited after migration\n')
        self.assertNotIn('no work to do', self.build())
        self.assert_payloads()
        self.assert_no_work()
        self.assertFalse(canonical.exists(), 'mapping must not leave a host placeholder')

    def test_depfile_target_is_required_before_producing_policy(self):
        script = self.scriptdir / 'selinux_check_main.py'
        self.command([sys.executable, script, '--output-path', 'unused',
                      '--source-root-dir', '.', '--selinux-check-config', 'checks.json',
                      '--user-policy', 'user.policy', '--developer-policy', 'developer.policy',
                      '--tool-path', 'tools', '--policy-dir-list', 'default',
                      '--depfile', 'unused/check.d'], expected=2)
        self.assertFalse((self.root / 'unused').exists())

    def test_previously_generated_stamp_command_remains_compatible(self):
        self.command([NINJA, '-C', 'out/probe', 'build_policy'])
        args = self.action_args.copy()
        index = args.index('--dep-target')
        args[index:index + 2] = ['--stamp', 'legacy.complete']
        script = self.scriptdir / 'selinux_check_main.py'
        result = subprocess.run([sys.executable, str(script), *args],
                                cwd=self.root / 'out/probe', env=self.env,
                                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assert_payloads()
        self.assertTrue((self.root / 'out/probe/legacy.complete').is_file())
        self.assertTrue((self.root / 'out/probe' / self.depfile).read_text().startswith(
            'legacy.complete: '))


if __name__ == '__main__':
    unittest.main(verbosity=2)
