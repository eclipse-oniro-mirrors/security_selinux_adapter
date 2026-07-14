# AGENTS.md

## Basic Information

| Attribute | Value |
| -------- | -------- |
| Repository | selinux_adapter |
| Subsystem | security |
| Language | TE, C/C++, Python |
| Last Modified | 2026-01-30 |

## Overview

This is the SELinux adapter component for OpenHarmony. It provides mandatory access control (MAC) capabilities for system resources, such as files, parameters, system abilities (SAs), and Hardware Driver Foundation (HDF) services, based on the system architecture characteristics and SELinux. This topic describes how to develop the OpenHarmony SELinux features based on the SELinux access control model.

- Access control for parameters, SAs, and HDF services.
- Setting of application labels.
- Security policy compiling and loading.
- Security context compiling and loading.
- Policy validity check during compilation.

## Build Commands

### Building the Component

```bash
# Build the full component
hb build selinux_adapter -i
```

### Running Tests

```bash
# Run all unit tests
hb build selinux_adapter -t

# Or use the test directly from build output
./out/standard/test/tests/unittest/selinux_adapter/selinux_adapter/
```

The test framework uses OHA-developer_test. Individual test suites include:
- `hap_restorecon_unittest` - Set SELinux context for HAP tests
- `hap_restorecon_hapfile_test` - Convert context from `normal_hap_data_file` to `appdat` test
- `paraperm_checker_unittest` - Parameter permission checking tests
- `service_checker_unittest` - Service security checking tests
- `parameter_static_unittest` - Static parameter tests
- `seharmony_cjson_unittest` - JSON parsing tests

### Verification

**Task-specific validation:**

| Task Type | Additional Validation |
| --- | --- |
| Policy change | Check build log for `neverallow` violations; boot device and check `dmesg` for AVC denials |
| Command-Line tool change | Run tool-specific unit tests from list above |
| API change | Check backward compatibility of `interfaces/policycoreutils/include/`; test dependent components |
| Context file change | Verify context mappings are correct; test file labeling with `ls -lZ` |
| Library change | Run all unit tests; verify no API breakage |

**If validation cannot be run:**
- Document why validation was skipped
- List manual verification steps performed
- Identify risks of unvalidated changes
- Request review from appropriate team member

**Done definition:**
Before marking any task complete, verify:
1. ✅ Build succeeds without errors or warnings
2. ✅ All unit tests pass
3. ✅ If policy changed: no `neverallow` violations in build log
4. ✅ If policy changed: boot tested and no unexpected AVC denials (or denials explained)
5. ✅ If API changed: backward compatibility verified or migration plan documented
6. ✅ Code follows style guides ([Coding Style Guide](https://gitcode.com/openharmony/docs/blob/master/en/contribute/OpenHarmony-c-coding-style-guide.md), [Secure Coding Guide](https://gitcode.com/openharmony/docs/blob/master/en/contribute/OpenHarmony-c-cpp-secure-coding-guide.md))
7. ✅ Changes do not violate constraints in "Constraints and Boundaries" section

**Final response format:**
When task is complete, report:
```
## Task Complete

**Summary:** [Brief description of changes]

**Files Modified:**
- `path/to/file1` - [Brief reason for change]
- `path/to/file2` - [Brief reason for change]

- Build: [SUCCESS/FAILED]
- Unit tests: [PASSED/FAILED - list any failures]
- Policy validation: [N/A or no neverallow violations / violations found]
- Device testing: [N/A or tested with results]
```

## Architecture

### Directory Structure

```
sepolicy/                 # Security policy definitions (build-time)
├── base/                # Base policies
├── ohos_policy/         # OpenHarmony-specific policies
├── ohos_product/        # Product-specific policies
├── min/                 # Minimal policy set
└── whitelist/           # Policy validation whitelists used for selinux_check

scripts/                 # Build and validation scripts
├── build_policy.py      # Main policy compilation script
├── build_contexts.py    # File context compilation
└── selinux_check/       # Policy validation framework

framework/               # Runtime libraries and tools
├── policycoreutils/     # Core SELinux utilities
│   ├── src/            # Source files
│   └── include/        # Public headers
└── tools/              # Command-line tools
    ├── load_policy/       # Policy loading tool
    ├── restorecon/        # File restoration tool
    ├── hap_restorecon/    # HAP context restoration tool
    ├── param_check/       # Parameter permission check tool
    └── service_check/     # Service security check tool

interfaces/policycoreutils/include/  # innerkits
```

### Build System Architecture

The component uses the GN (Generate Ninja) build system with these key build targets:

1. **Policy Compilation** (`build_policy` action):
   - Collects `.te` (type enforcement) files from multiple policy directories
   - Uses `checkpolicy` and `secilc` from third_party/selinux
   - Generates `policy.31` (binary policy), `.cil` files (CIL policies), and hash files
   - Supports split policy build (system/vendor/public separation)

2. **Context Compilation** (`build_contexts` action):
   - Builds file_contexts, service_contexts, parameter_contexts
   - Uses `sefcontext_compile` to create binary contexts
   - Depends on `build_policy` completing first

3. **SELinux check** (`selinux_check` action):
   - Loads check configuration `selinux_check.json`
   - Uses `checkpolicy` to generate policy set `all.cil` and `file_contexts`
   - Parses policy and validates the policy
   - Raises exception if the new policy which violates standard

4. **Runtime Libraries**:
   - `libload_policy.z.so` - Loads SELinux policy at runtime
   - `librestorecon.z.so` - Restores file security contexts
   - `libhap_restorecon.z.so` - Set context for application process and application data file
   - `libparaperm_checker.z.so` - Parameter permission checking
   - `libservice_checker.z.so` - SA and hdf service security checking

### Command-line Tools (framework/tools/)

- **restorecon**

   **Location**: `framework/tools/restorecon/restorecon.c`

   Restores file security contexts recursively for a given path.

   Usage:
   ```bash
   restorecon /path/to/directory
   ```

   Calls `RestoreconRecurse()` from librestorecon.z.so.

- **hap_restorecon**

   **Location**: `framework/tools/hap_restorecon/test.cpp`

   Sets SELinux contexts for HAP applications. Supports both file and domain context operations.

   Usage:
   ```bash
   # File context restoration
   hap_restorecon -p /data/app/el1/100/base/com.ohos.test -n com.ohos.test -a normal -r 0

   # Domain context setting
   hap_restorecon -d -n com.ohos.test -a normal -i

   # Force restoration with interrupt support
   hap_restorecon -F -p /data/app/el1/100/base/com.ohos.test -n com.ohos.test -a normal -r 0
   ```

   Options:
   - `-p, --path`: Path to restorecon
   - `-n, --name`: Package name
   - `-a, --apl`: APL level (normal/system/core)
   - `-r, --recurse`: Recursively restore (0/1)
   - `-d, --domain`: Set domain context
   - `-i, --preinstalledapp`: Pre-installed app flag
   - `-F, --force-restorecon`: Force restoration with async support
   - `-S, --stop-restorecon`: Stop restoration task
   - `-R, --stop-reason`: Stop reason (0:UNIDLE, 1:UPDATE, 2:DELETE)
   - `-T, --test-interruption`: Test interruption logic
   - `-t, --run-time`: Run for N seconds then stop

## Where to Look

| Task | Primary Paths | Key Files | Read First |
| --- | --- | --- | --- |
| Add policy for new system service | `sepolicy/ohos_policy/*/system/` | `*.te`, `service_contexts` | `sepolicy/AGENTS.md` |
| Add policy for new vendor service | `sepolicy/ohos_policy/*/vendor/` | `*.te`, `service_contexts` | `sepolicy/AGENTS.md` |
| Fix AVC denial | `sepolicy/ohos_policy/*/` | Check dmesg/hilog, edit relevant `.te` | `sepolicy/AGENTS.md` "Debugging SELinux Issues" |
| Add cross-component type definition | `sepolicy/ohos_policy/*/public/` | `*.te` | `sepolicy/AGENTS.md` "Policy Organization" |
| Modify framework base policies | `sepolicy/base/` | `*.te`, `file_contexts` | Requires architecture review |
| Add CLI tool | `framework/tools/` | Tool directory, `BUILD.gn` | This document |
| Modify runtime library | `framework/policycoreutils/src/` | `*.c`, `*.h` | This document |
| Modify public API | `interfaces/policycoreutils/include/` | Header files | Requires compatibility check |

## Vocabulary Routing

| Term | Context | Document to Read |
| --- | --- | --- |
| `neverallow` | Build failure or policy rule | `sepolicy/base/glb_never_def.spt` + review all `neverallow` rules before adding any `allow` rule |
| `AVC denied` / `avc: denied` | dmesg/hilog output | `sepolicy/AGENTS.md` "Interpreting AVC Denials" + [SELinux Development Introduction](../../../docs/en/device-dev/subsystems/subsys-security-selinux-develop-intro.md) |
| `permissive=1` | AVC denial log | Indicates SELinux logged but did not block; still requires policy fix |
| `enforcing` / `permissive` | Mode configuration | This document "Runtime Configuration" |
| `domain transition` / `type transition` | Policy rule type | `sepolicy/base/` transition rules; may require `type_transition` and `allow` rules |
| `attribute` | Application policy | `sepolicy/AGENTS.md` "Common Issues" - use attributes for application policies |
| `scontext` / `tcontext` / `tclass` | AVC denial fields | Source label, target label, object class - use to construct policy rule |
| `hap_domain` / `normal_hap_attr` | Application labels | `sehap_contexts` and `sepolicy/AGENTS.md` application policy section |

## Constraints and Boundaries

### Security Constraints (CRITICAL - This is a security component)

**Do NOT:**
- **Do NOT** add overly permissive rules such as `allow *:* *` or `allow domain *:file *`
- **Do NOT** add rules that violate `without security review` constraints
- **Do NOT** modify generated files in output directories: `policy.31`, `*.cil` files are generated from `.te` source files
- **Do NOT** modify SELinux framework files without architecture review: `sepolicy/base/security_classes`, `sepolicy/base/initial_sids`, `sepolicy/base/access_vectors`, `sepolicy/base/mls`
- **Do NOT** change public API in `interfaces/policycoreutils/include/` without backward compatibility check
- **Do NOT** run `setenforce 0` on production devices without explicit approval
- **Do NOT** add new SELinux classes or permissions without architecture review

**Ask BEFORE:**
- **Ask BEFORE** adding any `allow` rule that grants wildcard permissions (`*`) or (`{ read write open }` to sensitive types)
- **Ask BEFORE** modifying `neverallow` rules in `sepolicy/base/glb_never_def.spt`
- **Ask BEFORE** adding new SELinux classes, permissions

### Architecture Invariants

- All `allow` rules must have corresponding justification documented in commit message
- Application policies **MUST** use attributes (`normal_hap_attr`, `system_basic_hap_attr`, `system_core_hap_attr`) not specific types
- System component policies go in `sepolicy/**/system/`, vendor component policies go in `sepolicy/**/vendor/`
- Cross-component type definitions go in `sepolicy/**/public/`
- Policies follow build order: base → ohos_policy → ohos_product, later policies can override earlier ones
- Generated files are outputs only: edit source `.te` and `*_contexts` files, never edit `policy.31` or `.cil`

### Generated File Boundaries

These files are **GENERATED** and must not be edited:
- `policy.31` - Binary policy compiled from `.te` files
- `*.cil` - CIL intermediate files compiled from `.te` files
- Binary context files compiled from `*_contexts` source files

Source of truth:
- `.te` files for policy rules
- `file_contexts`, `service_contexts`, `parameter_contexts`, etc. for security context mappings
- `sehap_contexts` for application context mappings

### Public API Stability

Files in `interfaces/policycoreutils/include/` are public APIs:
- Must maintain backward compatibility
- Changing function signatures requires version bump and migration plan
- New functions should be added, not existing functions modified
- Breaking changes require approval and migration documentation

### Common Agent Failure Patterns

1. **Editing generated files** - Agent edits `policy.31` or `.cil` instead of source `.te` files
2.  **Wrong policy location** - Agent puts system policy in `vendor/` or vendor policy in `system/`
3. **Type vs attribute confusion** - Agent uses specific type instead of attribute for application policies

## Policy for SELinux

@sepolicy/AGENTS.md

## Coding Guide
[Coding Style Guide](https://gitcode.com/openharmony/docs/blob/master/en/contribute/OpenHarmony-c-coding-style-guide.md)
[Secure Coding Guide](https://gitcode.com/openharmony/docs/blob/master/en/contribute/OpenHarmony-c-cpp-secure-coding-guide.md)

## GN Build Arguments Reference

Key configurable arguments in `selinux.gni`:
- `selinux_adapter_build_path` - Additional policy directories
- `selinux_adapter_components` - Specify the current component (default/system/vendor)
- `selinux_adapter_vendor_policy_version` - Vendor policy compatibility version
- `selinux_adapter_enforce` - Default enforcing mode
- `selinux_adapter_mcs_enable` - Multi-level security enablement
- `selinux_adapter_support_developer_mode` - Support developer mode
- `selinux_adapter_special_build_policy_script` - Enhanced policy compilation script
- `selinux_adapter_extra_args` - Extra arguments for policy compilation action
- `selinux_adapter_special_build_contexts_script` - Enhanced context compilation script
- `selinux_adapter_contexts_extra_args` - Extra arguments for context compilation action
- `selinux_adapter_check_extend_list` - Enhanced selinux check tool

## Dependencies

### External Dependencies
- `selinux:libselinux` - Core SELinux library
- `selinux:checkpolicy` - Policy compiler (host tool)
- `selinux:secilc` - CIL compiler (host tool)
- `selinux:sefcontext_compile` - File context compiler (host tool)
- `hilog:libhilog` - Logging framework
- `cJSON:cjson` - JSON parsing
- `bounds_checking_function:libsec` - Security functions

### Related Repositories
- `third_party/selinux/` - Main SELinux userspace tools
- `third_party/pcre/` - PCRE2 library for regex

## Runtime Configuration

SELinux mode is controlled by `/etc/selinux/config`:
- `SELINUX=enforcing` - Policies are enforced
- `SELINUX=permissive` - Violations logged but not blocked (development mode)

Runtime commands:
- `getenforce` - Show current mode
- `setenforce 1` - Enable enforcing mode
- `setenforce 0` - Enable permissive mode

## History Record

| Version | Date | Content | Author |
| -------- | -------- | -------- | -------- |
| v1.2 | 2026-07-10 | Add Where to Look, Vocabulary Routing, Constraints and Boundaries, Verification sections; Change to hb build commands; Remove duplicate Minimum checks; Remove Before You Start section | [Reviewer] |
| v1.1 | 2026-02-12 | Move document for SEPolicy to sepolicy/AGENTS.md | lihehe |
| v1.0 | 2026-01-30 | Init AGENTS.md | lihehe |

