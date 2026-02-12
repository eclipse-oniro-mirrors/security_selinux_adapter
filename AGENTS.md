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
./build.sh --product-name rk3568 -T selinux_adapter --ccache
```

### Running Tests

```bash
# Run all unit tests
./build.sh --product-name=rk3568 --build-target selinux_adapter_test --ccache

# Or use the test directly from build output
./out/rk3568/tests/selinux_adapter/selinux_adapter/selinux_adapter_unittest
```

The test framework uses OHA-developer_test. Individual test suites include:
- `hap_restorecon_unittest` - Set SELinux context for HAP tests
- `hap_restorecon_hapfile_test` - Convert context from `normal_hap_data_file` to `appdat` test
- `paraperm_checker_unittest` - Parameter permission checking tests
- `service_checker_unittest` - Service security checking tests
- `parameter_static_unittest` - Static parameter tests
- `seharmony_cjson_unittest` - JSON parsing tests

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
| v1.1 | 2026-02-12 | Move document for SEPolicy to sepolicy/AGENTS.md | lihehe |
| v1.0 | 2026-01-30 | Init AGENTS.md | lihehe |

