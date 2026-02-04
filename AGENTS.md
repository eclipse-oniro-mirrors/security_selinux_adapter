# AGENTS.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

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
    ├── load_policy/    # Policy loading tool
    ├── restorecon/     # File restoration tool
    └── hap_restorecon/ # application context restoration tool

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

### Policy Organization

Policies are under `sepolicy/`. Each feature collects necessary policies in its own directory, which always has three sub-directories carrying different policies:

1. **\*/system/\*** - Policies for system components.
2. **\*/vendor/\*** - Policies for vendor components.
3. **\*/public/\*** - Policies for cross-component access, e.g., the type definition of config files in vendor image which should be accessed by system services.

The build system concatenates these in order, allowing product-specific policies to override base policies.

### Universal Policy and Context Files

The universal policy and context files contain SELinux policies to be configured during the development.

| File Name| Description| Document |
| -------- | -------- | -------- |
| *.te | SELinux policy source file, which defines the types and **allow** and **neverallow** rules.| [AVC Log Information and Policy Format](../../../docs/en/device-dev/subsystems/subsys-security-selinux-develop-intro.md#avc-log-information) |
| file_contexts | Defines the mappings between the paths of physical files and labels (contexts). | [Configuring policy for a File](../../../docs/en/device-dev/subsystems/subsys-security-selinux-sample-file.md) |
| virtfs_contexts | Defines the mappings between the paths of virtual files and labels.| [Configuring policy for a File in a Virtual File System](../../../docs/en/device-dev/subsystems/subsys-security-selinux-sample-file.md#file-in-a-virtual-file-system) |
| sehap_contexts | Defines the mappings between key application information, labels of application processes, and labels of application data directories.| [Configuring policy for Application Process](../../../docs/en/device-dev/subsystems/subsys-security-selinux-sample-domain.md#application-process) |
| parameter_contexts | Defines the mappings between parameters and labels.| [Configuring policy for a Parameter](../../../docs/en/device-dev/subsystems/subsys-security-selinux-sample-param.md) |
| service_contexts | Defines the mappings between SAs and labels.| [Configuring policy for an SA](../../../docs/en/device-dev/subsystems/subsys-security-selinux-sample-sa.md#sa) |
| hdf_service_contexts | Defines the mappings between HDF services and labels.| [Configuring policy for an HDF Service](../../../docs/en/device-dev/subsystems/subsys-security-selinux-sample-sa.md#hdf-service) |

### SELinux Framework Policy Files

The following table lists the SELinux framework policy files, which should not be modified generally.

| File Name| Description|
| -------- | -------- |
| security_classes | Defines the classes.|
| initial_sids | Defines the SIDs.|
| access_vectors | Defines the permissions supported by classes.|
| glb_perm_def.spt | Defines the global macros for classes and permissions. Global macros help simplify policy statements.|
| glb_never_def.spt | Defines global macros for **neverallow** rules.|
| mls | Defines the multi-level security (MLS) levels.|
| glb_te_def.spt | Defines global macros for TE rules.|
| attributes | Defines universal sets of attributes (access control rules). When defining a policy type, you can specify attributes. Then, the policy type inherits the permissions of the attributes.|
| glb_roles.spt | Defines roles.|
| users | Defines users.|
| initial_sid_contexts | Defines the initial SID contexts.|
| fs_use | Defines the default labels for different file systems.|

### Key Build Outputs

| Output | Location | Purpose |
|--------|----------|---------|
| policy.31 | `/etc/selinux/targeted/policy/` | Binary policy loaded by kernel |
| file_contexts | `/etc/selinux/targeted/contexts/` | file security contexts |
| parameter_contexts | `/etc/selinux/targeted/contexts/` | System parameter contexts |
| service_contexts | `/etc/selinux/targeted/contexts/` | Service security contexts |
| hdf_service_contexts | `/etc/selinux/targeted/contexts/` | HDF service contexts |
| sehap_contexts | `/etc/selinux/targeted/contexts/` | Application process and file security contexts |

## Coding Guide
[Coding Style Guide](../../../docs/en/contribute/OpenHarmony-c-coding-style-guide.md)
[Secure Coding Guide](../../../docs/en/contribute/OpenHarmony-c-cpp-secure-coding-guide.md)

## Debugging SELinux Issues

### Interpreting AVC Denials

When SELinux blocks an operation, it logs an AVC denial. Example:
```
audit: type=1400 audit(1502458430.566:4): avc: denied { open } for pid=1658 comm="setenforce"
  path="/sys/fs/selinux/enforce" scontext=u:r:hdcd:s0 tcontext=u:object_r:selinuxfs:s0 tclass=file permissive=1
```

Key fields:
- `{ open }` - The operation that was denied
- `scontext=u:r:hdcd:s0` - Source (process) label
- `tcontext=u:object_r:selinuxfs:s0` - Target (object) label
- `tclass=file` - Object class
- `permissive=1` - 0 = blocked (enforcing), 1 = logged only (permissive)

Converting to policy rule:
```te
allow hdcd selinuxfs:file open;
```

### Device Verification Commands

```bash
ls -lZ /                    # View file labels
ps -eZ                      # View process labels
getenforce                  # Check current mode (enforcing/permissive)
setenforce 1                # Enable enforcing mode
setenforce 0                # Enable permissive mode
```

## Policy Development Workflow

1. **Identify the denial** - Check dmesg or hilog for AVC messages
2. **Write the rule** - Add to appropriate `.te` file in `sepolicy/`
3. **Build policy** - Run `./build.sh --product-name=rk3568 -T selinux_adapter --ccache`
4. **Test on device** - Flash image and verify the denial is resolved

Details for [SELinux Development Introduction](../../../docs/en/device-dev/subsystems/subsys-security-selinux-develop-intro.md).

### Policy Organization

Place rules in the appropriate location:
- `sepolicy/ohos_policy/**/system/` - System component policies
- `sepolicy/ohos_policy/**/vendor/` - Vendor-specific policies
- `sepolicy/ohos_policy/**/public/` - Cross-component access (type definitions, etc.)

The build concatenates these in order, allowing product-specific policies to override base policies.

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

## Common Issues

- **SELinux Policies for Applications** - The policies, which allow application to access or allow a process to access application data file, should use attribute instead of type. For example, if a file can be read by system basic applications, the policy should be `allow system_basic_hap_attr example_file_type:file {read}` rather than `allow system_basic_hap example_file_type:file {read}`.

   | Application	| Attribute |
   | -------- | -------- |
   | normal applications	| normal_hap_attr |
   | system_basic applications |	system_basic_hap_attr |
   | system_core applications	| system_core_hap_attr |
   | All applications | hap_domain |

   | Application Data | Attribute|
   | -------- | -------- |
   | Directories of normal applications| normal_hap_data_file_attr |
   | Directories of system_basic applications| system_basic_hap_data_file_attr |
   | Directories of system_core applications| system_core_hap_data_file_attr |
   | All application directories| normal_hap_data_file_attr & system_basic_hap_data_file_attr & system_core_hap_data_file_attr |


- **Policies for system and vendor component** - An `allow` policy should be written under `sepolicy/**/system/*.te` if the access subject belongs to system component, even though its type is defined in `sepolicy/**/public/*.te` and the rule grant it permission to access object in vendor component. For vendor component access subjects, the policies should also be written under `sepolicy/**/vendor/*.te`. 

Details for [SELinux checklist](../../../docs/en/device-dev/subsystems/subsys-security-selinux-checklist.md).

## History Record

| Version | Date | Content | Author |
| -------- | -------- | -------- | -------- |
| v1.0 | 2026-01-30 | Init AGENTS.md | lihehe |
