# SEPolicy（sepolicy/ 子目录指导）

## 定位

本文件覆盖 `sepolicy/` 下 TE 策略（`.te`）与上下文文件（`*_contexts`）的改动指导；仓库级流程、技能调用与总体约束见根目录 `AGENTS.md`。改动前需按根目录 `AGENTS.md`「改动前确认」声明任务类别、已读文档、技能与适用约束。

目录职责：
- `sepolicy/base/`：框架策略，修改需架构评审（全局宏与 `neverallow` 定义在 `base/public/glb_*.spt`）
- `sepolicy/ohos_policy/`：OpenHarmony 子系统策略
- `sepolicy/ohos_product/`：产品策略
- `sepolicy/min/`：最小策略集
- `sepolicy/whitelist/`：selinux_check 校验用的基线与白名单

## 知识索引

改动前按场景读取：

| 场景 | 先读 |
| --- | --- |
| 新增系统 SA 的完整策略落地 | 完整样例 `sepolicy/ohos_policy/update/module_update/`：`public/type.te` 定义域类型，`system/` 下 `service.te`、`service_contexts`、`file_contexts`、`init.te` |
| 新增 vendor 组件策略 | 参照 `sepolicy/ohos_policy/powermgr/battery_manager/`（`public/system/vendor` 三目录完整样例） |
| 构建日志出现 `neverallow` 冲突 | 本文件「neverallow 先行」；`sepolicy/base/public/glb_never_def.spt` |
| 通用 SELinux 开发背景、AVC 日志格式 | [SELinux Development Introduction](https://gitcode.com/openharmony/docs/blob/master/en/device-dev/subsystems/subsys-security-selinux-develop-intro.md) |
| 各类上下文文件的配置样例 | 下表官方样例文档 |
| 策略合入自检 | [SELinux checklist](https://gitcode.com/openharmony/docs/blob/master/zh-cn/device-dev/subsystems/subsys-security-selinux-checklist.md) |

上下文文件与官方样例（文本 `*_contexts` 是定义源头，编译产物禁止手改）：

| 文件 | 作用 | 样例文档 |
| --- | --- | --- |
| file_contexts | 物理文件路径到标签的映射 | [Configuring policy for a File](https://gitcode.com/openharmony/docs/blob/master/en/device-dev/subsystems/subsys-security-selinux-sample-file.md) |
| virtfs_contexts | 虚拟文件路径到标签的映射 | [File in a Virtual File System](https://gitcode.com/openharmony/docs/blob/master/en/device-dev/subsystems/subsys-security-selinux-sample-file.md#file-in-a-virtual-file-system) |
| sehap_contexts | 应用信息到进程/数据目录标签的映射 | [Application Process](https://gitcode.com/openharmony/docs/blob/master/en/device-dev/subsystems/subsys-security-selinux-sample-domain.md#application-process) |
| parameter_contexts | 系统参数到标签的映射 | [Configuring policy for a Parameter](https://gitcode.com/openharmony/docs/blob/master/en/device-dev/subsystems/subsys-security-selinux-sample-param.md) |
| service_contexts | SA 到标签的映射 | [SA](https://gitcode.com/openharmony/docs/blob/master/en/device-dev/subsystems/subsys-security-selinux-sample-sa.md#sa) |
| hdf_service_contexts | HDF 服务到标签的映射 | [HDF Service](https://gitcode.com/openharmony/docs/blob/master/en/device-dev/subsystems/subsys-security-selinux-sample-sa.md#hdf-service) |

## 核心规则（添加/修改策略前必查）

### neverallow 先行

- 添加任何 `allow` 前先核对 `sepolicy/base/public/glb_never_def.spt` 及相关目录 `public/` 下的全部 `neverallow` 规则；违反 `neverallow` 会直接构建失败
- 禁止添加过度宽松规则（如 `allow *:* *`、`allow domain *:file *`）；任何 `allow` 规则必须在提交信息中说明理由
- 验证：`./build.sh --product-name rk3568 --build-target selinux_adapter` 或 `hb build selinux_adapter -i`，检查构建日志无 `neverallow` 违规

### 新增 sadomain 域必须登记基线

任何携带 `sadomain` 属性的新域必须同步登记 `sepolicy/whitelist/flex/domain_baseline.json`（追加到 `user.sadomain` 数组），否则 `scripts/selinux_check/check_domain.py` 校验会使构建失败。

### 策略放置

- 系统组件策略放 `**/system/`，厂商组件策略放 `**/vendor/`，跨组件类型定义放 `**/public/`
- `allow` 规则按**主体归属**放置：主体属系统组件即写 `**/system/*.te`（即使客体在 vendor 侧），厂商主体同理
- 策略按 base → ohos_policy → ohos_product 顺序编译，后序可覆盖先序

### 应用策略必须用属性

允许应用访问、或允许进程访问应用数据文件的策略，必须用属性而非具体 type：

| 对象 | 属性 |
| --- | --- |
| normal 应用 | `normal_hap_attr` |
| system_basic 应用 | `system_basic_hap_attr` |
| system_core 应用 | `system_core_hap_attr` |
| 全部应用 | `hap_domain` |
| 各级应用数据目录 | `normal_hap_data_file_attr` / `system_basic_hap_data_file_attr` / `system_core_hap_data_file_attr` |

### 框架文件改动需架构评审

`sepolicy/base/` 下的 `security_classes`、`initial_sids`、`access_vectors`、`mls`、`attributes`、`users`、`glb_roles.spt`、`fs_use`、`initial_sid_contexts`，以及 `base/public/` 下的 `glb_*.spt`；新增 SELinux class/permission 同属架构级改动。

## AVC 排查

典型 AVC denial：

```
avc: denied { open } for pid=1658 comm="xxx" path="..."
  scontext=u:r:hdcd:s0 tcontext=u:object_r:selinuxfs:s0 tclass=file permissive=1
```

- `{ open }`：被拒操作；`scontext`：主体标签；`tcontext`：客体标签；`tclass`：对象类
- 转换为策略：`allow <scontext 的域> <tcontext 的类型>:<tclass> <操作>;`，如 `allow hdcd selinuxfs:file open;`
- `permissive=1` 表示仅记录未拦截，**不等于问题已修复**

排查流程：定位 dmesg/hilog 中的 AVC → 按上方规则写 `.te` → 构建验证（命令见「neverallow 先行」）无 `neverallow` 违规 → 刷机验证 denial 消失。

设备验证命令：

```bash
ls -lZ /path   # 查看文件标签
ps -eZ         # 查看进程标签
getenforce     # 查看当前模式（enforcing/permissive）
```

## 构建产物与设备位置

`policy.31` 与二进制 `*_contexts` 为编译产物（源头是 `.te` 与文本 `*_contexts`，禁止手改），部署在设备 `/etc/selinux/targeted/`（策略在 `policy/`，上下文在 `contexts/`）。

## 完成定义

- 构建通过（`./build.sh --product-name rk3568 --build-target selinux_adapter` 或 `hb build selinux_adapter -i`），日志无 `neverallow` 违规
- 新增 `sadomain` 域已登记 `domain_baseline.json`
- 策略改动：设备 dmesg/hilog 无预期外 AVC denied（无法设备验证时必须列为剩余风险）
- 说明运行的命令、结果与剩余风险；任务完成报告按根目录 `AGENTS.md`「最终响应要求」执行

## 历史记录

| version | date | modify content | writer |
|------|------|---------|--------|
| v1.0 | 2026-02-12 | Init sepolicy/AGENTS.md | lihehe |
| v2.0 | 2026-09-23 | 参照 access_token 子目录 AGENTS.md 风格重构：中文化；删除框架文件逐项描述与重复章节；保留并强化约束（neverallow 先行、sadomain 基线登记、策略放置、应用属性、框架文件评审）；合并 AVC 排查流程与完成定义 | lihehe, AI |
| v2.1 | 2026-09-23 | Quality review optimization: pre-edit declaration pointer to root, vendor example and neverallow vocabulary routing, overly-permissive rule prohibition, build.sh verification variant | lihehe, AI |
