# AGENTS.md

## 项目定位

本仓库对应 OpenHarmony `base/security/selinux_adapter`，基于 SELinux 为系统资源（文件、参数、SA、HDF 服务）提供强制访问控制（MAC），覆盖策略与上下文的编译、加载、校验，以及应用标签设置。优先按这些目录定位问题：

- `sepolicy/`：安全策略与上下文定义的源头（`.te`、`*_contexts`）；AVC 修复与新增策略高频落在 `sepolicy/ohos_policy/**`，策略组织与 AVC 排查指导见 `sepolicy/AGENTS.md`
- `framework/policycoreutils/`：运行时库（策略加载、restorecon、hap_restorecon、参数/SA 权限检查）
- `framework/tools/`：命令行工具（load_policy、restorecon、hap_restorecon、param_check、service_check）
- `interfaces/policycoreutils/include/`：innerkits 公共头文件，改动需向后兼容
- `scripts/`：策略/上下文编译脚本与 selinux_check 策略校验框架
- `config/`、`test/unittest/`：构建配置与单元测试

## 核心职责划分

| 组件 | 职责 |
| --- | --- |
| sepolicy（base/ohos_policy/ohos_product） | TE 策略与上下文映射的定义源头，编译生成 `policy.31` 与二进制上下文 |
| libload_policy / librestorecon / libhap_restorecon | 运行时加载策略、恢复文件上下文、为应用进程与应用数据文件设置标签 |
| libparaperm_checker / libservice_checker | 系统参数、SA 与 HDF 服务的 SELinux 权限检查（安全强制点） |
| scripts/selinux_check | 编译期策略合法性校验，新策略违反标准规范时使构建失败 |
| framework/tools | 设备端 SELinux 命令行工具 |

## 改动前确认

改动前必须明确：

1. **任务类别**：策略规则、上下文映射、AVC 修复、运行时库、CLI 工具、公共 API、构建脚本、策略校验或其它
2. **已读文档**：列出相关的 AGENTS.md、源码文件或设计文档（策略类任务必读 `sepolicy/AGENTS.md`）
3. **将加载的技能**：按下方「技能调用」表匹配本次任务对应的 ohos-* 技能并加载；无匹配项时显式声明"无"，不得静默跳过
4. **适用约束**：列出本次改动必须遵守的约束项（策略位置、生成文件边界、neverallow、API 兼容性、安全边界等）

## 知识索引

改动前按场景读取对应文件或查看代码：

| 场景 | 先读 |
| --- | --- |
| 新增/修改策略规则、策略文件组织 | `sepolicy/AGENTS.md`（核心规则、策略放置） |
| 修复 AVC denied（dmesg/hilog 出现 `avc: denied`） | `sepolicy/AGENTS.md`（AVC 排查） |
| 应用策略与 hap 标签（`hap_domain`、`normal_hap_attr`） | `sepolicy/AGENTS.md`（应用策略必须用属性）与 `sehap_contexts` |
| 修改 base 框架策略文件（security_classes、access_vectors、initial_sids、mls） | 需架构评审；先读 `sepolicy/AGENTS.md`（框架文件改动需架构评审） |
| `neverallow` 构建失败 | `sepolicy/base/public/glb_never_def.spt`；添加任何 `allow` 前先核对全部 `neverallow` 规则 |
| 新增系统 SA / 新组件策略落地 | `sepolicy/AGENTS.md`（知识索引）；参照完整样例 `sepolicy/ohos_policy/update/module_update/`（`public/type.te` 定义域类型 + `system/` 下 `service_contexts`、`file_contexts`、`init.te` 等） |
| 新增 `sadomain` 域 | 必须同步登记 `sepolicy/whitelist/flex/domain_baseline.json`（`user.sadomain` 数组），否则 `scripts/selinux_check` 的 check_domain 校验使构建失败 |
| 设备端验证（getenforce、ls -lZ 等） | `sepolicy/AGENTS.md`（AVC 排查、设备验证命令） |
| 运行时库/CLI 工具改动 | 探索 `framework/`；涉及公共头文件时检查所有调用方 |
| 构建脚本、selinux_check 校验扩展 | 探索 `scripts/` |
| 日志/代码出现 `SEHM_*` 事件、HiSysEvent 上报（hap_restorecon/restorecon） | `hisysevent.yaml`（domain: SEHARMONY）；事件定义与上报时机改动影响故障归因，需检查上报调用方 |
| 通用 SELinux 开发背景 | [SELinux Development Introduction](https://gitcode.com/openharmony/docs/blob/master/en/device-dev/subsystems/subsys-security-selinux-develop-intro.md) |

## 技能调用

改动前必须按下表匹配并加载对应 ohos-* 技能；无匹配项时在「改动前确认」第 3 项中显式声明"无"。按场景选用：

### 开发与规范

| 场景 | 推荐技能 | 触发时机 |
| --- | --- | --- |
| 编写/修改/审查 OpenHarmony C 或 C++ 代码 | `ohos-dev-cpp-coding-style` | 任何 `framework/` 下 `.c/.cpp/.h` 改动 |
| 为新增/迁移 SystemAbility 补充 SELinux 策略 | `ohos-dev-sa-codegen` | 新增 SA 需要配套 `service_contexts` 与 `.te` 策略时 |

### 安全审查（本仓库为安全强制组件，优先级高）

| 场景 | 推荐技能 | 触发时机 |
| --- | --- | --- |
| C/C++ 安全审查 | `ohos-dev-security-code-review` | 改动 paraperm_checker/service_checker/hap_restorecon 等权限判定与标签设置逻辑后必须用此技能审查 |

### 构建与测试

| 场景 | 推荐技能 | 触发时机 |
| --- | --- | --- |
| OpenHarmony 构建执行/诊断 | `ohos-dev-build-execution-diagnosis` | 部件独立编译、策略编译失败、`build.log` 分析 |
| 生成 C/C++ 单元测试（HWTEST/ohos_unittest） | `ohos-test-ut-generation` | `test/unittest/` 补充单元测试用例 |
| 设备端验证（hdc 日志/标签检查） | `ohos-dev-hdc-command-usage` | 真机验证策略生效、AVC denied、`ls -lZ` 文件标签 |

### 工作流

| 场景 | 推荐技能 | 触发时机 |
| --- | --- | --- |
| PR CI 状态调查（DCP 事件、构建标签、CI 日志） | `ohos-ci-openharmony-ci-analysis` | PR 提交后排查 CI 失败 |
| GitCode PR 审查（oh-gc 获取 PR 元数据/diff/评论） | `ohos-dev-gitcode-pr-review` | 提交或审查 PR |
| 审计本文件等仓库代理指导质量 | `ohos-design-agent-instruction-quality-review` | 维护/改进本 AGENTS.md 或其它 coding-agent 指导文件 |

## 构建和验证

构建命令从 OpenHarmony 源码根目录执行，不在本子目录执行。

```bash
# 构建功能代码
./build.sh --product-name rk3568 --build-target selinux_adapter

# 独立编译（功能代码）
hb build selinux_adapter -i

# 独立编译（测试用例）
hb build selinux_adapter -t

# 运行单元测试
run -t UT -tp selinux_adapter

# 静态分析（如可用）
./build.sh --product-name rk3568 --build-target selinux_adapter --gn-args enable_cpp_static_check=true
```

按任务类型的附加验证：

| 任务类型 | 附加验证 |
| --- | --- |
| 策略改动 | 检查构建日志无 `neverallow` 违规；启动设备检查 `dmesg`/`hilog` 无预期外 AVC denied |
| 上下文文件改动 | 验证上下文映射正确，用 `ls -lZ` 检查文件标签 |
| 公共 API 改动 | 检查 `interfaces/policycoreutils/include/` 向后兼容并测试依赖组件 |
| 运行时库/CLI 工具改动 | 运行对应单元测试，确认无 API 破坏 |

## 项目约束

### 安全约束（CRITICAL）

- 禁止添加过度宽松规则（如 `allow *:* *`、`allow domain *:file *`）；任何 `allow` 规则必须在提交信息中说明理由
- 给敏感类型授予通配权限（`*`）或敏感权限组合（如 `{ read write open }`）前必须先询问
- 禁止未经审批在生产设备执行 `setenforce 0`
- 修改 `sepolicy/base/public/glb_never_def.spt` 中的 `neverallow`、新增 SELinux class/permission 属于架构级改动，动手前必须声明并寻求人工审查

### 生成文件边界

- `policy.31`、`*.cil`、二进制 `*_contexts` 均为构建产物，禁止手改；源头是 `.te` 与文本 `*_contexts`、`sehap_contexts`

### 策略位置与组织约束

- 应用策略必须使用属性（`normal_hap_attr`、`system_basic_hap_attr`、`system_core_hap_attr`），不得使用具体 type
- 系统组件策略放 `sepolicy/**/system/`，厂商组件策略放 `sepolicy/**/vendor/`，跨组件类型定义放 `sepolicy/**/public/`
- 策略按 base → ohos_policy → ohos_product 顺序编译，后序策略可覆盖先序
- `sepolicy/base/` 框架文件（`security_classes`、`initial_sids`、`access_vectors`、`mls`）修改需架构评审

### 公共 API 稳定性约束

- `interfaces/policycoreutils/include/` 为公共 API：必须向后兼容；新增函数优于修改既有函数；破坏性变更需审批与迁移文档

### DFX 与第三方依赖约束

- `hisysevent.yaml`（domain: SEHARMONY）定义 hap_restorecon/restorecon 的事件上报，事件定义与上报时机改动影响故障归因，需同步检查上报调用方
- 依赖 `third_party/selinux`（checkpolicy/secilc/libselinux/sefcontext_compile）与 `pcre`；升级需回归策略编译与 selinux_check 校验

### 常见代理失败模式

1. 手改 `policy.31`/`.cil` 等生成文件而非 `.te` 源文件
2. 系统策略误放 `vendor/`、厂商策略误放 `system/`
3. 应用策略误用具体 type 而非属性

## 完成定义

改动必须满足：

- 构建受影响的目标，或明确说明无法构建的原因
- 策略改动：构建日志无 `neverallow` 违规
- 运行对应单元测试；公共 API 改动确认向后兼容
- 说明运行的命令、结果、跳过的验证及剩余风险（设备侧 AVC 验证无法执行时必须列出）

## 最终响应要求

任务完成时报告：

0. **技能加载回执**：实际调用了哪些 ohos-* 技能（skill 名），或声明"未加载"及原因
1. **修改清单**：修改的文件列表和关键变更点
2. **构建结果**：运行的构建命令和结果（成功/失败）
3. **测试结果**：运行的测试命令和结果（通过/失败）
4. **策略验证**：neverallow 检查结果与设备侧 AVC 验证情况（或说明跳过原因）
5. **影响评估**：兼容性与安全影响评估（策略、上下文、公共 API）
6. **风险说明**：未验证的场景和剩余风险

## 常见陷阱

- 只加 `allow` 不核对 `neverallow` 约束，导致构建失败或放宽安全边界
- 修改生成产物而非 `.te`/`*_contexts` 源文件
- 策略放错目录（system/vendor/public），导致拆分策略构建或跨组件引用失败
- `permissive=1` 下 AVC 只记录不拦截，误认为问题已修复
- 公共头文件改动未检查所有调用方

## 编码规范

[Coding Style Guide](https://gitcode.com/openharmony/docs/blob/master/en/contribute/OpenHarmony-c-coding-style-guide.md)
[Secure Coding Guide](https://gitcode.com/openharmony/docs/blob/master/en/contribute/OpenHarmony-c-cpp-secure-coding-guide.md)

## 历史记录

| version | date | modify content | writer |
|------|------|---------|--------|
| v1.0 | 2026-01-30 | Init AGENTS.md | lihehe |
| v1.1 | 2026-02-12 | Move document for SEPolicy to sepolicy/AGENTS.md | lihehe |
| v1.2 | 2026-07-10 | Add Where to Look, Vocabulary Routing, Constraints and Boundaries, Verification sections | [Reviewer] |
| v2.0 | 2026-09-23 | Restructure: remove code-explorable knowledge (directory tree details, build system internals, CLI usage, GN args reference, dependency lists), keep constraints and routing, add mandatory ohos-* skill invocation and receipt | lihehe, AI |
| v2.1 | 2026-09-23 | KB evaluation iteration 1: fix glb_never_def.spt path (base/public/), convert out-of-repo doc links to external URLs, add new-SA canonical example routing and domain_baseline.json registration gate to knowledge index | AI |
| v2.2 | 2026-09-23 | Restructure sepolicy/AGENTS.md (sub-directory guidance); sync knowledge-index section references to new Chinese section names; fix glb_never_def.spt path in security constraints; add ./build.sh build command | lihehe, AI |
| v2.3 | 2026-09-23 | Quality review optimization: high-frequency path annotation, SEHM_* hisysevent routing and DFX/dependency constraints, static analysis command | lihehe, AI |
