### 关联的issue：

### 修改描述（修改功能描述，规格变更说明）：

### 策略合入自检
- [ ] 策略、注释不出现敏感词
- [ ] 不要继续往sepolicy/base下新增策略，策略放在sepolicy/ohos_policy下，按子系统/部件存放，没有请新增目录
- [ ] 如果涉及新增参数标签type ***, parameter_attr， 即type定义以parameter_attr结尾，需要与init责任田达成一致。参数规范详见：https://gitee.com/openharmony/docs/blob/master/zh-cn/device-dev/subsystems/subsys-boot-init-sysparam.md
- [ ] neverallow管控请写在相应目录的public路径下，保证系统和芯片组件能同时管控
- [ ] 不允许应用访问的SA服务使用neverallow规则看护
- [ ] 系统参数应禁止三方应用配置
- [ ] 具有写和执行的文件目录应该使用neverallow管控
- [ ] bin二进制执行文件应该设置独立标签
- [ ] 确保debug模式相关功能权限使用debug_only隔离
- [ ] 确保开发者模式相关功能权限用developer_only隔离
- [ ] 如果涉及修改neverallow策略，需要通过安全评审
    - [ ] 每条neverallow语句中仅允许出现唯一的“-violator_xxx”和唯一的"-rgm_violater_xxx"
    - [ ] 每条attribte violator_xx需要新增对应的neverallow violoater_xxx xxx:xxx {xxx}（该策略不在本仓库）
- [ ] 如果涉及新增sh作为主体的权限allow sh b:c {xxx} 需经过DFX责任田和安全评审
- [ ] 如果涉及新增su作为主体的权限allow su b:c {xxx} 无需添加，默认放行；su作为客体，需增加debug_only宏
- [ ] 新增ioctl权限allow a b:c {ioctl}需跟进avc日志中答应的ioctl命令字增加对应的allowxperm规则来限制具体使用的接口。例如：allowxperm accessibility data_service_el1_file:file ioctl { 0x5413 };
详见：https://gitee.com/openharmony/docs/blob/master/zh-cn/device-dev/subsystems/subsys-security-selinux-checklist.md#%E6%B6%89%E5%8F%8A%E6%96%B0%E5%A2%9Eioctl%E7%9A%84selinux%E7%AD%96%E7%95%A5%E8%87%AA%E6%A3%80
- [ ] 如果涉及hap权限，确认hap范围，如果是对全部应用使用hap_domain，allow hap_doamin xxx:xx xx
详见：https://gitee.com/openharmony/docs/blob/master/zh-cn/device-dev/subsystems/subsys-security-selinux-checklist.md#%E6%B6%89%E5%8F%8A%E5%BA%94%E7%94%A8%E7%9A%84selinux%E7%AD%96%E7%95%A5%E8%87%AA%E6%A3%80
- [ ] 不允许使用limit_domain\default_param\default_service\default_hdf_service默认标签

