/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <fcntl.h>
#include <fstream>
#include <string>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>
#include "src/callbacks.h"
#include "policycoreutils.h"
#include "selinux/selinux.h"
#include "selinux_error.h"
#include "selinux_klog.h"

namespace {
constexpr int32_t PIPE_NUM = 2;
constexpr int32_t BUFF_SIZE = 1024;
constexpr const char SYSTEM_CIL[] = "/system/etc/selinux/system.cil";
constexpr const char VENDOR_CIL[] = "/vendor/etc/selinux/vendor.cil";
constexpr const char PUBLIC_CIL[] = "/vendor/etc/selinux/public.cil";
constexpr const char SYSTEM_CIL_HASH[] = "/system/etc/selinux/system.cil.sha256";
constexpr const char PRECOMPILED_POLICY_SYSTEM_CIL_HASH[] = "/vendor/etc/selinux/prebuild_sepolicy.system.cil.sha256";
constexpr const char COMPILE_OUTPUT_POLICY[] = "/dev/policy.31";
constexpr const char DEFAULT_POLICY[] = "/system/etc/selinux/targeted/policy/policy.31";
constexpr const char PRECOMPILED_POLICY[] = "/vendor/etc/selinux/prebuild_sepolicy/policy.31";
constexpr const char BACKUP_PRECOMPILED_POLICY[] = "/system/etc/selinux/policy.31";
constexpr const char VERSION_POLICY_PATH[] = "/vendor/etc/selinux/version";
constexpr const char COMPATIBLE_CIL_PATH[] = "/system/etc/selinux/compatible/";
} // namespace

static void InitSelinuxLog(void)
{
    // set selinux log callback
    SetSelinuxKmsgLevel(SELINUX_KWARN);
    union selinux_callback cb;
    cb.func_log = SelinuxKmsg;
    selinux_set_callback(SELINUX_CB_LOG, cb);
}

static bool ReadFileFirstLine(const std::string &file, std::string &line)
{
    line.clear();
    if (access(file.c_str(), R_OK) != 0) {
        selinux_log(SELINUX_ERROR, "Access file %s failed\n", file.c_str());
        return false;
    }
    std::ifstream hashFile(file);
    if (!hashFile) {
        selinux_log(SELINUX_ERROR, "Open file %s failed\n", file.c_str());
        return false;
    }
    std::getline(hashFile, line);
    hashFile.close();
    return true;
}

static bool CompareHash(const std::string &file1, const std::string &file2)
{
    std::string line1;
    std::string line2;
    if (!ReadFileFirstLine(file1, line1) || !ReadFileFirstLine(file2, line2)) {
        return false;
    }
    return (!line1.empty()) && (!line2.empty()) && (line1 == line2);
}

static void DeleteTmpPolicyFile(const std::string &policyFile)
{
    if ((policyFile == COMPILE_OUTPUT_POLICY) && (access(policyFile.c_str(), R_OK) == 0)) {
        unlink(policyFile.c_str());
    }
}

static bool GetVendorPolicyVersion(std::string & version)
{
    if (!ReadFileFirstLine(VERSION_POLICY_PATH, version)) {
        return false;
    }
    return !version.empty();
}

static bool ReadPolicyFile(const std::string &policyFile, void **data, size_t &size)
{
    int fd = open(policyFile.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        selinux_log(SELINUX_ERROR, "Open policy file failed\n");
        DeleteTmpPolicyFile(policyFile);
        return false;
    }
    struct stat sb;
    if (fstat(fd, &sb) < 0) {
        selinux_log(SELINUX_ERROR, "Stat policy file failed\n");
        close(fd);
        DeleteTmpPolicyFile(policyFile);
        return false;
    }
    if (sb.st_size < 0) {
        return false;
    }
    size = static_cast<size_t>(sb.st_size);
    *data = mmap(nullptr, size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (*data == MAP_FAILED) {
        selinux_log(SELINUX_ERROR, "Mmap policy file failed\n");
        close(fd);
        DeleteTmpPolicyFile(policyFile);
        return false;
    }
    close(fd);
    DeleteTmpPolicyFile(policyFile);
    return true;
}

static bool GetSelinuxConfigFromFile(int &config)
{
    // get config from /system/etc/selinux/config
    return (selinux_getenforcemode(&config) == 0) && (config >= 0);
}

static bool GetSelinuxConfigFromCmdLine(int &config)
{
    // get config from /proc/cmdline
    std::string cmdFile = "/proc/cmdline";
    std::string line;
    if (!ReadFileFirstLine(cmdFile, line)) {
        return false;
    }

    std::string key = " enforcing=";
    size_t index = line.find(key);
    if (index != line.npos) {
        int value = line[index + key.size()] - '0';
        selinux_log(SELINUX_INFO, "Read cmdline enforcing=%d\n", value);
        if ((value == 0) || (value == 1)) {
            config = value;
            return true;
        }
    }
    return false;
}

static bool SetEnforceState(int newEnforceState)
{
    int oldEnforceState = security_getenforce(); // get from /sys/fs/selinux/enforce
    if (oldEnforceState < 0) {
        selinux_log(SELINUX_ERROR, "Security getenforce failed\n");
        return false;
    }
    if (oldEnforceState != newEnforceState) {
        if (security_setenforce(newEnforceState) < 0) {
            selinux_log(SELINUX_ERROR, "Security setenforce failed\n");
            return false;
        }
    }
    return true;
}

static int GetEnforceConfig(void)
{
    int cmdConfig;
    int fileConfig;
    int enforce;
    if (GetSelinuxConfigFromCmdLine(cmdConfig)) {
        enforce = cmdConfig;
    } else if (GetSelinuxConfigFromFile(fileConfig)) {
        enforce = fileConfig;
    } else {
        enforce = 0;
    }
    selinux_log(SELINUX_INFO, "Get enforce config %d\n", enforce);
    return enforce;
}

static bool LoadPolicy(void *data, size_t size)
{
    set_selinuxmnt("/sys/fs/selinux");

    if (!SetEnforceState(GetEnforceConfig())) {
        return false;
    }

    if (security_load_policy(data, size) < 0) {
        selinux_log(SELINUX_ERROR, "Security load policy failed\n");
        return false;
    }
    return true;
}

static bool GetVersionPolicy(std::string &versionPolicy)
{
    std::string version;
    if (!GetVendorPolicyVersion(version)) {
        selinux_log(SELINUX_ERROR, "Get vendor policy version failed\n");
        return false;
    }
    std::string path(COMPATIBLE_CIL_PATH + version + ".cil");
    if (access(path.c_str(), F_OK) == 0) {
        versionPolicy = path;
        return true;
    }
    selinux_log(SELINUX_ERROR, "Get vendor version policy failed\n");
    return false;
}

static bool GetPublicPolicy(std::string &publicPolicy)
{
    if (access(PUBLIC_CIL, F_OK) == 0) {
        publicPolicy = PUBLIC_CIL;
        return true;
    }
    selinux_log(SELINUX_ERROR, "Get vendor public policy failed\n");
    return false;
}

static std::vector<const char *> CombineCompileCmd(void)
{
    std::vector<const char *> compileCmd = {
        "/system/bin/secilc",
        VENDOR_CIL,
        "-m",
        "-N",
        "-M",
        "true",
        "-G",
        "-c",
        "31",
        "-f",
        "/sys/fs/selinux/null",
        "-o",
        COMPILE_OUTPUT_POLICY,
    };
    compileCmd.emplace_back(SYSTEM_CIL);
    std::string versionPolicy;
    if (GetVersionPolicy(versionPolicy)) {
        selinux_log(SELINUX_WARNING, "Add policy %s\n", versionPolicy.c_str());
        compileCmd.emplace_back(versionPolicy.c_str());
    }
    std::string publicPolicy;
    if (GetPublicPolicy(publicPolicy)) {
        selinux_log(SELINUX_WARNING, "Add policy %s\n", publicPolicy.c_str());
        compileCmd.emplace_back(publicPolicy.c_str());
    }
    compileCmd.emplace_back(nullptr);
    return compileCmd;
}

static bool WaitForChild(pid_t pid)
{
    int status = -1;
    if (waitpid(pid, &status, 0) < 0) {
        selinux_log(SELINUX_ERROR, "Waitpid failed\n");
        return false;
    }
    if (WIFEXITED(status)) {
        int exitCode = WEXITSTATUS(status);
        selinux_log(SELINUX_INFO, "Child terminated by exit %d\n", exitCode);
        if (exitCode == 0) {
            return true;
        }
    } else if (WIFSIGNALED(status)) {
        selinux_log(SELINUX_ERROR, "Child terminated by signal %d\n", WTERMSIG(status));
    } else if (WIFSTOPPED(status)) {
        selinux_log(SELINUX_ERROR, "Child stopped by signal %d\n", WSTOPSIG(status));
    } else {
        selinux_log(SELINUX_ERROR, "Child exit with status %d\n", status);
    }
    return false;
}

static bool CompilePolicy(void)
{
    std::vector<const char *> compileCmd = CombineCompileCmd();

    int pipeFd[PIPE_NUM];
    if (pipe(pipeFd) < 0) {
        selinux_log(SELINUX_ERROR, "Create pipe failed\n");
        return false;
    }
    pid_t pid = fork();
    if (pid < 0) {
        selinux_log(SELINUX_ERROR, "Fork subprocess failed\n");
        (void)close(pipeFd[0]);
        (void)close(pipeFd[1]);
        return false;
    }
    if (pid == 0) {
        (void)close(pipeFd[0]);
        if (dup2(pipeFd[1], STDERR_FILENO) == -1) {
            selinux_log(SELINUX_ERROR, "Dup2 failed\n");
            (void)close(pipeFd[1]);
            _exit(1);
        }
        (void)close(pipeFd[1]);
        if (execv(compileCmd[0], const_cast<char **>(compileCmd.data())) == -1) {
            selinux_log(SELINUX_ERROR, "Execv subprocess failed\n");
            return false;
        }
        _exit(1);
        return false;
    }
    (void)close(pipeFd[1]);

    FILE *fp = fdopen(pipeFd[0], "r");
    if (fp != nullptr) {
        char buf[BUFF_SIZE] = {0};
        while (fgets(buf, sizeof(buf) - 1, fp) != nullptr) {
            size_t n = strlen(buf);
            if (n == 0) {
                continue;
            }
            if (buf[n - 1] == '\n') {
                buf[n - 1] = '\0';
            }
            if (strstr(buf, "Failed") != nullptr) {
                selinux_log(SELINUX_ERROR, "SELinux compile result: %s\n", buf);
            }
        }
        fclose(fp);
    }

    (void)close(pipeFd[0]);

    return WaitForChild(pid);
}

static bool GetPolicyFile(std::string &policyFile)
{
    if (access(SYSTEM_CIL, R_OK) != 0) { // no system.cil file
        policyFile = DEFAULT_POLICY;
        selinux_log(SELINUX_WARNING, "No cil file found, load default policy\n");
        return true;
    }

    // check precompiled policy
    if (CompareHash(PRECOMPILED_POLICY_SYSTEM_CIL_HASH, SYSTEM_CIL_HASH)) {
        if (access(PRECOMPILED_POLICY, R_OK) == 0) {
            policyFile = PRECOMPILED_POLICY;
            selinux_log(SELINUX_WARNING, "Found precompiled policy, load %s\n", policyFile.c_str());
            return true;
        }
        if (access(BACKUP_PRECOMPILED_POLICY, R_OK) == 0) {
            policyFile = BACKUP_PRECOMPILED_POLICY;
            selinux_log(SELINUX_WARNING, "Found precompiled policy, load %s\n", policyFile.c_str());
            return true;
        }
    }

    // no precompiled policy, compile from cil
    selinux_log(SELINUX_WARNING, "No precompiled policy found, compile it\n");
    if (CompilePolicy()) {
        policyFile = COMPILE_OUTPUT_POLICY;
        return true;
    }
    return false;
}

static int LoadPolicyFromFile(const std::string &policyFile)
{
    void *data = nullptr;
    size_t size = 0;
    if (!ReadPolicyFile(policyFile, &data, size)) {
        return -1;
    }
    if (!LoadPolicy(data, size)) {
        munmap(data, size);
        return -1;
    }
    munmap(data, size);
    return 0;
}

int LoadPolicy(void)
{
    InitSelinuxLog();
    std::string policyFile;
    if (!GetPolicyFile(policyFile)) {
        return -1;
    }
    return LoadPolicyFromFile(policyFile);
}
