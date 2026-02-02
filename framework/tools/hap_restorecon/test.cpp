/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include <cstdio>
#include <cstdlib>
#include <getopt.h>
#include <iosfwd>
#include <iostream>
#include <istream>
#include <ostream>
#include <sstream>
#include <streambuf>
#include <string>
#include <unistd.h>
#include <vector>
#include <thread>

#include "hap_restorecon.h"
#include "selinux_error.h"

using namespace Selinux;

static const int WAIT_TIME_5S = 5;
static const uint32_t TEST_UID = 20190166;
struct TestInput {
    std::string name = "";
    std::string apl = "";
    std::vector<std::string> multiPath;
    bool domain = false;
    std::string recurse = "1";
    bool isPreinstalledApp = false;
    std::string extension = "";
    uint32_t uid = 0;
    bool force = false;
    bool stop = false;
    int stopReason = 0;
    bool testInterruption = false;
    int runTime = 0;
};

static void PrintUsage()
{
    printf("Usage:\n");
    printf("hap_restorecon -p /data/app/el1/100/base/com.ohos.test -n com.ohos.test -a normal -r 0\n");
    printf("hap_restorecon -d -n com.ohos.test -a normal -i\n");
    printf("\n");
    printf("Options:\n");
    printf(" -h (--help)                show the help information.              [eg: hap_restorecon -h]\n");
    printf(" -p (--path)                path to restorecon.                     [eg: -p "
           "/data/app/el1/100/base/com.ohos.test]\n");
    printf(" -r (--recurse)             recurse?                                [eg: -r 0]\n");
    printf(" -a (--apl)                 apl info.                               [eg: -a normal]\n");
    printf(" -n (--name)                package name.                           [eg: -n com.ohos.test]\n");
    printf(" -d (--domain)              setcon domain.                          [eg: -d]\n");
    printf(" -m (--multipath)           paths to restorecon.                    [eg: -m "
           "/data/app/el1/100/base/com.ohos.test1 "
           "/data/app/el1/100/base/com.ohos.test2]\n");
    printf(" -i (--preinstalledapp)     setcon preinstalled                     [eg: -i]\n");
    printf(" -e (--extension)           extension info.                         [eg: -e extension_info]\n");
    printf(" -F (--force-restorecon)    force restorecon.                       [eg: -F]\n");
    printf(" -S (--stop-restorecon)     stop restorecon.                        [eg: -S]\n");
    printf(" -R (--stop-reason)         stop reason (0:UNIDLE, 1:UPDATE, 2:DELETE). [eg: -R 0]\n");
    printf(" -T (--test-interruption)   test interruption logic.                [eg: -T]\n");
    printf(" -t (--run-time)            run for N seconds then stop.            [eg: -t 5]\n");
    printf("\n");
}

static void SetOptions(int argc, char *argv[], const option *options, TestInput &input)
{
    int index = 0;
    const char *optStr = "hda:p:n:r:m:ie:uFSR:Tt:";
    int para = 0;
    while ((para = getopt_long(argc, argv, optStr, options, &index)) != -1) {
        switch (para) {
            case 'h':
                PrintUsage();
                exit(0);
            case 'a': input.apl = optarg; break;
            case 'd': input.domain = true; break;
            case 'p': input.multiPath.emplace_back(optarg); break;
            case 'm': {
                std::stringstream str(optarg);
                std::string tmp;
                while (str >> tmp) {
                    input.multiPath.emplace_back(tmp);
                }
                break;
            }
            case 'n': input.name = optarg; break;
            case 'r': input.recurse = optarg; break;
            case 'i': input.isPreinstalledApp = true; break;
            case 'e': input.extension = optarg; break;
            case 'u': input.uid = TEST_UID; break;
            case 'F': input.force = true; break;
            case 'S': input.stop = true; break;
            case 'R': input.stopReason = atoi(optarg); break;
            case 'T': input.testInterruption = true; break;
            case 't': input.runTime = atoi(optarg); break;
            default:
                printf("Try 'hap_restorecon -h' for more information.\n");
                exit(-1);
        }
    }
}

int main(int argc, char *argv[])
{
    struct option options[] = {
        {"help", no_argument, nullptr, 'h'},          {"apl", required_argument, nullptr, 'a'},
        {"name", required_argument, nullptr, 'n'},    {"domain", no_argument, nullptr, 'd'},
        {"path", required_argument, nullptr, 'p'},    {"mutilpath", required_argument, nullptr, 'm'},
        {"recurse", required_argument, nullptr, 'r'}, {"preinstalledapp", no_argument, nullptr, 'i'},
        {"extension", required_argument, nullptr, 'e'},
        {"force-restorecon", no_argument, nullptr, 'F'},
        {"stop-restorecon", no_argument, nullptr, 'S'},
        {"stop-reason", required_argument, nullptr, 'R'},
        {"test-interruption", no_argument, nullptr, 'T'},
        {"run-time", required_argument, nullptr, 't'},
        {nullptr, no_argument, nullptr, 0},
    };

    if (argc == 1) {
        PrintUsage();
        exit(0);
    }

    TestInput testCmd;
    SetOptions(argc, argv, options, testCmd);
    HapContext test;
    HapFileRestoreContext& forceTest = HapFileRestoreContext::GetInstance();
    int res = 0;
    if (testCmd.testInterruption) {
        HapFileInfo hapFileInfo = {
            .pathNameOrig = testCmd.multiPath,
            .apl = testCmd.apl,
            .packageName = testCmd.name,
            .flags = static_cast<unsigned int>(atoi(testCmd.recurse.c_str())),
            .hapFlags = testCmd.isPreinstalledApp ? 1 : 0,
            .uid = testCmd.uid
        };

        printf("=== Starting Interruption Test ===\n");
        printf("1. Starting SetFileConForce in background thread...\n");
        std::thread t([&forceTest, hapFileInfo]() {
            ResultInfo resultInfo;
            int r = forceTest.SetFileConForce(hapFileInfo, 1, resultInfo);
            printf("Thread finished with result: %d, total: %u, current: %u\n",
                r, resultInfo.totalCount, resultInfo.currentCount);
        });
        printf("2. Sleeping %ds...\n", WAIT_TIME_5S);
        sleep(WAIT_TIME_5S);
        printf("3. Calling StopSetFileCon...\n");
        res = forceTest.StopSetFileCon(hapFileInfo, StopReason::BUSY, "BUSY");
        printf("Stop result: %d\n", res);
        if (t.joinable()) {
            t.join();
        }
        printf("4. Sleeping %ds (simulating pause)...\n", WAIT_TIME_5S);
        sleep(WAIT_TIME_5S);
        printf("5. Resuming SetFileConForce...\n");
        ResultInfo resultInfo;
        res = forceTest.SetFileConForce(hapFileInfo, 1, resultInfo);
        printf("Resume finished with result: %d, total: %u, current: %u\n",
            res, resultInfo.totalCount, resultInfo.currentCount);
    } else if (testCmd.force) {
        HapFileInfo hapFileInfo = {
            .pathNameOrig = testCmd.multiPath,
            .apl = testCmd.apl,
            .packageName = testCmd.name,
            .flags = static_cast<unsigned int>(atoi(testCmd.recurse.c_str())),
            .hapFlags = testCmd.isPreinstalledApp ? 1 : 0,
            .uid = testCmd.uid
        };

        if (testCmd.runTime > 0) {
            printf("=== Running with timeout: %d seconds ===\n", testCmd.runTime);
            std::thread t([&forceTest, hapFileInfo]() {
                ResultInfo resultInfo;
                int r = forceTest.SetFileConForce(hapFileInfo, 1, resultInfo);
                printf("Thread finished with result: %d, total: %u, current: %u\n",
                    r, resultInfo.totalCount, resultInfo.currentCount);
            });

            sleep(testCmd.runTime);
            printf("=== Timeout reached, stopping task... ===\n");
            res = forceTest.StopSetFileCon(hapFileInfo, static_cast<StopReason>(testCmd.stopReason), "STOP");
            printf("Stop result: %d\n", res);

            if (t.joinable()) {
                t.join();
            }
        } else {
            ResultInfo resultInfo;
            res = forceTest.SetFileConForce(hapFileInfo, 1, resultInfo);
            std::cout << GetErrStr(res) << " total: " << resultInfo.totalCount <<
            " current: " << resultInfo.currentCount << std::endl;
        }
    } else if (testCmd.stop) {
        HapFileInfo hapFileInfo = {
            .pathNameOrig = testCmd.multiPath,
            .apl = testCmd.apl,
            .packageName = testCmd.name,
            .flags = static_cast<unsigned int>(atoi(testCmd.recurse.c_str())),
            .hapFlags = testCmd.isPreinstalledApp ? 1 : 0,
            .uid = testCmd.uid
        };
        res = forceTest.StopSetFileCon(hapFileInfo, static_cast<StopReason>(testCmd.stopReason), "STOP");
        std::cout << "Stop result: " << GetErrStr(res) << std::endl;
    } else if (!testCmd.domain) {
        HapFileInfo hapFileInfo = {
            .pathNameOrig = testCmd.multiPath,
            .apl = testCmd.apl,
            .packageName = testCmd.name,
            .flags = static_cast<unsigned int>(atoi(testCmd.recurse.c_str())),
            .hapFlags = testCmd.isPreinstalledApp ? 1 : 0,
            .uid = testCmd.uid
        };
        res = test.HapFileRestorecon(hapFileInfo);
        std::cout << GetErrStr(res) << std::endl;
    } else {
        HapDomainInfo hapDomainInfo {
            .apl = testCmd.apl,
            .packageName = testCmd.name,
            .extensionType = testCmd.extension,
            .hapFlags = testCmd.isPreinstalledApp ? 1 : 0,
            .uid = testCmd.uid
        };
        res = test.HapDomainSetcontext(hapDomainInfo);
        std::cout << GetErrStr(res) << std::endl;
        sleep(WAIT_TIME_5S);
    }
    exit(0);
}
