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

#include "hap_restorecon.h"
#include "selinux_error.h"

using namespace Selinux;

static const int ALARM_TIME_S = 5;
struct testInput {
    std::string name = "";
    std::string apl = "";
    std::vector<std::string> multiPath;
    bool domain = false;
    std::string recurse = "1";
    bool isPreinstalledApp = false;
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
    printf("\n");
}

static void SetOptions(int argc, char *argv[], const option *options, testInput &input)
{
    int index = 0;
    const char *optStr = "hda:p:n:r:m:i";
    int para = 0;
    while ((para = getopt_long(argc, argv, optStr, options, &index)) != -1) {
        switch (para) {
            case 'h': {
                PrintUsage();
                exit(0);
            }
            case 'a': {
                input.apl = optarg;
                break;
            }
            case 'd': {
                input.domain = true;
                break;
            }
            case 'p': {
                input.multiPath.emplace_back(optarg);
                break;
            }
            case 'm': {
                std::stringstream str(optarg);
                std::string tmp;
                while (str >> tmp) {
                    input.multiPath.emplace_back(tmp);
                }
                break;
            }
            case 'n': {
                input.name = optarg;
                break;
            }
            case 'r': {
                input.recurse = optarg;
                break;
            }
            case 'i': {
                input.isPreinstalledApp = true;
                break;
            }
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
        {nullptr, no_argument, nullptr, 0},
    };

    if (argc == 1) {
        PrintUsage();
        exit(0);
    }

    testInput testCmd;
    SetOptions(argc, argv, options, testCmd);
    HapContext test;
    int res = 0;
    if (!testCmd.domain) {
        HapFileInfo hapFileInfo = {
            .pathNameOrig = testCmd.multiPath,
            .apl = testCmd.apl,
            .packageName = testCmd.name,
            .flags = atoi(testCmd.recurse.c_str()),
            .hapFlags = testCmd.isPreinstalledApp ? 1 : 0
        };
        res = test.HapFileRestorecon(hapFileInfo);
        std::cout << GetErrStr(res) << std::endl;
    } else {
        HapDomainInfo hapDomainInfo {
            .apl = testCmd.apl,
            .packageName = testCmd.name,
            .hapFlags = testCmd.isPreinstalledApp ? 1 : 0
        };
        res = test.HapDomainSetcontext(hapDomainInfo);
        std::cout << GetErrStr(res) << std::endl;
        sleep(ALARM_TIME_S);
    }
    exit(0);
}
