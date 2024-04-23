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
#include <memory>
#include <ostream>
#include <string>
#ifdef TIME_DISPLAY
#include <sys/time.h>
#endif
#include <unistd.h>
#include <sys/socket.h>
#include <selinux/selinux.h>

#include "selinux_error.h"
#include "selinux_parameter.h"
#include "param_checker.h"

using namespace Selinux;

#ifdef TIME_DISPLAY
const static long USEC_PER_SEC = 1000000L;
#endif

struct testInput {
    std::string paraName;
    char cmd = '\0';
};

static void TestLoadList()
{
    ParamContextsList *buff = nullptr;
#ifdef TIME_DISPLAY
    struct timeval start, end, diff;
    gettimeofday(&start, nullptr);
#endif
    buff = GetParamList();
    if (buff == nullptr) {
        std::cout << "buff empty" << std::endl;
        return;
    }
#ifdef TIME_DISPLAY
    gettimeofday(&end, nullptr);
    timersub(&end, &start, &diff);
    int runtime_us = diff.tv_sec * USEC_PER_SEC + diff.tv_usec;
    std::cout << "GetParamList time use: " << runtime_us << std::endl;
#endif

    ParamContextsList *head = buff;
    while (buff != nullptr) {
        if (security_check_context(buff->info.paraContext) < 0) {
            std::cout << "failed check context: " << buff->info.paraContext << " " << strlen(buff->info.paraContext)
                      << std::endl;
            buff = buff->next;
            continue;
        }
        std::cout << "param: " << buff->info.paraName << ", contexts: " << buff->info.paraContext
                  << ", index: " << buff->info.index << std::endl;
        buff = buff->next;
    }
#ifdef TIME_DISPLAY
    gettimeofday(&start, nullptr);
#endif
    DestroyParamList(&head);
#ifdef TIME_DISPLAY
    gettimeofday(&end, nullptr);
    timersub(&end, &start, &diff);
    runtime_us = diff.tv_sec * USEC_PER_SEC + diff.tv_usec;
    std::cout << "DestroyParamList time use: " << runtime_us << std::endl;
#endif
}

static void TestGetContext(std::string &paraName)
{
#ifdef TIME_DISPLAY
    struct timeval start, end, diff;
    gettimeofday(&start, nullptr);
#endif
    const char *context = GetParamLabel(paraName.c_str());
    int index = GetParamLabelIndex(paraName.c_str());
    std::cout << "paraName: " << paraName << "context: " << context << " index: " << index << std::endl;
#ifdef TIME_DISPLAY
    gettimeofday(&end, nullptr);
    timersub(&end, &start, &diff);
    int runtime_us = diff.tv_sec * USEC_PER_SEC + diff.tv_usec;
    std::cout << "time use: " << runtime_us << std::endl;
#endif
    std::cout << "para " << paraName.c_str() << "'s context is " << context << std::endl;
}

static void TestReadPara(std::string &paraName)
{
#ifdef TIME_DISPLAY
    struct timeval start, end, diff;
    gettimeofday(&start, nullptr);
#endif
    const char *contexts = GetParamLabel(paraName.c_str());
    std::string path = "/dev/__parameters__/" + std::string(contexts);
    if (access(path.c_str(), F_OK) != 0) {
        std::cout << "read param: " << paraName << " fail" << std::endl;
    } else {
        std::cout << "read param: " << paraName << " succ" << std::endl;
    }
#ifdef TIME_DISPLAY
    gettimeofday(&end, nullptr);
    timersub(&end, &start, &diff);
    int runtime_us = diff.tv_sec * USEC_PER_SEC + diff.tv_usec;
    std::cout << "time use: " << runtime_us << std::endl;
#endif
}

static void TestSetPara(std::string &paraName, SrcInfo *info)
{
#ifdef TIME_DISPLAY
    struct timeval start, end, diff;
    gettimeofday(&start, nullptr);
#endif
    std::cout << GetErrStr(SetParamCheck(paraName.c_str(), GetParamLabel(paraName.c_str()), info)) << std::endl;
#ifdef TIME_DISPLAY
    gettimeofday(&end, nullptr);
    timersub(&end, &start, &diff);
    int runtime_us = diff.tv_sec * USEC_PER_SEC + diff.tv_usec;
    std::cout << "time use: " << runtime_us << std::endl;
#endif
}

static void PrintUsage()
{
    std::cout << "Options:" << std::endl;
    std::cout << " -h (--help)           show the help information.      [eg: param_check -h]" << std::endl;
    std::cout << " -g (--getContext)     get context for paraName.       [eg: param_check -g]" << std::endl;
    std::cout << " -r (--read)           read para perm.                 [eg: param_check -r]" << std::endl;
    std::cout << " -w (--write)          write para perm.                [eg: param_check -w]" << std::endl;
    std::cout << " -l (--list)           load para list.                 [eg: param_check -l]" << std::endl;
    std::cout << " -n (--paraName)       paraName.                       [eg: param_check -r|-w|-g -n para_name]"
              << std::endl;
    std::cout << "" << std::endl;
    std::cout << "Usage:" << std::endl;
    std::cout << ">>>>>>> choice 1: continuous input parameters" << std::endl;
    std::cout << "step 1:" << std::endl;
    std::cout << "param_check -r|-w|-g|-l" << std::endl;
    std::cout << "step 2:" << std::endl;
    std::cout << "input param name and press 'enter' to continue, or ctrl+C to end process" << std::endl;
    std::cout << "" << std::endl;
    std::cout << ">>>>>>> choice 2: single input parameter" << std::endl;
    std::cout << "param_check -r|-w|-g -n para_name" << std::endl;
    std::cout << "" << std::endl;
}

static void SetOptions(int argc, char *argv[], const option *options, testInput &input)
{
    int index = 0;
    const char *optStr = "hgrwln:";
    int para = 0;
    while ((para = getopt_long(argc, argv, optStr, options, &index)) != -1) {
        switch (para) {
            case 'h': {
                PrintUsage();
                exit(0);
            }
            case 'n': {
                input.paraName = optarg;
                break;
            }
            case 'g': {
                input.cmd = 'g';
                break;
            }
            case 'r': {
                input.cmd = 'r';
                break;
            }
            case 'w': {
                input.cmd = 'w';
                break;
            }
            case 'l': {
                TestLoadList();
                exit(0);
            }
            default:
                std::cout << "Try 'param_check -h' for more information." << std::endl;
                exit(-1);
        }
    }
}

static void TestWriteParameters(testInput &testCmd)
{
    int fd[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, fd) < 0) {
        perror("socketpair");
        exit(EXIT_FAILURE);
    }

    SrcInfo info;
    info.uc.pid = getpid();
    info.uc.uid = getuid();
    info.uc.gid = getgid();
    info.sockFd = fd[0];
    if (!testCmd.paraName.empty()) {
        TestSetPara(testCmd.paraName, &info);
        close(fd[0]);
        close(fd[1]);
        exit(0);
    }
    std::string paraName;
    while (std::cin >> paraName) {
        TestSetPara(paraName, &info);
    }
    close(fd[0]);
    close(fd[1]);
    exit(0);
}

static void Test(testInput &testCmd)
{
    std::string paraName;
    switch (testCmd.cmd) {
        case 'g': {
            if (!testCmd.paraName.empty()) {
                TestGetContext(testCmd.paraName);
                exit(0);
            }
            while (std::cin >> paraName) {
                TestGetContext(paraName);
            }
            exit(0);
        }
        case 'r': {
            if (!testCmd.paraName.empty()) {
                TestReadPara(testCmd.paraName);
                exit(0);
            }
            while (std::cin >> paraName) {
                TestReadPara(paraName);
            }
            exit(0);
        }
        case 'w': {
            TestWriteParameters(testCmd);
            break;
        }
        default:
            PrintUsage();
            exit(-1);
    }
}

int main(int argc, char *argv[])
{
    struct option options[] = {
        {"help", no_argument, nullptr, 'h'}, {"paraName", required_argument, nullptr, 'n'},
        {"read", no_argument, nullptr, 'r'}, {"write", no_argument, nullptr, 'w'},
        {"list", no_argument, nullptr, 'l'}, {"getContext", no_argument, nullptr, 'g'},
        {nullptr, no_argument, nullptr, 0},
    };

    if (argc == 1) {
        PrintUsage();
        exit(0);
    }
    InitParamSelinux(0);
    testInput testCmd;
    SetOptions(argc, argv, options, testCmd);
    Test(testCmd);
    exit(0);
}
