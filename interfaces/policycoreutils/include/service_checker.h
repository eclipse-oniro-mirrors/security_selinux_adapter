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

#ifndef SERVICE_CHECKER_H
#define SERVICE_CHECKER_H

#include <iosfwd>
#include <string>
#include <sys/types.h>

struct ServiceInfo {
    std::string serviceName = "";
    std::string serviceContext = "";
};

class ServiceChecker {
public:
    ServiceChecker(bool isHdf);

    int ListServiceCheck(const pid_t callingPid);

    int GetServiceCheck(const pid_t callingPid, const std::string &serviceName);

    int GetRemoteServiceCheck(const pid_t callingPid, const std::string &remoteServiceName);

    int AddServiceCheck(const pid_t callingPid, const std::string &serviceName);

    static ServiceChecker& GetInstance();

protected:
private:
    int CheckPerm(const pid_t callingPid, const std::string &serviceName, std::string action);
    int GetServiceContext(const std::string &serviceName, std::string &context);

    bool isHdf_ = false;
    std::string serviceClass_ = "";
};

#endif // SERVICE_CHECKER_H
