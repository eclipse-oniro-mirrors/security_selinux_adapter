/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef SEHARMONY_HISYSEVENT_ADAPTER_H
#define SEHARMONY_HISYSEVENT_ADAPTER_H

#include <string>
#include <cstdint>
#include "hap_restorecon.h"

namespace Selinux {

std::string AnonymizePath(const std::string& path);
std::vector<std::string> AnonymizePathList(const std::vector<std::string>& pathList);

struct RestoreFinishInfo {
    bool changeContext = false;
    bool isSkipAlias = false;
    int32_t stopReason = 0;
    std::vector<std::string> currentPath;
    int32_t successCount = 0;
    int32_t errorCount = 0;
    int32_t totalCount = 0;
    std::string stopDesc = "";
};

void ReportSeharmonyRestoreErr(const std::string& bundleName, int32_t uid,
    int32_t errCode, const std::string& errMsg);
void ReportSeharmonyHapFileRestoreStart(const HapFileInfo& hapFileInfo, const uint32_t remainingNum);
void ReportSeharmonyHapFileRestoreFinish(const HapFileInfo& hapFileInfo, const RestoreFinishInfo& finishInfo);

} // namespace Selinux

#endif // SEHARMONY_HISYSEVENT_ADAPTER_H
