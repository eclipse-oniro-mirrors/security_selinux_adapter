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

#include "seharmony_hisysevent_adapter.h"
#include "selinux/context.h"
#include "selinux/selinux.h"
#include "src/callbacks.h"
#include "selinux_error.h"
#include "selinux_log.h"

#ifdef HAS_HISYSEVENT_PART
#include "hisysevent.h"
#endif // HAS_HISYSEVENT_PART

namespace Selinux {
namespace {
#ifdef HAS_HISYSEVENT_PART
using namespace OHOS::HiviewDFX;
static constexpr char SELINUX_DOMAIN[] = "SEHARMONY";
#endif // HAS_HISYSEVENT_PART
static constexpr int ANONYMIZATION_INTERVAL = 2;
}

std::string AnonymizePath(const std::string& path)
{
    std::string res = path;
    int count = 0;
    for (char &c : res) {
        if (c == '/') {
            count = 0;
        } else {
            count++;
            if (count % ANONYMIZATION_INTERVAL == 0) {
                c = '*';
            }
        }
    }
    return res;
}

std::vector<std::string> AnonymizePathList(const std::vector<std::string>& pathList)
{
    std::vector<std::string> result;
    for (const std::string &path : pathList) {
        result.push_back(AnonymizePath(path));
    }
    return result;
}

void ReportSeharmonyRestoreErr(const std::string& bundleName, int32_t uid,
    int32_t errCode, const std::string& errMsg)
{
#ifdef HAS_HISYSEVENT_PART
    int ret = HiSysEventWrite(SELINUX_DOMAIN, "SEHM_RESTORE_ERR",
        HiSysEvent::EventType::FAULT,
        "BUNDLE_NAME", bundleName,
        "UID", uid,
        "ERROR_CODE", errCode,
        "ERROR_MSG", errMsg);
    if (ret != 0) {
        selinux_log(SELINUX_ERROR, "hisysevent write failed! ret %d. errCode %d", ret, errCode);
    }
#else // HAS_HISYSEVENT_PART
    (void)errCode;
    (void)errMsg;
#endif // HAS_HISYSEVENT_PART
}

void ReportSeharmonyHapFileRestoreStart(const HapFileInfo& hapFileInfo)
{
#ifdef HAS_HISYSEVENT_PART
    int ret = HiSysEventWrite(SELINUX_DOMAIN, "SEHM_HAPFILE_RESTORE_START",
        HiSysEvent::EventType::STATISTIC,
        "BUNDLE_NAME", hapFileInfo.packageName,
        "PATH_LIST", hapFileInfo.pathNameOrig,
        "UID", static_cast<int32_t>(hapFileInfo.uid),
        "APL", hapFileInfo.apl,
        "HAP_FLAGS", static_cast<int32_t>(hapFileInfo.hapFlags),
        "FLAGS", static_cast<int32_t>(hapFileInfo.flags));
    if (ret != 0) {
        selinux_log(SELINUX_ERROR, "hisysevent write failed! ret %d. packageName %s",
            ret, hapFileInfo.packageName.c_str());
    }
#else // HAS_HISYSEVENT_PART
    (void)hapFileInfo;
#endif // HAS_HISYSEVENT_PART
}

void ReportSeharmonyHapFileRestoreFinish(const HapFileInfo& hapFileInfo, const RestoreFinishInfo& finishInfo)
{
#ifdef HAS_HISYSEVENT_PART
    int ret = HiSysEventWrite(SELINUX_DOMAIN, "SEHM_HAPFILE_RESTORE_FINISH",
        HiSysEvent::EventType::STATISTIC,
        "BUNDLE_NAME", hapFileInfo.packageName,
        "PATH_LIST", hapFileInfo.pathNameOrig,
        "CHANGE_CONTEXT", finishInfo.changeContext,
        "IS_SKIP_ALIAS", finishInfo.isSkipAlias,
        "STOP_REASON", finishInfo.stopReason,
        "CURRENT_PATH", AnonymizePathList(finishInfo.currentPath),
        "COUNT", finishInfo.successCount,
        "ERROR_COUNT", finishInfo.errorCount,
        "TOTAL_COUNT", finishInfo.totalCount);
    if (ret != 0) {
        selinux_log(SELINUX_ERROR, "hisysevent write failed! ret %d. packageName %s",
            ret, hapFileInfo.packageName.c_str());
    }
#else // HAS_HISYSEVENT_PART
    (void)hapFileInfo;
    (void)finishInfo;
#endif // HAS_HISYSEVENT_PART
}

} // namespace Selinux
