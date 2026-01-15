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

#ifndef HAPFILE_RESTORE_TASK_H
#define HAPFILE_RESTORE_TASK_H

#include <iosfwd>
#include <string>
#include <unordered_map>
#include <vector>
#include <mutex>
#include <atomic>
#include <selinux/context.h>
#include "seharmony_cjson.h"

#include "hap_restorecon.h"

namespace Selinux {
enum PathCheckResult {
    TO_RESTORE,
    SKIP_THIS,
    SKIP_SUB
};

PathCheckResult CheckCurrenPath(const std::string &path, const std::string &resumeFromPath, bool &skipping);
int InheritExternInfo(const char *oldSecontext, const char *newSecontext, char **finalContext);

class RestoreTask {
public:
    std::mutex infoMutex;
    RefreshInfo info;
    uint32_t successCount = 0;
    uint32_t failureCount = 0;
public:
    RestoreTask(std::string bundleName, uint32_t uid);
    bool TryToStop(StopReason stopReason, const std::string& stopDesc, bool shouldSave);

    void SetInterrupted();

    bool IsInterrupted();

    StopReason GetStopReason(std::string& stopDesc);

    bool GetShouldSave();

    bool IsStopping();

    int RestoreTraversal(const std::string &path);
    int RestoreTraversal(std::shared_ptr<PathInfo> pathInfo, uint32_t& successCount, uint32_t& failureCount);
    void GetProgress(uint32_t& totalCount, std::vector<std::string>& currentPath);
    void GetRestorePaths(std::vector<std::string>& paths);
private:
    bool isInterrupted_ {false};

    // should hold lock before change
    std::mutex stopLock_;
    bool stopRequested_ {false};
    StopReason stopReason_ {StopReason::NONE};
    std::string stopDesc_ = "";
    bool shouldSave_ {true};
};
}
#endif // HAPFILE_RESTORE_TASK_H
