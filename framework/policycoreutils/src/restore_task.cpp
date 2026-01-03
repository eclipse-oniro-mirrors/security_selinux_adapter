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

#include "restore_task.h"
#include "seharmony_hisysevent_adapter.h"

#include <include/fts.h>
#include <pthread.h>
#include <cstring>
#include <cerrno>
#include "selinux_error.h"
#include "selinux_log.h"
#include "selinux/context.h"
#include "selinux/selinux.h"
#include "src/callbacks.h"

namespace Selinux {

static const char *APPDAT_CONTEXT = "u:object_r:appdat:s0";

// /system/lib
// /systen/lib64/a
static bool IsPrefix(const std::string &parent, const std::string &child)
{
    if (parent.empty() || child.empty()) {
        return false;
    }
    if (parent == child) {
        return true;
    }
    size_t parentLen = parent.length();
    if (child.length() <= parentLen) {
        return false;
    }
    if (child.compare(0, parentLen, parent) != 0) {
        return false;
    }
    if (child[parentLen] == '/') {
        return true;
    }
    return false;
}

PathCheckResult CheckCurrenPath(const std::string &path, const std::string &resumeFromPath, bool &skipping)
{
    int cmp = resumeFromPath.compare(path);
    // Alphabetically larger path
    if (cmp < 0) {
        skipping = false;
        return TO_RESTORE;
    } else { // equal or larger
        // to travse the path
        if (IsPrefix(path, resumeFromPath)) {
            return SKIP_THIS;
        } else {
            return SKIP_SUB;
        }
    }
}

RestoreTask::RestoreTask(std::string bundleName, uint32_t uid)
{
    info.bundleName = bundleName;
    info.uid = uid;
}

bool RestoreTask::TryToStop(StopReason stopReason, bool shouldSave)
{
    std::lock_guard<std::mutex> lock(stopLock_);
    stopRequested_ = true;
    // cannot change from delete to save
    if (!shouldSave_) {
        return false;
    }
    stopReason_ = stopReason;
    shouldSave_ = shouldSave;
    return true;
}

void RestoreTask::SetInterrupted()
{
    isInterrupted_ = true;
}

bool RestoreTask::IsInterrupted()
{
    return isInterrupted_;
}

StopReason RestoreTask::GetStopReason()
{
    std::lock_guard<std::mutex> lock(stopLock_);
    return stopReason_;
}

bool RestoreTask::GetShouldSave()
{
    std::lock_guard<std::mutex> lock(stopLock_);
    return shouldSave_;
}

bool RestoreTask::IsStopping()
{
    std::lock_guard<std::mutex> lock(stopLock_);
    return stopRequested_;
}

int CompareFtsEnt(const FTSENT * const *a, const FTSENT * const *b)
{
    return strcmp((*a)->fts_name, (*b)->fts_name);
}

int InheritExternInfo(const char *oldSecontext, const char *newSecontext, char **finalContext)
{
    if (finalContext == nullptr) {
        return -SELINUX_PTR_NULL;
    }
    *finalContext = nullptr;

    context_t cona = context_new(oldSecontext);
    context_t conb = context_new(newSecontext);
    int ret = -SELINUX_PTR_NULL;

    if (cona != nullptr && conb != nullptr) {
        const char *oldType = context_type_get(cona);
        const char *newType = context_type_get(conb);

        if (oldType != nullptr && newType != nullptr && strcmp(oldType, newType) == 0) {
            ret = SELINUX_SUCC;
        } else if (context_user_set(conb, context_user_get(cona)) != 0) {
            ret = -SELINUX_SET_CONTEXT_USER_ERROR;
        } else if (context_role_set(conb, context_role_get(cona)) != 0) {
            ret = -SELINUX_SET_CONTEXT_ROLE_ERROR;
        } else if (context_range_get(cona) && context_range_set(conb, context_range_get(cona)) != 0) {
            ret = -SELINUX_SET_CONTEXT_RANGE_ERROR;
        } else if (context_str(conb) != nullptr) {
            *finalContext = strdup(context_str(conb));
            ret = (*finalContext != nullptr) ? SELINUX_SUCC : -SELINUX_PTR_NULL;
        }
    }

    if (cona) {
        context_free(cona);
    }
    if (conb) {
        context_free(conb);
    }
    return ret;
}

static int InnerRestoreconSb(const char *path, const char *newSecontext)
{
    char *oldSecontext = nullptr;
    if (lgetfilecon(path, &oldSecontext) < 0) {
        selinux_log(SELINUX_ERROR, "Get current secontext failed on: %s, errno: %s\n",
            AnonymizePath(path).c_str(), strerror(errno));
        return -SELINUX_GET_CONTEXT_ERROR;
    }

    char *updatedContext = nullptr;
    int res = InheritExternInfo(oldSecontext, newSecontext, &updatedContext);
    if (res != SELINUX_SUCC) {
        selinux_log(SELINUX_ERROR, "InheritExternInfo failed on: %s, error: %d\n",
            AnonymizePath(path).c_str(), res);
        freecon(oldSecontext);
        return res;
    }

    if (updatedContext == nullptr) {
        freecon(oldSecontext);
        return SELINUX_SUCC;
    }

    int ret = SELINUX_SUCC;
    if (lsetfilecon(path, updatedContext) < 0) {
        selinux_log(SELINUX_ERROR, "Set context failed on: %s, ctx: %s, errno: %s\n",
            AnonymizePath(path).c_str(), updatedContext, strerror(errno));
        ret = -SELINUX_SET_CONTEXT_ERROR;
    }

    free(updatedContext);
    freecon(oldSecontext);
    return ret;
}


int RestoreTask::RestoreTraversal(const std::string &path)
{
    std::lock_guard<std::mutex> infoLock(this->infoMutex);
    if (info.paths.find(path) == info.paths.end()) {
        return -SELINUX_ARG_INVALID;
    }
    auto pathInfo = info.paths[path];
    if (pathInfo->done) {
        return SELINUX_SUCC;
    }

    uint32_t successCount = 0;
    uint32_t failureCount = 0;
    int ret = this->RestoreTraversal(pathInfo, successCount, failureCount);
    // summarize the task
    this->successCount += successCount;
    this->failureCount += failureCount;
    return ret;
}

int RestoreTask::RestoreTraversal(
    std::shared_ptr<PathInfo> pathInfo, uint32_t& successCount, uint32_t& failureCount)
{
    std::string lastPath = "";
    bool skipping = !pathInfo->finished.empty();
    char *paths[2] = {const_cast<char*>(pathInfo->target.c_str()), nullptr};
    FTS *fts = fts_open(paths, FTS_PHYSICAL | FTS_NOCHDIR, CompareFtsEnt);
    if (fts == nullptr) {
        selinux_log(SELINUX_ERROR, "fts_open failed on %s, errno: %s\n",
            AnonymizePath(paths[0]).c_str(), strerror(errno));
        return -SELINUX_FTS_OPEN_ERROR;
    }
    FTSENT *ftsent = nullptr;
    int ret = SELINUX_SUCC;
    while ((ftsent = fts_read(fts)) != nullptr) {
        if (this->IsStopping()) {
            this->SetInterrupted();
            ret = -SELINUX_RESTORECON_TASK_STOPPED;
            break;
        }

        switch (ftsent->fts_info) {
            case FTS_DC:
                ret = -SELINUX_FTS_ELOOP;
                break;
            case FTS_DP:
                continue;
            case FTS_DNR:
            case FTS_ERR:
            case FTS_NS:
                fts_set(fts, ftsent, FTS_SKIP);
                ++failureCount;
                continue;
            case FTS_D:
            default:
                if (skipping) {
                    PathCheckResult checkRet = CheckCurrenPath(ftsent->fts_path, pathInfo->finished, skipping);
                    if (checkRet == SKIP_SUB) {
                        if (ftsent->fts_info == FTS_D) {
                            fts_set(fts, ftsent, FTS_SKIP);
                        }
                        continue;
                    } else if (checkRet == SKIP_THIS) {
                        continue;
                    }
                }
                if (InnerRestoreconSb(ftsent->fts_path, APPDAT_CONTEXT) == SELINUX_SUCC) {
                    ++successCount;
                    lastPath = ftsent->fts_path;
                } else {
                    ++failureCount;
                }
        }
    }
    fts_close(fts);
    if (successCount > 0 && !lastPath.empty()) {
        pathInfo->finished = lastPath;
    }
    pathInfo->count += successCount;
    if (!this->IsInterrupted()) {
        pathInfo->done = true;
    }
    return ret;
}

void RestoreTask::GetProgress(uint32_t& totalCount, std::vector<std::string>& currentPath)
{
    std::lock_guard<std::mutex> infoLock(this->infoMutex);
    for (const auto& kv : this->info.paths) {
        totalCount += kv.second->count;
        if (!kv.second->finished.empty()) {
            currentPath.push_back(kv.second->finished);
        }
    }
}
}
