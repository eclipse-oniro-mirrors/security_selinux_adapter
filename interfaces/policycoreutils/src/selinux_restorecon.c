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

#include <unistd.h>
#include <libgen.h>
#include <include/fts.h>
#include <linux/limits.h>
#include "src/callbacks.h"
#include "src/label_internal.h"
#include "policycoreutils.h"
#include "selinux_error.h"
#include "selinux_log.h"
#include "selinux/restorecon.h"

static pthread_once_t g_fcOnce = PTHREAD_ONCE_INIT;
static struct selabel_handle *g_fcHandle = NULL;
static const char SYSTEM_FILE_CONTEXTS[] = "/system/etc/selinux/targeted/contexts/file_contexts";
static const char VENDOR_FILE_CONTEXTS[] = "/vendor/etc/selinux/targeted/contexts/file_contexts";
#define MAX_OPT_NUM 3 // system + vendor + digest

typedef struct selinux_opt SelinuxOptions;

static void SetFileContextsHandle(void)
{
    if (g_fcHandle != NULL) {
        selinux_log(SELINUX_ERROR, "File_contexts handle already set\n");
        return;
    }

    SelinuxOptions options[MAX_OPT_NUM] = {0};

    unsigned int index = 0;
    if (access(SYSTEM_FILE_CONTEXTS, R_OK) == 0) {
        SelinuxOptions systemOption = {SELABEL_OPT_PATH, SYSTEM_FILE_CONTEXTS};
        options[index++] = systemOption;
    }
    if (access(VENDOR_FILE_CONTEXTS, R_OK) == 0) {
        SelinuxOptions vendorOption = {SELABEL_OPT_PATH, VENDOR_FILE_CONTEXTS};
        options[index++] = vendorOption;
    }

    // default option of selabel_open
    SelinuxOptions digestOption = {SELABEL_OPT_DIGEST, (char *)1};
    options[index++] = digestOption;

    g_fcHandle = selabel_open(SELABEL_CTX_FILE, options, index);
    if (g_fcHandle == NULL) {
        selinux_log(SELINUX_ERROR, "File_contexts handle open fail\n");
        return;
    }

    selinux_restorecon_set_sehandle(g_fcHandle);
}

int RestoreconCommon(const char *path, unsigned int flag, unsigned int nthreads)
{
    __selinux_once(g_fcOnce, SetFileContextsHandle);
    if (g_fcHandle == NULL) {
        selinux_log(SELINUX_ERROR, "File_contexts handle is null\n");
        return -1;
    }
    return selinux_restorecon_parallel(path, flag, nthreads);
}

static void SelinuxSetCallback(void)
{
    SetSelinuxHilogLevel(SELINUX_HILOG_ERROR);
    union selinux_callback cb;
    cb.func_log = SelinuxHilog;
    selinux_set_callback(SELINUX_CB_LOG, cb);
}

static int RestoreconSb(const char *path, char *newSecontext)
{
    char *oldSecontext = NULL;
    if (lgetfilecon(path, &oldSecontext) < 0) {
        selinux_log(SELINUX_ERROR, "Get current secontext failed on: %s, errno: %s\n", path, strerror(errno));
        return -SELINUX_GET_CONTEXT_ERROR;
    }

    if (strcmp(oldSecontext, newSecontext)) {
        if (lsetfilecon(path, newSecontext) < 0) {
            selinux_log(SELINUX_ERROR, "Set selinux context failed on: %s, errno: %s\n", path, strerror(errno));
            freecon(oldSecontext);
            return -SELINUX_SET_CONTEXT_ERROR;
        }
    }
    freecon(oldSecontext);
    return SELINUX_SUCC;
}

static int RestoreconRecurseFromParentDir(const char *realPath, char *newSecontext)
{
    char *paths[2] = {NULL, NULL};
    paths[0] = strdup(realPath);
    if (paths[0] == NULL) {
        return -SELINUX_PTR_NULL;
    }

    FTS *fts = fts_open(paths, FTS_PHYSICAL | FTS_NOCHDIR, NULL);
    if (fts == NULL) {
        selinux_log(SELINUX_ERROR, "file_open failed on %s: %s\n", paths[0], strerror(errno));
        free(paths[0]);
        return -SELINUX_FTS_OPEN_ERROR;
    }

    FTSENT *ftsent = NULL;
    int error = 0;
    while ((ftsent = fts_read(fts)) != NULL) {
        switch (ftsent->fts_info) {
            case FTS_DC:
                selinux_log(SELINUX_ERROR, "Fts ELOOP on %s\n", ftsent->fts_path);
                (void)fts_close(fts);
                free(paths[0]);
                return -SELINUX_FTS_ELOOP;
            case FTS_DP:
                continue;
            case FTS_DNR:
                selinux_log(SELINUX_ERROR, "Read error on %s, errno: %s\n", ftsent->fts_path, strerror(errno));
                error = -SELINUX_UNKNOWN_ERROR;
                fts_set(fts, ftsent, FTS_SKIP);
                continue;
            case FTS_ERR:
                selinux_log(SELINUX_ERROR, "Error on %s, errno: %s\n", ftsent->fts_path, strerror(errno));
                error = -SELINUX_UNKNOWN_ERROR;
                fts_set(fts, ftsent, FTS_SKIP);
                continue;
            case FTS_NS:
                selinux_log(SELINUX_ERROR, "stat error on %s, errno: %s\n", ftsent->fts_path, strerror(errno));
                error = -SELINUX_UNKNOWN_ERROR;
                fts_set(fts, ftsent, FTS_SKIP);
                continue;
            case FTS_D:
            default:
                if (RestoreconSb(ftsent->fts_path, newSecontext) != 0) {
                    error = -SELINUX_RESTORECON_ERROR;
                }
                break;
        }
    }
    (void)fts_close(fts);
    free(paths[0]);
    return error;
}

int Restorecon(const char *path)
{
    return RestoreconCommon(path, SELINUX_RESTORECON_REALPATH, 1);
}

int RestoreconRecurse(const char *path)
{
    return RestoreconCommon(path, SELINUX_RESTORECON_REALPATH | SELINUX_RESTORECON_RECURSE, 1);
}

int RestoreconRecurseParallel(const char *path, unsigned int nthreads)
{
    return RestoreconCommon(path, SELINUX_RESTORECON_REALPATH | SELINUX_RESTORECON_RECURSE, nthreads);
}

int RestoreconRecurseForce(const char *path)
{
    return RestoreconCommon(path,
        SELINUX_RESTORECON_REALPATH | SELINUX_RESTORECON_RECURSE | SELINUX_RESTORECON_IGNORE_DIGEST, 1);
}

/* Restorecon the path recursively, using parent directory's label */
int RestoreconFromParentDir(const char *path)
{
    static pthread_once_t fcOnce = PTHREAD_ONCE_INIT;
    __selinux_once(fcOnce, SelinuxSetCallback);

    if (path == NULL) {
        return -SELINUX_ARG_INVALID;
    }

    // check selinux state, less than 1 is disabled
    if (is_selinux_enabled() < 1) {
        selinux_log(SELINUX_ERROR, "Selinux not enabled\n");
        return -SELINUX_STAT_INVAILD;
    }

    char realPath[PATH_MAX + 1] = { 0x00 };
    char parent[PATH_MAX + 1] = { 0x00 };
    if (realpath(path, realPath) == NULL || realpath(path, parent) == NULL) {
        selinux_log(SELINUX_ERROR, "Get real path failed: %s, errno: %s\n", path, strerror(errno));
        return -SELINUX_PATH_INVAILD;
    }

    char *parentPath = dirname(parent);
    char *parentSecontext = NULL;
    if (lgetfilecon(parentPath, &parentSecontext) < 0) {
        selinux_log(SELINUX_ERROR, "Get parent dir secontext failed: %s, errno: %s\n", parentPath, strerror(errno));
        return -SELINUX_GET_CONTEXT_ERROR;
    }
    int ret = RestoreconRecurseFromParentDir(realPath, parentSecontext);
    freecon(parentSecontext);
    return ret;
}