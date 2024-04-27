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

#include "hap_restorecon.h"

#include <cctype>
#include <cerrno>
#include <climits>
#include <clocale>
#include <cstdlib>
#include <fstream>
#include <istream>
#include <regex>
#include <sstream>
#include <streambuf>
#include <string>
#include <sys/stat.h>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <vector>

#include <include/fts.h>
#include <pthread.h>
#include "selinux/context.h"
#include "selinux/selinux.h"

#include "src/callbacks.h"
#include "selinux_error.h"
#include "selinux_log.h"

using namespace Selinux;

namespace {
#ifdef SELINUX_TEST
static const std::string SEHAP_CONTEXTS_FILE = "/data/test/sehap_contexts";
#else
static const std::string SEHAP_CONTEXTS_FILE = "/system/etc/selinux/targeted/contexts/sehap_contexts";
#endif // STARTUP_INIT_TEST

static const std::string APL_PREFIX = "apl=";
static const std::string NAME_PREFIX = "name=";
static const std::string DOMAIN_PREFIX = "domain=";
static const std::string TYPE_PREFIX = "type=";
static const std::string DEBUGGABLE_PREFIX = "debuggable=";
static const std::string DEBUGGABLE = "debuggable";
static const char *DEFAULT_CONTEXT = "u:object_r:unlabeled:s0";
static const int CONTEXTS_LENGTH_MIN = 20; // sizeof("apl=x domain= type=")
static const int CONTEXTS_LENGTH_MAX = 1024;
static pthread_once_t g_fcOnce = PTHREAD_ONCE_INIT;
static std::unique_ptr<SehapContextsTrie> g_sehapContextsTrie = nullptr;
std::mutex g_loadContextsLock;
} // namespace

static void SelinuxSetCallback()
{
    SetSelinuxHilogLevel(SELINUX_HILOG_ERROR);
    union selinux_callback cb;
    cb.func_log = SelinuxHilog;
    selinux_set_callback(SELINUX_CB_LOG, cb);
}

static bool CouldSkip(const std::string &line)
{
    if (line.size() <= CONTEXTS_LENGTH_MIN || line.size() > CONTEXTS_LENGTH_MAX) {
        return true;
    }
    int i = 0;
    while (isspace(line[i])) {
        i++;
    }
    if (line[i] == '#') {
        return true;
    }
    if (line.find(APL_PREFIX) == line.npos) {
        return true;
    }
    return false;
}

static struct SehapInfo DecodeString(std::string &line)
{
    std::stringstream input(line);
    std::string tmp;
    struct SehapInfo contextBuff;
    bool aplVisit = false;
    bool nameVisit = false;
    bool domainVisit = false;
    bool typeVisit = false;
    bool debuggableVisit = false;

    while (input >> tmp) {
        if (!aplVisit && (tmp.find(APL_PREFIX) != tmp.npos)) {
            contextBuff.apl = tmp.substr(tmp.find(APL_PREFIX) + APL_PREFIX.size());
            aplVisit = true;
        } else if (!nameVisit && (tmp.find(NAME_PREFIX) != tmp.npos)) {
            contextBuff.name = tmp.substr(tmp.find(NAME_PREFIX) + NAME_PREFIX.size());
            nameVisit = true;
        } else if (!domainVisit && (tmp.find(DOMAIN_PREFIX) != tmp.npos)) {
            contextBuff.domain = tmp.substr(tmp.find(DOMAIN_PREFIX) + DOMAIN_PREFIX.size());
            domainVisit = true;
        } else if (!typeVisit && (tmp.find(TYPE_PREFIX) != tmp.npos)) {
            contextBuff.type = tmp.substr(tmp.find(TYPE_PREFIX) + TYPE_PREFIX.size());
            typeVisit = true;
        } else if (!debuggableVisit && (tmp.find(DEBUGGABLE_PREFIX) != tmp.npos)) {
            std::string debuggable = tmp.substr(tmp.find(DEBUGGABLE_PREFIX) + DEBUGGABLE_PREFIX.size());
            contextBuff.debuggable = !strcmp(debuggable.c_str(), "true");
        }
    }

    return contextBuff;
}

static bool CheckPath(const std::string &path)
{
    std::regex pathPrefix1("^/data/app/el[1-4]/[0-9]+/(base|database)/.*");
    std::regex pathPrefix2("^/data/accounts/account_0/appdata/.*");
    std::regex pathPrefix3("^/data/service/el[1-4]/[0-9]+/backup/bundles/.*");
    if (std::regex_match(path, pathPrefix1) || std::regex_match(path, pathPrefix2) ||
        std::regex_match(path, pathPrefix3)) {
        return true;
    }
    return false;
}

static bool CheckApl(const std::string &apl)
{
    if (apl == "system_core" || apl == "system_basic" || apl == "normal") {
        return true;
    }
    return false;
}

static std::string GetHapContextKey(struct SehapInfo *hapInfo)
{
    std::string keyPara;

    if (hapInfo->debuggable) {
        keyPara = hapInfo->apl + "." + DEBUGGABLE;
    } else if (!hapInfo->name.empty()) {
        keyPara = hapInfo->apl + "." + hapInfo->name;
    } else {
        keyPara = hapInfo->apl;
    }

    return keyPara;
}

static bool HapContextsInsert(std::string line, int lineNum)
{
    struct SehapInfo tmpInfo = DecodeString(line);
    std::string keyPara = GetHapContextKey(&tmpInfo);
    if (keyPara.empty()) {
        selinux_log(SELINUX_ERROR, "hap_contexts read fail in line %d\n", lineNum);
        return false;
    }

    selinux_log(SELINUX_INFO, "insert keyPara %s\n", keyPara.c_str());
    bool ret = g_sehapContextsTrie->Insert(keyPara, tmpInfo.domain, tmpInfo.type);
    if (!ret) {
        selinux_log(SELINUX_ERROR, "sehap contexts trie insert fail %s\n", keyPara.c_str());
        return false;
    }

    if (tmpInfo.name.empty() && !tmpInfo.debuggable) {
        keyPara = tmpInfo.apl + ".";
        ret = g_sehapContextsTrie->Insert(keyPara, tmpInfo.domain, tmpInfo.type);
    }

    return ret;
}

static bool HapContextsLoad()
{
    // load sehap_contexts file
    std::ifstream contextsFile(SEHAP_CONTEXTS_FILE);
    if (contextsFile) {
        g_sehapContextsTrie = std::make_unique<SehapContextsTrie>();
        if (g_sehapContextsTrie == nullptr) {
            selinux_log(SELINUX_ERROR, "malloc g_sehapContextsTrie fail");
            return false;
        }
        int lineNum = 0;
        std::string line;
        while (getline(contextsFile, line)) {
            lineNum++;
            if (CouldSkip(line)) {
                continue;
            }
            if (!HapContextsInsert(line, lineNum)) {
                g_sehapContextsTrie->Clear();
                g_sehapContextsTrie = nullptr;
                return false;
            }
        }
    } else {
        selinux_log(SELINUX_ERROR, "Load hap_contexts fail, no such file: %s\n", SEHAP_CONTEXTS_FILE.c_str());
        return false;
    }
    selinux_log(SELINUX_INFO, "Load hap_contexts succes: %s\n", SEHAP_CONTEXTS_FILE.c_str());
    contextsFile.close();
    return true;
}

HapContext::HapContext()
{
    __selinux_once(g_fcOnce, SelinuxSetCallback);
}

HapContext::~HapContext() {}

int HapContext::HapFileRestorecon(HapFileInfo& hapFileInfo)
{
    if (hapFileInfo.apl.empty() || hapFileInfo.pathNameOrig.empty() || !CheckApl(hapFileInfo.apl)) {
        return -SELINUX_ARG_INVALID;
    }
    bool failFlag = false;
    for (auto pathname : hapFileInfo.pathNameOrig) {
        int res = HapFileRestorecon(pathname.c_str(), hapFileInfo);
        if (res != SELINUX_SUCC) {
            failFlag = true;
            selinux_log(SELINUX_ERROR, "HapFileRestorecon fail for path: %s, errorNo: %d", pathname.c_str(), res);
        }
    }
    return failFlag ? -SELINUX_RESTORECON_ERROR : SELINUX_SUCC;
}

int HapContext::HapFileRestorecon(const std::string &pathNameOrig, HapFileInfo& hapFileInfo)
{
    if (hapFileInfo.apl.empty() || pathNameOrig.empty() || !CheckApl(hapFileInfo.apl)) {
        return -SELINUX_ARG_INVALID;
    }
    if (is_selinux_enabled() < 1) {
        selinux_log(SELINUX_INFO, "Selinux not enbaled");
        return SELINUX_SUCC;
    }

    char realPath[PATH_MAX];
    if (realpath(pathNameOrig.c_str(), realPath) == nullptr) {
        return -SELINUX_PATH_INVAILD;
    }

    if (!CheckPath(realPath)) {
        return -SELINUX_PATH_INVAILD;
    }

    char *newSecontext = nullptr;
    char *oldSecontext = nullptr;
    int res = GetSecontext(hapFileInfo, pathNameOrig, &newSecontext, &oldSecontext);
    if (res < 0) {
        return res;
    }
    if (strcmp(oldSecontext, newSecontext) == 0) {
        freecon(newSecontext);
        freecon(oldSecontext);
        return SELINUX_SUCC;
    }
    freecon(newSecontext);
    freecon(oldSecontext);
    // determine whether needs recurse
    bool recurse = (hapFileInfo.flags & SELINUX_HAP_RESTORECON_RECURSE) ? true : false;
    if (!recurse) {
        int ret = RestoreconSb(realPath, hapFileInfo);
        if (ret < 0) {
            selinux_log(SELINUX_ERROR, "RestoreconSb failed");
        }
        return ret;
    }
    return HapFileRecurseRestorecon(realPath, hapFileInfo);
}

int HapContext::HapFileRecurseRestorecon(const std::string &realPath, HapFileInfo& hapFileInfo)
{
    char *paths[2] = {nullptr, nullptr};
    paths[0] = strdup(realPath.c_str());
    if (paths[0] == nullptr) {
        return -SELINUX_PTR_NULL;
    }

    int ftsFlags = FTS_PHYSICAL | FTS_NOCHDIR;
    FTS *fts = fts_open(paths, ftsFlags, nullptr);
    if (fts == nullptr) {
        selinux_log(SELINUX_ERROR, "%s on %s: %s\n", GetErrStr(SELINUX_FTS_OPEN_ERROR), paths[0], strerror(errno));
        free(paths[0]);
        return -SELINUX_FTS_OPEN_ERROR;
    }

    FTSENT *ftsent = nullptr;
    int error = 0;
    while ((ftsent = fts_read(fts)) != nullptr) {
        switch (ftsent->fts_info) {
            case FTS_DC:
                selinux_log(SELINUX_ERROR, "%s on %s\n", GetErrStr(SELINUX_FTS_ELOOP), ftsent->fts_path);
                (void)fts_close(fts);
                free(paths[0]);
                return -SELINUX_FTS_ELOOP;
            case FTS_DP:
                continue;
            case FTS_DNR:
                selinux_log(SELINUX_ERROR, "Read error on %s, errorno: %s\n", ftsent->fts_path, strerror(errno));
                fts_set(fts, ftsent, FTS_SKIP);
                continue;
            case FTS_ERR:
                selinux_log(SELINUX_ERROR, "Error on %s, errorno: %s\n", ftsent->fts_path, strerror(errno));
                fts_set(fts, ftsent, FTS_SKIP);
                continue;
            case FTS_NS:
                selinux_log(SELINUX_ERROR, "stat error on %s, errorno: %s\n", ftsent->fts_path, strerror(errno));
                fts_set(fts, ftsent, FTS_SKIP);
                continue;
            case FTS_D:
            default:
                if (RestoreconSb(ftsent->fts_path, hapFileInfo) != 0) {
                    error = -SELINUX_RESTORECON_ERROR;
                }
                break;
        }
    }
    (void)fts_close(fts);
    free(paths[0]);
    return error;
}

int HapContext::RestoreconSb(const std::string &pathNameOrig, HapFileInfo& hapFileInfo)
{
    char *newSecontext = nullptr;
    char *oldSecontext = nullptr;
    int res = GetSecontext(hapFileInfo, pathNameOrig, &newSecontext, &oldSecontext);
    if (res < 0) {
        return res;
    }

    if (strcmp(oldSecontext, newSecontext)) {
        if (lsetfilecon(pathNameOrig.c_str(), newSecontext) < 0) {
            freecon(newSecontext);
            freecon(oldSecontext);
            return -SELINUX_SET_CONTEXT_ERROR;
        }
    }
    freecon(newSecontext);
    freecon(oldSecontext);
    return SELINUX_SUCC;
}

int HapContext::GetSecontext(HapFileInfo& hapFileInfo, const std::string &pathNameOrig,
    char **newSecontext, char **oldSecontext)
{
    if (lgetfilecon(pathNameOrig.c_str(), oldSecontext) < 0) {
        return -SELINUX_GET_CONTEXT_ERROR;
    }

    int res = HapLabelLookup(hapFileInfo.apl, hapFileInfo.packageName, newSecontext, hapFileInfo.hapFlags);
    if (res < 0) {
        freecon(*oldSecontext);
        return res;
    }
    return SELINUX_SUCC;
}

int HapContext::HapLabelLookup(const std::string &apl, const std::string &packageName,
    char **secontextPtr, unsigned int hapFlags)
{
    *secontextPtr = strdup(DEFAULT_CONTEXT);
    if (*secontextPtr == nullptr) {
        return -SELINUX_PTR_NULL;
    }
    const char *secontext = *secontextPtr;
    context_t con = context_new(secontext);
    if (con == nullptr) {
        freecon(*secontextPtr);
        *secontextPtr = nullptr;
        return -SELINUX_PTR_NULL;
    }
    int res = HapContextsLookup(false, apl, packageName, con, hapFlags);
    if (res < 0) {
        freecon(*secontextPtr);
        *secontextPtr = nullptr;
        context_free(con);
        return res;
    }
    secontext = context_str(con);
    if (secontext == nullptr) {
        freecon(*secontextPtr);
        *secontextPtr = nullptr;
        context_free(con);
        return -SELINUX_PTR_NULL;
    }
    // if new contexts is same as old
    if (!strcmp(secontext, *secontextPtr)) {
        freecon(*secontextPtr);
        *secontextPtr = nullptr;
        context_free(con);
        return SELINUX_SUCC;
    }
    // check whether the context is valid
    if (security_check_context(secontext) < 0) {
        freecon(*secontextPtr);
        *secontextPtr = nullptr;
        context_free(con);
        selinux_log(SELINUX_ERROR, "context: %s, %s\n", secontext, GetErrStr(SELINUX_CHECK_CONTEXT_ERROR));
        return -SELINUX_CHECK_CONTEXT_ERROR;
    }
    freecon(*secontextPtr);
    *secontextPtr = strdup(secontext);
    if (*secontextPtr == nullptr) {
        context_free(con);
        return -SELINUX_PTR_NULL;
    }
    context_free(con);
    return SELINUX_SUCC;
}

int HapContext::HapDomainSetcontext(HapDomainInfo& hapDomainInfo)
{
    if (hapDomainInfo.apl.empty() || !CheckApl(hapDomainInfo.apl)) {
        return -SELINUX_ARG_INVALID;
    }

    if (is_selinux_enabled() < 1) {
        selinux_log(SELINUX_INFO, "Selinux not enbaled");
        return SELINUX_SUCC;
    }

    char *oldTypeContext = nullptr;
    if (getcon(&oldTypeContext)) {
        return -SELINUX_GET_CONTEXT_ERROR;
    }

    context_t con = nullptr;
    con = context_new(oldTypeContext);
    if (con == nullptr) {
        return -SELINUX_PTR_NULL;
    }

    int res = HapContextsLookup(true, hapDomainInfo.apl, hapDomainInfo.packageName, con, hapDomainInfo.hapFlags);
    if (res < 0) {
        freecon(oldTypeContext);
        context_free(con);
        return res;
    }

    const char *typeContext = context_str(con);
    if (typeContext == nullptr) {
        freecon(oldTypeContext);
        context_free(con);
        return -SELINUX_PTR_NULL;
    }

    selinux_log(SELINUX_INFO, "Hap type for %s is changing from %s to %s\n",
        hapDomainInfo.packageName.c_str(), oldTypeContext, typeContext);

    if (security_check_context(typeContext) < 0) {
        freecon(oldTypeContext);
        context_free(con);
        selinux_log(SELINUX_ERROR, "context: %s, %s\n", typeContext, GetErrStr(SELINUX_CHECK_CONTEXT_ERROR));
        return -SELINUX_CHECK_CONTEXT_ERROR;
    }

    if (strcmp(typeContext, oldTypeContext)) {
        if (setcon(typeContext) < 0) {
            freecon(oldTypeContext);
            context_free(con);
            return -SELINUX_SET_CONTEXT_ERROR;
        }
    }
    selinux_log(SELINUX_INFO, "Hap setcon finish for %s\n", hapDomainInfo.packageName.c_str());

    freecon(oldTypeContext);
    context_free(con);
    return SELINUX_SUCC;
}

int HapContext::HapContextsLookup(bool isDomain, const std::string &apl, const std::string &packageName,
    context_t con, unsigned int hapFlags)
{
    {
        std::lock_guard<std::mutex> lock(g_loadContextsLock);
        if (g_sehapContextsTrie == nullptr) {
            if (!HapContextsLoad()) {
                return -SELINUX_CONTEXTS_FILE_LOAD_ERROR;
            }
        }
    }

    std::string keyPara;
    if (hapFlags & SELINUX_HAP_RESTORECON_PREINSTALLED_APP) {
        keyPara = apl + "." + packageName;
        selinux_log(SELINUX_INFO, "preinstall hap, keyPara: %s", keyPara.c_str());
    } else if (hapFlags & SELINUX_HAP_DEBUGGABLE) {
        keyPara = apl + "." + DEBUGGABLE;
        selinux_log(SELINUX_INFO, "debuggable hap, keyPara: %s", keyPara.c_str());
    } else {
        selinux_log(SELINUX_INFO, "not a preinstall hap, apl: %s", apl.c_str());
        keyPara = apl;
    }

    std::string type = g_sehapContextsTrie->Search(keyPara, isDomain);
    if (!type.empty()) {
        return TypeSet(type, con);
    }
    return -SELINUX_KEY_NOT_FOUND;
}

int HapContext::TypeSet(const std::string &type, context_t con)
{
    if (type.empty()) {
        selinux_log(SELINUX_ERROR, "type is empty in contexts file");
        return -SELINUX_ARG_INVALID;
    }
    if (context_type_set(con, type.c_str())) {
        selinux_log(SELINUX_ERROR, "%s %s\n", GetErrStr(SELINUX_SET_CONTEXT_TYPE_ERROR), type.c_str());
        return -SELINUX_SET_CONTEXT_TYPE_ERROR;
    }
    return SELINUX_SUCC;
}
