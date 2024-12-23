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
static const std::string EXTRA_PREFIX = "extra=";
static const std::string EXTENSION_PREFIX = "extension=";
static const std::string DEBUGGABLE = "debuggable";
static const std::string DLPSANDBOX = "dlp_sandbox";
static const std::string INPUT_ISOLATE = "input_isolate";
static const char *DEFAULT_CONTEXT = "u:object_r:unlabeled:s0";
static const int CONTEXTS_LENGTH_MIN = 20; // sizeof("apl=x domain= type=")
static const int CONTEXTS_LENGTH_MAX = 1024;
static const uint32_t UID_BASE = 200000;
static const char *NORMAL_HAP_TYPE = "normal_hap";
static const char *DEBUG_HAP_TYPE = "debug_hap";
static const char *NORMAL_HAP_USER = "o";
static const int CATEGORY_SEG0_OFFSET = 0;
static const int CATEGORY_SEG1_OFFSET = 256;
static const int CATEGORY_SEG2_OFFSET = 512;
static const int CATEGORY_SEG3_OFFSET = 768;
static const int CATEGORY_SEG4_OFFSET = 1024;
static const int CATEGORY_MASK = 0xff;
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

static struct SehapInfo DecodeString(const std::string &line, bool &isValid)
{
    std::stringstream input(line);
    std::string tmp;
    struct SehapInfo contextBuff;
    bool aplVisit = false;
    bool nameVisit = false;
    bool domainVisit = false;
    bool typeVisit = false;
    bool debuggableVisit = false;
    bool extraVisit = false;
    bool extensionVisit = false;

    while (input >> tmp) {
        size_t pos;
        if (!aplVisit && (pos = tmp.find(APL_PREFIX)) != tmp.npos) {
            contextBuff.apl = tmp.substr(pos + APL_PREFIX.size());
            aplVisit = true;
        } else if (!nameVisit && (pos = tmp.find(NAME_PREFIX)) != tmp.npos) {
            contextBuff.name = tmp.substr(pos + NAME_PREFIX.size());
            nameVisit = true;
        } else if (!domainVisit && (pos = tmp.find(DOMAIN_PREFIX)) != tmp.npos) {
            contextBuff.domain = tmp.substr(pos + DOMAIN_PREFIX.size());
            domainVisit = true;
        } else if (!typeVisit && (pos = tmp.find(TYPE_PREFIX)) != tmp.npos) {
            contextBuff.type = tmp.substr(pos + TYPE_PREFIX.size());
            typeVisit = true;
        } else if (!debuggableVisit && (pos = tmp.find(DEBUGGABLE_PREFIX)) != tmp.npos) {
            std::string debuggable = tmp.substr(pos + DEBUGGABLE_PREFIX.size());
            contextBuff.debuggable = !strcmp(debuggable.c_str(), "true");
            debuggableVisit = true;
        } else if (!extensionVisit && (pos = tmp.find(EXTENSION_PREFIX)) != tmp.npos) {
            contextBuff.extension = tmp.substr(pos + EXTENSION_PREFIX.size());
            extensionVisit = true;
        } else if (!extraVisit && (pos = tmp.find(EXTRA_PREFIX)) != tmp.npos) {
            std::string extra = tmp.substr(pos + EXTRA_PREFIX.size());
            if (extra == DLPSANDBOX) {
                contextBuff.extra |= SELINUX_HAP_DLP;
            } else if (extra == INPUT_ISOLATE) {
                contextBuff.extra |= SELINUX_HAP_INPUT_ISOLATE;
            } else {
                selinux_log(SELINUX_ERROR, "invalid extra %s\n", extra.c_str());
                isValid = false;
                break;
            }
            extraVisit = true;
        }
    }
    return contextBuff;
}

static bool CheckPath(const std::string &path)
{
    std::regex pathPrefix1("^/data/app/el[1-5]/[0-9]+/(base|database|sharefiles)/.*");
    std::regex pathPrefix2("^/data/accounts/account_0/appdata/.*");
    std::regex pathPrefix3("^/data/service/el[1-5]/[0-9]+/backup/bundles/.*");
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

static std::string GetHapContextKey(const struct SehapInfo *hapInfo)
{
    std::string keyPara;

    if (hapInfo->extra & SELINUX_HAP_INPUT_ISOLATE) {
        if (hapInfo->debuggable) {
            keyPara = hapInfo->apl + "." + DEBUGGABLE + "." + INPUT_ISOLATE;
        } else {
            keyPara = hapInfo->apl + "." + INPUT_ISOLATE;
        }
    } else if (hapInfo->extra & SELINUX_HAP_DLP) {
        keyPara = hapInfo->apl + "." + DLPSANDBOX;
    } else if (hapInfo->debuggable) {
        keyPara = hapInfo->apl + "." + DEBUGGABLE;
    } else if (!hapInfo->name.empty()) {
        keyPara = hapInfo->apl + "." + hapInfo->name;
    } else {
        keyPara = hapInfo->apl;
    }

    return keyPara;
}

static bool HapContextsInsert(const SehapInfo &tmpInfo, int lineNum)
{
    std::string keyPara = GetHapContextKey(&tmpInfo);
    if (keyPara.empty()) {
        selinux_log(SELINUX_ERROR, "hap_contexts read fail in line %d\n", lineNum);
        return false;
    }

    selinux_log(SELINUX_INFO, "insert keyPara %s\n", keyPara.c_str());
    bool ret = g_sehapContextsTrie->Insert(keyPara, tmpInfo.domain, tmpInfo.type, tmpInfo.extension);
    if (!ret) {
        selinux_log(SELINUX_ERROR, "sehap contexts trie insert fail %s\n", keyPara.c_str());
        return false;
    }
    if (tmpInfo.name.empty() && !tmpInfo.debuggable && !tmpInfo.extra) {
        keyPara = tmpInfo.apl + ".";
        ret = g_sehapContextsTrie->Insert(keyPara, tmpInfo.domain, tmpInfo.type, tmpInfo.extension);
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
            bool isValid = true;
            struct SehapInfo tmpInfo = DecodeString(line, isValid);
            if (!isValid) {
                continue;
            }
            if (!HapContextsInsert(tmpInfo, lineNum)) {
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

static bool CheckValidCmp(char *oldSecontext, char *newSecontext)
{
    if (oldSecontext == nullptr || newSecontext == nullptr) {
        if (oldSecontext != nullptr) {
            freecon(oldSecontext);
        }
        if (newSecontext != nullptr) {
            freecon(newSecontext);
        }
        return false;
    }
    return true;
}

static void FreeContext(char *oldTypeContext, context_t con)
{
    if (oldTypeContext != nullptr) {
        freecon(oldTypeContext);
    }
    if (con != nullptr) {
        context_free(con);
    }
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
        return -SELINUX_PATH_INVALID;
    }

    if (!CheckPath(realPath)) {
        return -SELINUX_PATH_INVALID;
    }

    char *newSecontext = nullptr;
    char *oldSecontext = nullptr;
    int res = GetSecontext(hapFileInfo, pathNameOrig, &newSecontext, &oldSecontext);
    if (res < 0) {
        return res;
    }
    if (!CheckValidCmp(oldSecontext, newSecontext)) {
        selinux_log(SELINUX_ERROR, "oldSecontext or newSecontext is null");
        return -SELINUX_PTR_NULL;
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
                (void)fts_close(fts);
                free(paths[0]);
                return -SELINUX_FTS_ELOOP;
            case FTS_DP:
                continue;
            case FTS_DNR:
                fts_set(fts, ftsent, FTS_SKIP);
                continue;
            case FTS_ERR:
                fts_set(fts, ftsent, FTS_SKIP);
                continue;
            case FTS_NS:
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

    if (!CheckValidCmp(oldSecontext, newSecontext)) {
        selinux_log(SELINUX_ERROR, "oldSecontext or newSecontext is null");
        return -SELINUX_PTR_NULL;
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
    HapContextParams params = {apl, packageName, hapFlags};
    int res = HapContextsLookup(params, false, con);
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
        selinux_log(SELINUX_ERROR, "context: %s, %s\n", secontext, GetErrStr(SELINUX_CHECK_CONTEXT_ERROR));
        freecon(*secontextPtr);
        *secontextPtr = nullptr;
        context_free(con);
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
        selinux_log(SELINUX_INFO, "Selinux not enabled");
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

    HapContextParams params = {hapDomainInfo.apl, hapDomainInfo.packageName,
        hapDomainInfo.hapFlags, hapDomainInfo.extensionType};
    int res = HapContextsLookup(params, con, hapDomainInfo.uid);
    if (res < 0) {
        FreeContext(oldTypeContext, con);
        return res;
    }

    const char *typeContext = context_str(con);
    if (typeContext == nullptr) {
        FreeContext(oldTypeContext, con);
        return -SELINUX_PTR_NULL;
    }

    selinux_log(SELINUX_INFO, "Hap type for %s is changing from %s to %s\n",
        hapDomainInfo.packageName.c_str(), oldTypeContext, typeContext);

    if (security_check_context(typeContext) < 0) {
        selinux_log(SELINUX_ERROR, "context: %s, %s\n", typeContext, GetErrStr(SELINUX_CHECK_CONTEXT_ERROR));
        FreeContext(oldTypeContext, con);
        return -SELINUX_CHECK_CONTEXT_ERROR;
    }

    if (strcmp(typeContext, oldTypeContext)) {
        if (setcon(typeContext) < 0) {
            FreeContext(oldTypeContext, con);
            return -SELINUX_SET_CONTEXT_ERROR;
        }
    }
    selinux_log(SELINUX_INFO, "Hap setcon finish for %s\n", hapDomainInfo.packageName.c_str());

    FreeContext(oldTypeContext, con);
    return SELINUX_SUCC;
}

int HapContext::HapContextsLookup(const HapContextParams &params, bool isDomain, context_t con)
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
    if (params.hapFlags & SELINUX_HAP_INPUT_ISOLATE) {
        if (params.hapFlags & SELINUX_HAP_DEBUGGABLE) {
            keyPara = params.apl + "." + DEBUGGABLE + "." + INPUT_ISOLATE;
            selinux_log(SELINUX_INFO, "input_isolate debug hap, keyPara: %s", keyPara.c_str());
        } else {
            keyPara = params.apl + "." + INPUT_ISOLATE;
            selinux_log(SELINUX_INFO, "input_isolate isolate hap, keyPara: %s", keyPara.c_str());
        }
    } else if (params.hapFlags & SELINUX_HAP_DLP) {
        keyPara = params.apl + "." + DLPSANDBOX;
        selinux_log(SELINUX_INFO, "dlpsandbox hap, keyPara: %s", keyPara.c_str());
    } else if (params.hapFlags & SELINUX_HAP_RESTORECON_PREINSTALLED_APP) {
        keyPara = params.apl + "." + params.packageName;
        selinux_log(SELINUX_INFO, "preinstall hap, keyPara: %s", keyPara.c_str());
    } else if (params.hapFlags & SELINUX_HAP_DEBUGGABLE) {
        keyPara = params.apl + "." + DEBUGGABLE;
        selinux_log(SELINUX_INFO, "debuggable hap, keyPara: %s", keyPara.c_str());
    } else {
        selinux_log(SELINUX_INFO, "not a preinstall hap, apl: %s", params.apl.c_str());
        keyPara = params.apl;
    }

    std::string type = g_sehapContextsTrie->Search(keyPara, isDomain, params.extension);
    if (!type.empty()) {
        return TypeSet(type, con);
    }
    return -SELINUX_KEY_NOT_FOUND;
}

int HapContext::HapContextsLookup(const HapContextParams &params, context_t con, uint32_t uid)
{
    int res = HapContextsLookup(params, true, con);
    if (res < 0) {
        return res;
    }
    res = UserAndMCSRangeSet(uid, con);
    if (res < 0) {
        return res;
    }
    return SELINUX_SUCC;
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

int HapContext::UserAndMCSRangeSet(uint32_t uid, context_t con)
{
    if (uid < UID_BASE) {
        return SELINUX_SUCC;
    }
    const char *currentType = context_type_get(con);
    if (currentType == nullptr) {
        selinux_log(SELINUX_ERROR, "Failed to get context type.");
        return -SELINUX_SET_CONTEXT_USER_ERROR;
    }
    std::string typeStr = std::string(currentType);
    if ((typeStr != NORMAL_HAP_TYPE) && (typeStr != DEBUG_HAP_TYPE)) {
        return SELINUX_SUCC;
    }
    int ret = context_user_set(con, NORMAL_HAP_USER);
    if (ret != 0) {
        selinux_log(SELINUX_ERROR, "Failed to set context user %s\n", NORMAL_HAP_USER);
        return -SELINUX_SET_CONTEXT_USER_ERROR;
    }
    uint32_t userId = uid / UID_BASE;
    uint32_t appId = uid % UID_BASE;
    std::string level = "s0:x" + std::to_string(CATEGORY_SEG0_OFFSET + (appId & CATEGORY_MASK)) +
                ",x" + std::to_string(CATEGORY_SEG1_OFFSET + ((appId >> 8) & CATEGORY_MASK)) +
                ",x" + std::to_string(CATEGORY_SEG2_OFFSET + ((appId >> 16) & CATEGORY_MASK)) +
                ",x" + std::to_string(CATEGORY_SEG3_OFFSET + (userId & CATEGORY_MASK)) +
                ",x" + std::to_string(CATEGORY_SEG4_OFFSET + ((userId >> 8) & CATEGORY_MASK));
    ret = context_range_set(con, level.c_str());
    if (ret != 0) {
        selinux_log(SELINUX_ERROR, "Failed to set context range %s\n", level.c_str());
        return -SELINUX_SET_CONTEXT_RANGE_ERROR;
    }
    return SELINUX_SUCC;
}
