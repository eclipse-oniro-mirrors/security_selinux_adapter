/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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
#include <atomic>
#include <mutex>
#include <memory>
#include <map>
#include <unistd.h>

#include <include/fts.h>
#include <pthread.h>
#include "selinux/context.h"
#include "selinux/selinux.h"

#include "src/callbacks.h"
#include "selinux_error.h"
#include "selinux_log.h"
#include "restore_task.h"
#include "seharmony_cjson.h"
#include "seharmony_hisysevent_adapter.h"


using namespace Selinux;

namespace {
#ifdef SELINUX_TEST
static const std::string SEHAP_CONTEXTS_FILE = "/data/test/sehap_contexts";
static const std::string PRODUCT_CONFIG_FILE = "/data/test/product_config";
#else
static const std::string SEHAP_CONTEXTS_FILE = "/system/etc/selinux/targeted/contexts/sehap_contexts";
static const std::string PRODUCT_CONFIG_FILE = "/version/etc/selinux/product_config";
#endif // STARTUP_INIT_TEST

static const std::string APL_PREFIX = "apl=";
static const std::string NAME_PREFIX = "name=";
static const std::string DOMAIN_PREFIX = "domain=";
static const std::string TYPE_PREFIX = "type=";
static const std::string DEBUGGABLE_PREFIX = "debuggable=";
static const std::string EXTRA_PREFIX = "extra=";
static const std::string EXTENSION_PREFIX = "extension=";
static const std::string LEVEL_PREFIX = "levelFrom=";
static const std::string USER_PREFIX = "user=";
static const std::string DEBUGGABLE = "debuggable";
static const std::string DLP_SANDBOX_READ_ONLY = "dlp_sandbox_read_only";
static const std::string DLPSANDBOX = "dlp_sandbox";
static const std::string INPUT_ISOLATE = "input_isolate";
static const std::string INPUT_ISOLATE_FULL = "input_isolate_full";
static const std::string CUSTOMSANDBOX = "custom_sandbox";
static const std::string ISOLATED_GPU = "isolated_gpu";
static const std::string ISOLATED_RENDER = "isolated_render";
static const char *ORIGINAL_TYPE = "normal_hap_data_file";
static const char *UPDATED_TYPE = "appdat";
static const char *DEFAULT_CONTEXT = "u:object_r:unlabeled:s0";
static const int CONTEXTS_LENGTH_MIN = 20; // sizeof("apl=x domain= type=")
static const int CONTEXTS_LENGTH_MAX = 1024;
#ifdef MCS_ENABLE
static const uint32_t UID_BASE = 200000;
static const uint32_t USER_BASE = 100;
static const int CATEGORY_SEG0_OFFSET = 0;
static const int CATEGORY_SEG1_OFFSET = 256;
static const int CATEGORY_SEG2_OFFSET = 512;
static const int CATEGORY_SEG3_OFFSET = 768;
static const int CATEGORY_SEG4_OFFSET = 1024;
static const int CATEGORY_MASK = 0xff;
static const int SHIFT_8 = 8;
static const int SHIFT_16 = 16;
static const std::string DEFAULT_LEVEL_PREFIX = "defaultLevelFrom=";
static const std::string DEFAULT_USER_PREFIX = "defaultUser=";
static const std::string DEFAULT_MCS_HAP_FILE_PREFIX = "mcsHapFileEnabled=";
static LevelFrom g_defaultLevelFrom = LEVELFROM_NONE;
static std::string g_defaultUser = "u";
static bool g_mcsHapFileEnabled = false;
#endif
static pthread_once_t g_fcOnce = PTHREAD_ONCE_INIT;
static std::unique_ptr<SehapContextsTrie> g_sehapContextsTrie = nullptr;
std::mutex g_loadContextsLock;
} // namespace

static void SelinuxSetCallback()
{
    SetSelinuxHilogLevel(SELINUX_HILOG_INFO);
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

#ifdef MCS_ENABLE
static LevelFrom GetLevelFrom(const std::string &level)
{
    LevelFrom levelFrom = LEVELFROM_NONE;
    if (level == "all") {
        levelFrom = LEVELFROM_ALL;
    } else if (level == "user") {
        levelFrom = LEVELFROM_USER;
    } else if (level == "app") {
        levelFrom = LEVELFROM_APP;
    } else {
        levelFrom = g_defaultLevelFrom;
    }

    return levelFrom;
}

static std::string DeleteNonLetter(std::string str)
{
    str.erase(std::remove_if(str.begin(), str.end(), [](char c) { return !std::isalpha(c); }), str.end());
    return str;
}

static void SetDefaultConfig()
{
    std::ifstream configFile(PRODUCT_CONFIG_FILE);
    if (!configFile) {
        selinux_log(SELINUX_ERROR, "Read %s failed, errno: %s\n", PRODUCT_CONFIG_FILE.c_str(), strerror(errno));
        return;
    }
    std::string line;
    bool levelVisited = false;
    bool userVisited = false;
    bool hapFileMcsVisited = false;
    while (getline(configFile, line) && !(levelVisited && userVisited && hapFileMcsVisited)) {
        size_t pos;
        if (!levelVisited) {
            pos = line.find(DEFAULT_LEVEL_PREFIX);
            if (pos == 0) {
                g_defaultLevelFrom = GetLevelFrom(DeleteNonLetter(line.substr(DEFAULT_LEVEL_PREFIX.size())));
                levelVisited = true;
                continue;
            }
        }
        if (!userVisited) {
            pos = line.find(DEFAULT_USER_PREFIX);
            if (pos == 0) {
                g_defaultUser = DeleteNonLetter(line.substr(DEFAULT_USER_PREFIX.size()));
                userVisited = true;
                continue;
            }
        }
        if (!hapFileMcsVisited) {
            pos = line.find(DEFAULT_MCS_HAP_FILE_PREFIX);
            if (pos == 0) {
                g_mcsHapFileEnabled =
                    !strcmp(DeleteNonLetter(line.substr(DEFAULT_MCS_HAP_FILE_PREFIX.size())).c_str(), "true");
                hapFileMcsVisited = true;
            }
        }
    }
    configFile.close();
}
#endif

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
#ifdef MCS_ENABLE
    bool levelVisit = false;
    bool userVisit = false;
    contextBuff.levelFrom = g_defaultLevelFrom;
    contextBuff.user = g_defaultUser;
#endif
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
#ifdef MCS_ENABLE
        } else if (!levelVisit && (pos = tmp.find(LEVEL_PREFIX)) != tmp.npos) {
            contextBuff.levelFrom = GetLevelFrom(tmp.substr(pos + LEVEL_PREFIX.size()));
            levelVisit = true;
        } else if (!userVisit && (pos = tmp.find(USER_PREFIX)) != tmp.npos) {
            contextBuff.user = tmp.substr(pos + USER_PREFIX.size());
            userVisit = true;
#endif
        } else if (!extraVisit && (pos = tmp.find(EXTRA_PREFIX)) != tmp.npos) {
            std::string extra = tmp.substr(pos + EXTRA_PREFIX.size());
            if (extra == ISOLATED_GPU) {
                contextBuff.extra |= SELINUX_HAP_ISOLATED_GPU;
            } else if (extra == ISOLATED_RENDER) {
                contextBuff.extra |= SELINUX_HAP_ISOLATED_RENDER;
            } else if (extra == INPUT_ISOLATE) {
                contextBuff.extra |= SELINUX_HAP_INPUT_ISOLATE;
            } else if (extra == CUSTOMSANDBOX) {
                contextBuff.extra |= SELINUX_HAP_CUSTOM_SANDBOX;
            } else if (extra == DLP_SANDBOX_READ_ONLY) {
                contextBuff.extra |= SELINUX_HAP_DLP_READ_ONLY;
            } else if (extra == DLPSANDBOX) {
                contextBuff.extra |= SELINUX_HAP_DLP_FULL_CONTROL;
            } else if (extra == INPUT_ISOLATE_FULL) {
                contextBuff.extra |= SELINUX_HAP_INPUT_ISOLATE_FULL;
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
    if (hapInfo->extra & SELINUX_HAP_ISOLATED_RENDER) {
        keyPara = hapInfo->apl + "." + ISOLATED_RENDER;
    } else if (hapInfo->extra & SELINUX_HAP_ISOLATED_GPU) {
        keyPara = hapInfo->apl + "." + ISOLATED_GPU;
    } else if (hapInfo->extra & SELINUX_HAP_INPUT_ISOLATE) {
        if (hapInfo->debuggable) {
            keyPara = hapInfo->apl + "." + DEBUGGABLE + "." + INPUT_ISOLATE;
        } else {
            keyPara = hapInfo->apl + "." + INPUT_ISOLATE;
        }
    } else if (hapInfo->extra & SELINUX_HAP_INPUT_ISOLATE_FULL) {
        if (hapInfo->debuggable) {
            keyPara = hapInfo->apl + "." + DEBUGGABLE + "." + INPUT_ISOLATE_FULL;
        } else {
            keyPara = hapInfo->apl + "." + INPUT_ISOLATE_FULL;
        }
    } else if (hapInfo->extra & SELINUX_HAP_DLP_READ_ONLY) {
        keyPara = hapInfo->apl + "." + DLP_SANDBOX_READ_ONLY;
    } else if (hapInfo->extra & SELINUX_HAP_DLP_FULL_CONTROL) {
        keyPara = hapInfo->apl + "." + DLPSANDBOX;
    } else if (hapInfo->extra & SELINUX_HAP_CUSTOM_SANDBOX) {
        if (hapInfo->debuggable) {
            keyPara = hapInfo->apl + "." + DEBUGGABLE + "." + CUSTOMSANDBOX + "." + hapInfo->name;
        } else {
            keyPara = hapInfo->apl + "." + CUSTOMSANDBOX + "." + hapInfo->name;
        }
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

    SehapInsertParamInfo tmpInsertInfo = {
#ifdef MCS_ENABLE
        tmpInfo.levelFrom,
        tmpInfo.user,
#endif
        tmpInfo.domain,
        tmpInfo.type,
        tmpInfo.extension
    };
    bool ret = g_sehapContextsTrie->Insert(keyPara, tmpInsertInfo);
    if (!ret) {
        selinux_log(SELINUX_ERROR, "sehap contexts trie insert fail %s\n", keyPara.c_str());
        return false;
    }
    if (tmpInfo.name.empty() && !tmpInfo.debuggable && !tmpInfo.extra) {
        keyPara = tmpInfo.apl + ".";
        ret = g_sehapContextsTrie->Insert(keyPara, tmpInsertInfo);
    }
    return ret;
}

static bool HapContextsLoad()
{
#ifdef MCS_ENABLE
    SetDefaultConfig();
#endif
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

static int IsSkipSetContext(const char *oldSecontext, const char *newSecontext, bool &skipSetCon,
    const std::string &pathNameOrig)
{
    context_t oldContext = context_new(oldSecontext);
    if (oldContext == nullptr) {
        selinux_log(SELINUX_ERROR, "Old context is null");
        return -SELINUX_PTR_NULL;
    }
    context_t newContext = context_new(newSecontext);
    if (newContext == nullptr) {
        context_free(oldContext);
        selinux_log(SELINUX_ERROR, "New context is null");
        return -SELINUX_PTR_NULL;
    }

    if (!strcmp(context_type_get(oldContext), ORIGINAL_TYPE) && !strcmp(context_type_get(newContext), UPDATED_TYPE)) {
        selinux_log(SELINUX_INFO, "Skip set the context of path: %s.\n", pathNameOrig.c_str());
        skipSetCon = true;
    }

    context_free(oldContext);
    context_free(newContext);

    return SELINUX_SUCC;
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

    char realPath[PATH_MAX + 1];
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

    bool skipSetCon = false;
    res = IsSkipSetContext(oldSecontext, newSecontext, skipSetCon, pathNameOrig);
    if ((res != SELINUX_SUCC) || skipSetCon) {
        freecon(newSecontext);
        freecon(oldSecontext);
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

    HapContextParams params = {hapFileInfo.apl, hapFileInfo.packageName, hapFileInfo.hapFlags};
    params.uid = hapFileInfo.uid;
    int res = HapLabelLookup(params, newSecontext);
    if (res < 0) {
        freecon(*oldSecontext);
        return res;
    }
    return SELINUX_SUCC;
}

int HapContext::HapLabelLookup(const HapContextParams &params, char **secontextPtr)
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
    int res = HapContextsLookup(params, con);
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
        FreeContext(oldTypeContext, con);
        return -SELINUX_PTR_NULL;
    }

    HapContextParams params = {hapDomainInfo.apl, hapDomainInfo.packageName,
        hapDomainInfo.hapFlags, hapDomainInfo.extensionType, true, hapDomainInfo.uid};
    int res = HapContextsLookup(params, con);
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

static std::string GetKeyParams(const HapContextParams &params)
{
    std::string keyPara;
    if (params.hapFlags & SELINUX_HAP_ISOLATED_GPU) {
        keyPara = params.apl + "." + ISOLATED_GPU;
    } else if (params.hapFlags & SELINUX_HAP_ISOLATED_RENDER) {
        keyPara = params.apl + "." + ISOLATED_RENDER;
    } else if (params.hapFlags & SELINUX_HAP_INPUT_ISOLATE) {
        if (params.hapFlags & SELINUX_HAP_DEBUGGABLE) {
            keyPara = params.apl + "." + DEBUGGABLE + "." + INPUT_ISOLATE;
        } else {
            keyPara = params.apl + "." + INPUT_ISOLATE;
        }
    } else if (params.hapFlags & SELINUX_HAP_INPUT_ISOLATE_FULL) {
        if (params.hapFlags & SELINUX_HAP_DEBUGGABLE) {
            keyPara = params.apl + "." + DEBUGGABLE + "." + INPUT_ISOLATE_FULL;
        } else {
            keyPara = params.apl + "." + INPUT_ISOLATE_FULL;
        }
    } else if (params.hapFlags & SELINUX_HAP_DLP_READ_ONLY) {
        keyPara = params.apl + "." + DLP_SANDBOX_READ_ONLY;
    } else if (params.hapFlags & SELINUX_HAP_DLP_FULL_CONTROL) {
        keyPara = params.apl + "." + DLPSANDBOX;
    } else if (params.hapFlags & SELINUX_HAP_CUSTOM_SANDBOX) {
        if (params.hapFlags & SELINUX_HAP_DEBUGGABLE) {
            keyPara = params.apl + "." + DEBUGGABLE + "." + CUSTOMSANDBOX + "." + params.packageName;
        } else {
            keyPara = params.apl + "." + CUSTOMSANDBOX + "." + params.packageName;
        }
    } else if (params.hapFlags & SELINUX_HAP_RESTORECON_PREINSTALLED_APP) {
        keyPara = params.apl + "." + params.packageName;
    } else if (params.hapFlags & SELINUX_HAP_DEBUGGABLE) {
        keyPara = params.apl + "." + DEBUGGABLE;
    } else {
        keyPara = params.apl;
    }
    return keyPara;
}

int HapContextLoadConfig()
{
    std::lock_guard<std::mutex> lock(g_loadContextsLock);
    if (g_sehapContextsTrie != nullptr) {
        return 0;
    }

    if (HapContextsLoad()) {
        return 0;
    }

    return -SELINUX_CONTEXTS_FILE_LOAD_ERROR;
}

int HapContext::HapContextsLookup(const HapContextParams &params, context_t con)
{
    int ret = HapContextLoadConfig();
    if (ret != 0) {
        selinux_log(SELINUX_ERROR, "read config error, ret=%d", ret);
        return ret;
    }

    std::string keyPara = GetKeyParams(params);
    SehapContextInfo contextInfo = g_sehapContextsTrie->Search(keyPara, params.isDomain, params.extension);
    if (contextInfo.context.empty()) {
        return -SELINUX_KEY_NOT_FOUND;
    }
    int res = TypeSet(contextInfo.context, con);
    if (res < 0) {
        return res;
    }
#ifdef MCS_ENABLE
    if (contextInfo.levelFrom != LEVELFROM_NONE && (params.isDomain || g_mcsHapFileEnabled)) {
        return UserAndMCSRangeSet(params.uid, con, contextInfo.levelFrom, contextInfo.user);
    }
#endif
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

HapFileRestoreContext& HapFileRestoreContext::GetInstance()
{
    static HapFileRestoreContext instance;
    return instance;
}

HapFileRestoreContext::HapFileRestoreContext() : HapContext()
{
    __selinux_once(g_fcOnce, SelinuxSetCallback);
}

HapFileRestoreContext::~HapFileRestoreContext() {}

bool HapFileRestoreContext::IsAppdatContext(const HapFileInfo& hapFileInfo)
{
    char *secontext = nullptr;
    HapContextParams params = {hapFileInfo.apl, hapFileInfo.packageName, hapFileInfo.hapFlags};
    params.uid = hapFileInfo.uid;
    bool isAppdat = false;
    
    if (HapLabelLookup(params, &secontext) == SELINUX_SUCC && secontext != nullptr) {
        context_t targetContext = context_new(secontext);
        if (targetContext == nullptr) {
            selinux_log(SELINUX_ERROR, "Create context is null");
            freecon(secontext);
            return isAppdat;
        }
        if (strcmp(context_type_get(targetContext), UPDATED_TYPE) == 0) {
            isAppdat = true;
        }
        context_free(targetContext);
        freecon(secontext);
    }
    return isAppdat;
}

int HapFileRestoreContext::SetFileConForce(const HapFileInfo& hapFileInfo, ResultInfo& resultInfo)
{
    selinux_log(SELINUX_INFO, "SetFileConForce start, bundleName=%s, uid = %u",
            hapFileInfo.packageName.c_str(), hapFileInfo.uid);
    if (!IsAppdatContext(hapFileInfo)) {
        selinux_log(SELINUX_INFO, "Skip SetFileConForce for non-appdat context, bundleName=%s",
            hapFileInfo.packageName.c_str());
        DeleteRefreshInfo(hapFileInfo.packageName, hapFileInfo.uid);
        return SELINUX_SUCC;
    }
    if (hapFileInfo.packageName.empty() || hapFileInfo.pathNameOrig.empty()) {
        selinux_log(SELINUX_ERROR, "Invalid args or context check failed for bundleName=%s",
            hapFileInfo.packageName.c_str());
        return -SELINUX_ARG_INVALID;
    }
    Selinux::ReportSeharmonyHapFileRestoreStart(hapFileInfo);
    std::shared_ptr<RestoreTask> task = nullptr;
    int ret = InitRestoreTask(task, hapFileInfo);
    if (ret == -SELINUX_NO_FOUND_PATHS) {
        return SELINUX_SUCC;
    } else if (ret != SELINUX_SUCC) {
        return ret;
    }

    std::vector<std::string> paths;
    task->GetRestorePaths(paths);
    for (const auto& origPath : paths) {
        if (task->IsStopping()) {
            task->SetInterrupted();
            ret = -SELINUX_RESTORECON_TASK_STOPPED;
            break;
        }
        ret = ProcessRestorePath(task, origPath, hapFileInfo);
        if (ret == -SELINUX_RESTORECON_TASK_STOPPED) {
            break;
        }
    }

    FinishRestoreTask(hapFileInfo, resultInfo);
    selinux_log(SELINUX_INFO, "SetFileConForce end, ret=%d, bundlename=%s, count=%u, totalcount=%u",
        ret, hapFileInfo.packageName.c_str(), resultInfo.currentCount, resultInfo.totalCount);
    return ret;
}

int HapFileRestoreContext::InitRestoreTask(std::shared_ptr<RestoreTask>& task, const HapFileInfo& hapFileInfo)
{
    std::lock_guard<std::mutex> lock(restoreTaskMutex_);
    if (restoreTask_ != nullptr) {
        selinux_log(SELINUX_ERROR, "Restorecon task already in progress for %s", restoreTask_->info.bundleName.c_str());
        return -SELINUX_RESTORECON_TASK_ALREADY_RUNNING;
    }
    task = std::make_shared<RestoreTask>(hapFileInfo.packageName, hapFileInfo.uid);
    // Load progress
    std::vector<std::string> pathNameOrig = hapFileInfo.pathNameOrig;
    int ret = ReadRefreshInfo(task->info, pathNameOrig);
    if (ret == -SELINUX_NO_FOUND_PATHS) {
        restoreTask_ = nullptr;
        return -SELINUX_NO_FOUND_PATHS;
    } else { // ignore other errors
        restoreTask_ = task;
    }
    return SELINUX_SUCC;
}

int HapFileRestoreContext::ProcessRestorePath(std::shared_ptr<RestoreTask> task,
    const std::string& targetPath, const HapFileInfo& hapFileInfo)
{
    int ret = task->RestoreTraversal(targetPath);
    if (ret != SELINUX_SUCC && ret != -SELINUX_RESTORECON_TASK_STOPPED) {
        Selinux::ReportSeharmonyRestoreErr(hapFileInfo.packageName,
            hapFileInfo.uid, ret, "RestoreTraversal failed");
        selinux_log(SELINUX_ERROR, "RestoreTraversal failed for path %s with error %d\n", targetPath.c_str(), ret);
    }
    return ret;
}

void HapFileRestoreContext::FinishRestoreTask(const HapFileInfo& hapFileInfo, ResultInfo& resultInfo)
{
    std::lock_guard<std::mutex> lock(restoreTaskMutex_);
    if (restoreTask_ == nullptr) {
        return;
    }

    uint32_t total = 0;
    std::vector<std::string> currentPath;
    restoreTask_->GetProgress(total, currentPath);
    resultInfo.totalCount = total;
    resultInfo.currentCount = restoreTask_->successCount;

    if (restoreTask_->IsInterrupted() && restoreTask_->GetShouldSave()) {
        std::lock_guard<std::mutex> infoLock(restoreTask_->infoMutex);
        WriteRefreshInfo(restoreTask_->info);
    } else {
        DeleteRefreshInfo(hapFileInfo.packageName, hapFileInfo.uid);
    }

    RestoreFinishInfo finishInfo;
    finishInfo.totalCount = static_cast<int32_t>(total);
    finishInfo.successCount = static_cast<int32_t>(resultInfo.currentCount);
    finishInfo.errorCount = static_cast<int32_t>(restoreTask_->failureCount);
    finishInfo.changeContext = (resultInfo.currentCount > 0);
    finishInfo.stopReason = static_cast<int32_t>(restoreTask_->GetStopReason());
    finishInfo.currentPath = currentPath;
    finishInfo.isSkipAlias = false;

    Selinux::ReportSeharmonyHapFileRestoreFinish(hapFileInfo, finishInfo);
    restoreTask_ = nullptr;
}

int HapFileRestoreContext::StopSetFileCon(const HapFileInfo& hapFileInfo, StopReason stopReason)
{
    std::lock_guard<std::mutex> lock(restoreTaskMutex_);
    bool isAppdat = IsAppdatContext(hapFileInfo);
    bool shouldSave = (stopReason == StopReason::BUSY) || (stopReason == StopReason::UPDATE && isAppdat);
    if (restoreTask_ != nullptr &&
        restoreTask_->info.bundleName == hapFileInfo.packageName &&
        restoreTask_->info.uid == hapFileInfo.uid) {
        (void) restoreTask_->TryToStop(stopReason, shouldSave);
    }
    if (!shouldSave) {
        DeleteRefreshInfo(hapFileInfo.packageName, hapFileInfo.uid);
    }
    selinux_log(SELINUX_INFO, "StopSetFileCon, bundleName=%s, uid = %u, shouldSave = %d",
        hapFileInfo.packageName.c_str(), hapFileInfo.uid, shouldSave);
    return SELINUX_SUCC;
}

#ifdef MCS_ENABLE
static std::string GetMCSLevel(const LevelFrom &levelFrom, uint32_t userId, uint32_t appId)
{
    std::string level = "s0";
    switch (levelFrom) {
        case LEVELFROM_APP:
            level = "s0:x" + std::to_string(CATEGORY_SEG0_OFFSET + (appId & CATEGORY_MASK)) +
                ",x" + std::to_string(CATEGORY_SEG1_OFFSET + ((appId >> SHIFT_8) & CATEGORY_MASK)) +
                ",x" + std::to_string(CATEGORY_SEG2_OFFSET + ((appId >> SHIFT_16) & CATEGORY_MASK));
            break;
        case LEVELFROM_USER:
            level = "s0:x" + std::to_string(CATEGORY_SEG3_OFFSET + (userId & CATEGORY_MASK)) +
                ",x" + std::to_string(CATEGORY_SEG4_OFFSET + ((userId >> SHIFT_8) & CATEGORY_MASK));
            break;
        case LEVELFROM_ALL:
            level = "s0:x" + std::to_string(CATEGORY_SEG0_OFFSET + (appId & CATEGORY_MASK)) +
                ",x" + std::to_string(CATEGORY_SEG1_OFFSET + ((appId >> SHIFT_8) & CATEGORY_MASK)) +
                ",x" + std::to_string(CATEGORY_SEG2_OFFSET + ((appId >> SHIFT_16) & CATEGORY_MASK)) +
                ",x" + std::to_string(CATEGORY_SEG3_OFFSET + (userId & CATEGORY_MASK)) +
                ",x" + std::to_string(CATEGORY_SEG4_OFFSET + ((userId >> SHIFT_8) & CATEGORY_MASK));
            break;
        default:
            break;
    }
    return level;
}

int HapContext::UserAndMCSRangeSet(uint32_t uid, context_t con, const LevelFrom &levelFrom, const std::string &user)
{
    if (uid < UID_BASE) {
        return SELINUX_SUCC;
    }
    uint32_t userId = uid / UID_BASE;
    uint32_t appId = uid % UID_BASE;
    if (userId < USER_BASE) {
        return SELINUX_SUCC;
    }
    int ret = context_user_set(con, user.c_str());
    if (ret != 0) {
        selinux_log(SELINUX_ERROR, "Failed to set context user %s\n", user.c_str());
        return -SELINUX_SET_CONTEXT_USER_ERROR;
    }
    std::string level = GetMCSLevel(levelFrom, userId, appId);
    ret = context_range_set(con, level.c_str());
    if (ret != 0) {
        selinux_log(SELINUX_ERROR, "Failed to set context range %s\n", level.c_str());
        return -SELINUX_SET_CONTEXT_RANGE_ERROR;
    }
    return SELINUX_SUCC;
}
#endif
