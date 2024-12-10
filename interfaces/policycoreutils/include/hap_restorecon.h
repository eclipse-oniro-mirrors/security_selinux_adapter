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

#ifndef HAP_RESTORECON_H
#define HAP_RESTORECON_H

#include <iosfwd>
#include <string>
#include <unordered_map>
#include <vector>
#include <selinux/context.h>
#include "sehap_contexts_trie.h"

#define SELINUX_HAP_RESTORECON_RECURSE 1    // whether the data directory need recurse
#define SELINUX_HAP_RESTORECON_PREINSTALLED_APP 1   // whether it is a pre-built app
#define SELINUX_HAP_DEBUGGABLE 2 // whether it is a debuggable hap
#define SELINUX_HAP_DLP 4 // whether it is dlp hap
#define SELINUX_HAP_INPUT_ISOLATE 8 // whether it is input_isolate hap

// parameters of each SehapInfo in file sehap_contexts
struct SehapInfo {
    std::string apl = "";
    std::string name = "";
    std::string domain = "";
    std::string type = "";
    bool debuggable = false;
    unsigned int extra = 0;
};

struct HapFileInfo {
    std::vector<std::string> pathNameOrig;
    std::string apl;
    std::string packageName;
    unsigned int flags;
    unsigned int hapFlags = 0;
};

struct HapDomainInfo {
    std::string apl;
    std::string packageName;
    unsigned int hapFlags = 0;
};

class HapContext {
public:
    HapContext();
    ~HapContext();
    int HapFileRestorecon(HapFileInfo& hapFileInfo);

    int HapDomainSetcontext(HapDomainInfo& hapDomainInfo);

protected:
    int HapFileRestorecon(const std::string &pathNameOrig, HapFileInfo& hapFileInfo);
    int HapFileRecurseRestorecon(const std::string &realPath, HapFileInfo& hapFileInfo);
    int RestoreconSb(const std::string &pathNameOrig, HapFileInfo& hapFileInfo);
    int GetSecontext(HapFileInfo& hapFileInfo, const std::string &pathNameOrig,
        char **newSecontext, char **oldSecontext);
    int HapLabelLookup(const std::string &apl, const std::string &packageName,
        char **secontextPtr, unsigned int hapFlags);

    int HapContextsLookup(bool isDomain, const std::string &apl, const std::string &packageName,
        context_t con, unsigned int hapFlags);
    int TypeSet(const std::string &type, context_t con);
};

#endif // HAP_RESTORECON_H
