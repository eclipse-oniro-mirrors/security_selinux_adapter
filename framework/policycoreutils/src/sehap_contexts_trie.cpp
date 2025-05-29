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
#include "sehap_contexts_trie.h"
#include <deque>

#include "src/callbacks.h"
#include "selinux/selinux.h"
#include "selinux_log.h"
#include <iostream>

std::vector<std::string> SehapContextsTrie::SplitString(const std::string& paraName)
{
    std::vector<std::string> words;
    std::string delimiter = ".";
    size_t len = paraName.length();
    size_t index = 0;
    while (index < len) {
        size_t pos;
        if ((pos = paraName.substr(index).find(delimiter)) == std::string::npos) {
            break;
        }
        std::string element = paraName.substr(index, pos);
        if (!element.empty()) {
            words.emplace_back(element);
        }
        index += pos + delimiter.length();
    }
    if (!paraName.substr(index).empty()) {
        words.emplace_back(paraName.substr(index));
    }
    return words;
}

SehapContextsTrie* SehapContextsTrie::FindChild(const std::string& element)
{
    SehapContextsTrie* node = this;
    auto iter = node->children.find(element);
    if (iter != node->children.end()) {
        return iter->second;
    }
    return nullptr;
}

void NodeTypeInfo::Insert(const SehapInsertParamInfo &paramInfo)
{
    if (!paramInfo.extension.empty()) {
        ExtensionInfo extInfo;
        extInfo.domain = paramInfo.domain;
#ifdef MCS_ENABLE
        extInfo.levelFrom = paramInfo.levelFrom;
        extInfo.user = paramInfo.user;
#endif
        extensionMap[paramInfo.extension] = extInfo;
    } else {
        this->domain = paramInfo.domain;
        this->type = paramInfo.type;
#ifdef MCS_ENABLE
        this->levelFrom = paramInfo.levelFrom;
        this->user = paramInfo.user;
#endif
    }
    this->isEnd = true;
}

bool SehapContextsTrie::Insert(const std::string& paraName, const SehapInsertParamInfo &paramInfo)
{
    SehapContextsTrie* node = this;
    std::vector<std::string> words = SplitString(paraName);
    for (const std::string& word : words) {
        if (word == "*") {
            break;
        }
        if (node->children[word] == nullptr) {
            node->children[word] = new (std::nothrow) SehapContextsTrie();
            if (node->children[word] == nullptr) {
                selinux_log(SELINUX_ERROR, "new child sehapcontextstrie failed!");
                return false;
            }
        }
        node = node->children[word];
    }

    if ((paraName.back() == '.') || (paraName.back() == '*')) {
        node->prefixInfo.Insert(paramInfo);
    } else {
        node->matchedInfo.Insert(paramInfo);
    }

    return true;
}

SehapContextInfo NodeTypeInfo::Search(bool isDomain, const std::string& extension) const
{
    SehapContextInfo contextInfo;
    if (isDomain && !extension.empty()) {
        auto it = extensionMap.find(extension);
        if (it != extensionMap.end()) {
            contextInfo.context = it->second.domain;
            contextInfo.isDomain = isDomain;
#ifdef MCS_ENABLE
            contextInfo.levelFrom = it->second.levelFrom;
            contextInfo.user = it->second.user;
#endif
            return contextInfo;
        }
    }
    contextInfo.context = isDomain ? domain : type;
    contextInfo.isDomain = isDomain;
#ifdef MCS_ENABLE
    contextInfo.levelFrom = levelFrom;
    contextInfo.user = user;
#endif
    return contextInfo;
}

SehapContextInfo SehapContextsTrie::Search(const std::string& paraName, bool isDomain, const std::string& extension)
{
    std::vector<std::string> words = SplitString(paraName);
    SehapContextInfo contextInfo;
    SehapContextsTrie* root = this;
    for (size_t i = 0; i < words.size(); i++) {
        const std::string& word = words[i];
        auto child = root->FindChild(word);
        if (child == nullptr) {
            break;
        }
        root = child;
        if ((root->prefixInfo.isEnd) && (i != words.size() - 1)) {
            contextInfo = root->prefixInfo.Search(isDomain, extension);
        }
        if ((root->matchedInfo.isEnd) && (i == words.size() - 1)) {
            contextInfo = root->matchedInfo.Search(isDomain, extension);
        }
    }
    return contextInfo;
}

void SehapContextsTrie::Clear()
{
    SehapContextsTrie* root = this;
    std::deque<SehapContextsTrie*> nodeDeque;
    for (auto child : root->children) {
        nodeDeque.emplace_back(child.second);
    }
    while (!nodeDeque.empty()) {
        root = nodeDeque.front();
        nodeDeque.pop_front();
        if (root != nullptr) {
            for (auto child : root->children) {
                nodeDeque.emplace_back(child.second);
            }
            delete root;
        }
    }
}