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

bool SehapContextsTrie::Insert(const std::string& paraName, const std::string& domain, const std::string& type)
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
        node->prefixInfo.isEnd = true;
        node->prefixInfo.domain = domain;
        node->prefixInfo.type = type;
        return true;
    }
    node->matchedInfo.isEnd = true;
    node->matchedInfo.domain = domain;
    node->matchedInfo.type = type;
    return true;
}

std::string SehapContextsTrie::Search(const std::string& paraName, bool isDomain)
{
    std::vector<std::string> words = SplitString(paraName);
    std::string type = "";
    SehapContextsTrie* root = this;
    for (size_t i = 0; i < words.size(); i++) {
        const std::string& word = words[i];
        auto child = root->FindChild(word);
        if (child == nullptr) {
            break;
        }
        root = child;
        if ((root->prefixInfo.isEnd) && (i != words.size() - 1)) {
            if (isDomain) {
                type = root->prefixInfo.domain;
            } else {
                type = root->prefixInfo.type;
            }
        }
        if ((root->matchedInfo.isEnd) && (i == words.size() - 1)) {
            if (isDomain) {
                type = root->matchedInfo.domain;
            } else {
                type = root->matchedInfo.type;
            }
        }
    }
    return type;
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