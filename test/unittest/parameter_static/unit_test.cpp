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

#include "unit_test.h"

#include <iostream>
#include <new>
#include <selinux/selinux.h>
#include <vector>
#include "gtest/gtest.h"
#include "contexts_trie.h"
#include "selinux_error.h"
#include "selinux_map.h"
#include "selinux_share_mem.h"
#include "cstdlib"
#include "test_common.h"
#include "unistd.h"

namespace OHOS {
namespace Security {
namespace SelinuxUnitTest {
using namespace testing::ext;
using namespace Selinux;
const static std::string PARAMETER_CONTEXTS_FILE = "/system/etc/selinux/targeted/contexts/parameter_contexts";
static const char DEFAULT_CONTEXT[] = "u:object_r:default_param:s0";

void SelinuxUnitTest::SetUpTestCase() {}

void SelinuxUnitTest::TearDownTestCase() {}

void SelinuxUnitTest::SetUp() {}

void SelinuxUnitTest::TearDown() {}

static bool GenerateParamHashNode(const std::string &name, ParamHashNode **groupNode)
{
    auto tmp = static_cast<ParamHashNode*>(calloc(1, sizeof(ParamHashNode)));
    if (tmp == nullptr) {
        return false;
    }
    tmp->nameLen = name.size();
    tmp->name = strdup(name.c_str());
    if (tmp->name == nullptr) {
        free(tmp);
        return false;
    }
    tmp->childPtr = nullptr;
    *groupNode = tmp;
    return true;
}

static void FreeParamHashNode(ParamHashNode *groupNode)
{
    if (groupNode == nullptr) {
        return;
    }
    if (groupNode->name != nullptr) {
        free(groupNode->name);
    }
    free(groupNode);
}

/**
 * @tc.name: HashMapCreate001
 * @tc.desc: Test 'int32_t HashMapCreate(HashTab **handle)' with invalid params.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SelinuxUnitTest, HashMapCreate001, TestSize.Level1)
{
    ASSERT_EQ(-1, HashMapCreate(nullptr));
}

/**
 * @tc.name: HashMapCreate002
 * @tc.desc: Test 'int32_t HashMapCreate(HashTab **handle)' with valid params.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SelinuxUnitTest, HashMapCreate002, TestSize.Level1)
{
    HashTab *handle = nullptr;
    EXPECT_EQ(0, HashMapCreate(&handle));
    HashMapDestroy(handle);
}

/**
 * @tc.name: HashMapDestroy001
 * @tc.desc: Test 'void HashMapDestroy(HashTab *handle)' with handle nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SelinuxUnitTest, HashMapDestroy001, TestSize.Level1)
{
    HashTab *handle = nullptr;
    HashMapDestroy(handle);
    ASSERT_EQ(nullptr, handle);
}

/**
 * @tc.name: HashMapDestroy002
 * @tc.desc: Test 'void HashMapDestroy(HashTab *handle)' with handle valid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SelinuxUnitTest, HashMapDestroy002, TestSize.Level1)
{
    HashTab *handle = nullptr;
    ASSERT_TRUE(HashMapCreate(&handle) == 0);
    ASSERT_TRUE(handle != nullptr);

    for (size_t i = 0; i < 100; i++) {
        ParamHashNode *groupNode = nullptr;
        ASSERT_TRUE(GenerateParamHashNode(std::to_string(i), &groupNode));
        ASSERT_EQ(HashMapAdd(handle, &(groupNode->hashNode)), 0);
    }
    HashMapDestroy(handle);
}

/**
 * @tc.name: HashMapAdd001
 * @tc.desc: Test 'int32_t HashMapAdd(HashTab *handle, HashNode *node)' with handle nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SelinuxUnitTest, HashMapAdd001, TestSize.Level1)
{
    ParamHashNode *groupNode = nullptr;
    ASSERT_TRUE(GenerateParamHashNode("test", &groupNode));
    EXPECT_EQ(-1, HashMapAdd(nullptr, &(groupNode->hashNode)));
    FreeParamHashNode(groupNode);
}

/**
 * @tc.name: HashMapAdd002
 * @tc.desc: Test 'int32_t HashMapAdd(HashTab *handle, HashNode *node)' with node nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SelinuxUnitTest, HashMapAdd002, TestSize.Level1)
{
    HashTab *handle = nullptr;
    ASSERT_EQ(0, HashMapCreate(&handle));
    ASSERT_EQ(-1, HashMapAdd(handle, nullptr));
    HashMapDestroy(handle);
}

/**
 * @tc.name: HashMapAdd003
 * @tc.desc: Test 'int32_t HashMapAdd(HashTab *handle, HashNode *node)' with node->next not nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SelinuxUnitTest, HashMapAdd003, TestSize.Level1)
{
    HashTab *handle = nullptr;
    ASSERT_EQ(0, HashMapCreate(&handle));
    ParamHashNode *groupNode = nullptr;
    ASSERT_TRUE(GenerateParamHashNode("test", &groupNode));
    groupNode->hashNode.next = new (std::nothrow) HashNode;
    EXPECT_EQ(-1, HashMapAdd(handle, &(groupNode->hashNode)));
    FreeParamHashNode(groupNode);
    HashMapDestroy(handle);
}

/**
 * @tc.name: HashMapAdd004
 * @tc.desc: Test 'int32_t HashMapAdd(HashTab *handle, HashNode *node)' with key exist
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SelinuxUnitTest, HashMapAdd004, TestSize.Level1)
{
    HashTab *handle = nullptr;
    ASSERT_EQ(0, HashMapCreate(&handle));
    ParamHashNode *groupNode1 = nullptr;
    ASSERT_TRUE(GenerateParamHashNode("test", &groupNode1));
    ASSERT_EQ(0, HashMapAdd(handle, &(groupNode1->hashNode)));
    ParamHashNode *groupNode2 = nullptr;
    ASSERT_TRUE(GenerateParamHashNode("test", &groupNode2));
    ASSERT_EQ(-1, HashMapAdd(handle, &(groupNode2->hashNode)));
    FreeParamHashNode(groupNode2);
    HashMapDestroy(handle);
}

/**
 * @tc.name: InitSharedMem001
 * @tc.desc: Test 'void *InitSharedMem(const char *fileName, uint32_t spaceSize, bool readOnly)' with invalid params.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SelinuxUnitTest, InitSharedMem001, TestSize.Level1)
{
    EXPECT_EQ(nullptr, InitSharedMem("", 0, 0));
    ASSERT_NE(0, access("/invalid_path", R_OK));
    EXPECT_EQ(nullptr, InitSharedMem("/invalid_path", 1024 * 80, 1));
    EXPECT_EQ(nullptr, InitSharedMem("/dev/__parameters__/param_selinux", 0, 0));
}

/**
 * @tc.name: ReadSharedMem001
 * @tc.desc: Test 'char *ReadSharedMem(char *sharedMem, uint32_t length)' with invalid params.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SelinuxUnitTest, ReadSharedMem001, TestSize.Level1)
{
    EXPECT_EQ(nullptr, ReadSharedMem(nullptr, 1));
    EXPECT_EQ(nullptr, ReadSharedMem("test", 0));
}

/**
 * @tc.name: ReadSharedMem002
 * @tc.desc: Test 'char *ReadSharedMem(char *sharedMem, uint32_t length)' with valid params.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SelinuxUnitTest, ReadSharedMem002, TestSize.Level1)
{
    EXPECT_EQ("test", ReadSharedMem("test", 4));
}
} // namespace SelinuxUnitTest
} // namespace Security
} // namespace OHOS
