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

#include "unit_test.h"
#include <selinux/selinux.h>
#include "selinux_error.h"
#include "selinux_parameter.h"
#include "test_common.h"

namespace OHOS {
namespace Security {
namespace SelinuxUnitTest {
using namespace testing::ext;
using namespace Selinux;
const static std::string DEFAULT_CONTEXT = "u:object_r:default_param:s0";
static const int INVALID_INDEX = -1;
const static std::string TEST_NOT_EXIST_PARA_NAME = "unittest.not.exist";

void SelinuxUnitTest::SetUpTestCase()
{
    int res = InitParamSelinux(0);
    ASSERT_EQ(res, SELINUX_SUCC);
    std::cout << "SetUpTestCase: InitParamSelinux" << std::endl;
}

void SelinuxUnitTest::TearDownTestCase() {}

void SelinuxUnitTest::SetUp() {}

void SelinuxUnitTest::TearDown() {}

/**
 * @tc.name: GetParamList001
 * @tc.desc: GetParamList normal branch.
 * @tc.type: FUNC
 * @tc.require:AR000GJSDS
 */
HWTEST_F(SelinuxUnitTest, GetParamList001, TestSize.Level1)
{
    ParamContextsList *buff = nullptr;
    buff = GetParamList();
    ASSERT_NE(nullptr, buff);

    DestroyParamList(nullptr);
    DestroyParamList(&buff);
    ASSERT_EQ(nullptr, buff);
}

/**
 * @tc.name: GetParamLabel001
 * @tc.desc: GetParamLabel input invalid.
 * @tc.type: FUNC
 * @tc.require:AR000GJSDS
 */
HWTEST_F(SelinuxUnitTest, GetParamLabel001, TestSize.Level1)
{
    ASSERT_EQ(DEFAULT_CONTEXT, GetParamLabel(nullptr));

    ASSERT_EQ(DEFAULT_CONTEXT, GetParamLabel(TEST_NOT_EXIST_PARA_NAME.c_str()));
}

/**
 * @tc.name: GetParamLabelIndex001
 * @tc.desc: GetParamLabelIndex input invalid.
 * @tc.type: FUNC
 * @tc.require:AR000GJSDS
 */
HWTEST_F(SelinuxUnitTest, GetParamLabelIndex001, TestSize.Level1)
{
    ASSERT_EQ(INVALID_INDEX, GetParamLabelIndex(nullptr));
}
} // namespace SelinuxUnitTest
} // namespace Security
} // namespace OHOS
