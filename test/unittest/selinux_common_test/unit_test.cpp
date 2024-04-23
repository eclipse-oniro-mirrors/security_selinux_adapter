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
#include <thread>
#include <selinux/selinux.h>
#include "selinux_error.h"
#include "selinux_klog.h"
#include "selinux_log.h"
#include "test_common.h"

namespace OHOS {
namespace Security {
namespace SelinuxUnitTest {
using namespace testing::ext;
using namespace Selinux;

void SelinuxUnitTest::SetUpTestCase() {}

void SelinuxUnitTest::TearDownTestCase() {}

void SelinuxUnitTest::SetUp() {}

void SelinuxUnitTest::TearDown() {}

/**
 * @tc.name: SelinuxHilog001
 * @tc.desc: Test 'int SelinuxHilog(int logLevel, const char *fmt, ...)' with g_logLevel info.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SelinuxUnitTest, SelinuxHilog001, TestSize.Level1)
{
    SetSelinuxHilogLevel(SELINUX_HILOG_INFO);
    EXPECT_EQ(0, SelinuxHilog(SELINUX_HILOG_INFO, "test"));
    EXPECT_EQ(0, SelinuxHilog(SELINUX_HILOG_WARN, "test"));
    EXPECT_EQ(0, SelinuxHilog(SELINUX_HILOG_ERROR, "test"));
    EXPECT_EQ(0, SelinuxHilog(SELINUX_HILOG_AVC, "test"));
}

/**
 * @tc.name: SelinuxHilog002
 * @tc.desc: Test 'int SelinuxHilog(int logLevel, const char *fmt, ...)' with g_logLevel warn.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SelinuxUnitTest, SelinuxHilog002, TestSize.Level1)
{
    SetSelinuxHilogLevel(SELINUX_HILOG_WARN);
    EXPECT_EQ(-1, SelinuxHilog(SELINUX_HILOG_INFO, "test"));
    EXPECT_EQ(0, SelinuxHilog(SELINUX_HILOG_WARN, "test"));
    EXPECT_EQ(0, SelinuxHilog(SELINUX_HILOG_ERROR, "test"));
    EXPECT_EQ(0, SelinuxHilog(SELINUX_HILOG_AVC, "test"));
}

/**
 * @tc.name: SelinuxHilog003
 * @tc.desc: Test 'int SelinuxHilog(int logLevel, const char *fmt, ...)' with g_logLevel error.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SelinuxUnitTest, SelinuxHilog003, TestSize.Level1)
{
    SetSelinuxHilogLevel(SELINUX_HILOG_ERROR);
    EXPECT_EQ(-1, SelinuxHilog(SELINUX_HILOG_INFO, "test"));
    EXPECT_EQ(-1, SelinuxHilog(SELINUX_HILOG_WARN, "test"));
    EXPECT_EQ(0, SelinuxHilog(SELINUX_HILOG_ERROR, "test"));
    EXPECT_EQ(0, SelinuxHilog(SELINUX_HILOG_AVC, "test"));
}

/**
 * @tc.name: SelinuxHilog004
 * @tc.desc: Test 'int SelinuxHilog(int logLevel, const char *fmt, ...)' with logLevel invalid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SelinuxUnitTest, SelinuxHilog004, TestSize.Level1)
{
    SetSelinuxHilogLevel(SELINUX_HILOG_ERROR);
    EXPECT_EQ(-1, SelinuxHilog(SELINUX_HILOG_AVC + 1, "test"));
}

/**
 * @tc.name: SelinuxKmsg001
 * @tc.desc: Test 'int SelinuxKmsg(int logLevel, const char *fmt, ...)' with g_logLevel info.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SelinuxUnitTest, SelinuxKmsg001, TestSize.Level1)
{
    SetSelinuxKmsgLevel(SELINUX_KINFO);
    EXPECT_EQ(0, SelinuxKmsg(SELINUX_KINFO, "test"));
    EXPECT_EQ(0, SelinuxKmsg(SELINUX_KWARN, "test"));
    EXPECT_EQ(0, SelinuxKmsg(SELINUX_KERROR, "test"));
    EXPECT_EQ(0, SelinuxKmsg(SELINUX_KAVC, "test"));
}

/**
 * @tc.name: SelinuxKmsg002
 * @tc.desc: Test 'int SelinuxKmsg(int logLevel, const char *fmt, ...)' with g_logLevel warn.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SelinuxUnitTest, SelinuxKmsg002, TestSize.Level1)
{
    SetSelinuxKmsgLevel(SELINUX_KWARN);
    EXPECT_EQ(-1, SelinuxKmsg(SELINUX_KINFO, "test"));
    EXPECT_EQ(0, SelinuxKmsg(SELINUX_KWARN, "test"));
    EXPECT_EQ(0, SelinuxKmsg(SELINUX_KERROR, "test"));
    EXPECT_EQ(0, SelinuxKmsg(SELINUX_KAVC, "test"));
}

/**
 * @tc.name: SelinuxKmsg003
 * @tc.desc: Test 'int SelinuxKmsg(int logLevel, const char *fmt, ...)' with g_logLevel error.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SelinuxUnitTest, SelinuxKmsg003, TestSize.Level1)
{
    SetSelinuxKmsgLevel(SELINUX_KERROR);
    EXPECT_EQ(-1, SelinuxKmsg(SELINUX_KINFO, "test"));
    EXPECT_EQ(-1, SelinuxKmsg(SELINUX_KWARN, "test"));
    EXPECT_EQ(0, SelinuxKmsg(SELINUX_KERROR, "test"));
    EXPECT_EQ(0, SelinuxKmsg(SELINUX_KAVC, "test"));
}

/**
 * @tc.name: SelinuxKmsg004
 * @tc.desc: Test 'int SelinuxKmsg(int logLevel, const char *fmt, ...)' with logLevel invalid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SelinuxUnitTest, SelinuxKmsg004, TestSize.Level1)
{
    SetSelinuxKmsgLevel(SELINUX_KERROR);
    EXPECT_EQ(-1, SelinuxKmsg(SELINUX_KAVC + 1, "test"));
}
} // namespace SelinuxUnitTest
} // namespace Security
} // namespace OHOS
