/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
#include <string>
#include <thread>
#include <selinux/selinux.h>
#include "selinux_error.h"
#include "test_common.h"

namespace OHOS {
namespace Security {
namespace SelinuxUnitTest {
using namespace testing::ext;
using namespace Selinux;
const static int SLEEP_SECOND = 2;
const static std::string BASE_PATH = "/data/app/el1/0/base/";
const static std::string ACCOUNT_PATH = "/data/accounts/account_0/appdata/";
const static std::string TEST_HAP_PATH = BASE_PATH + "com.ohos.selftest/";
const static std::string TEST_ACCOUNT_PATH = ACCOUNT_PATH + "com.ohos.selftest/";
const static std::string TEST_ACCOUNT_SUB_PATH_1_FILE_1 = TEST_ACCOUNT_PATH + "file1.txt";

const static std::string TEST_SUB_PATH_1 = TEST_HAP_PATH + "subpath1/";
const static std::string TEST_SUB_PATH_2 = TEST_HAP_PATH + "subpath2/";
const static std::string TEST_SUB_PATH_3 = TEST_HAP_PATH + "subpath3/";
const static std::string TEST_SUB_PATH_4 = TEST_HAP_PATH + "subpath4/";

const static std::string TEST_SUB_PATH_1_FILE_1 = TEST_SUB_PATH_1 + "file1.txt";
const static std::string TEST_SUB_PATH_1_FILE_2 = TEST_SUB_PATH_1 + "file2.txt";
const static std::string TEST_SUB_PATH_2_FILE_1 = TEST_SUB_PATH_2 + "file1.txt";
const static std::string TEST_SUB_PATH_2_FILE_2 = TEST_SUB_PATH_2 + "file2.txt";
const static std::string TEST_SUB_PATH_3_FILE_1 = TEST_SUB_PATH_3 + "file1.txt";
const static std::string TEST_SUB_PATH_3_FILE_2 = TEST_SUB_PATH_3 + "file2.txt";
const static std::string TEST_SUB_PATH_4_FILE_1 = TEST_SUB_PATH_4 + "file1.txt";
const static std::string TEST_SUB_PATH_4_FILE_2 = TEST_SUB_PATH_4 + "file2.txt";

const static std::string TEST_UNSIMPLIFY_PATH = TEST_SUB_PATH_3 + "//../subpath4/";
const static std::string TEST_UNSIMPLIFY_FILE = TEST_SUB_PATH_4 + "//../subpath3/file1.txt";

const static std::string INVALID_PATH = "/data/data/path";
const static std::string EMPTY_STRING = "";
const static std::string SYSTEM_CORE_APL = "system_core";
const static std::string NORMAL_APL = "normal";
const static std::string INVALID_APL = "invalid_apl";

const static std::string TEST_HAP_BUNDLE_NAME = "com.hap.selftest";
const static std::string TEST_HAP_BUNDLE_NAME_WITH_NO_CONTEXTS = "com.ohos.test";
const static std::string TEST_HAP_BUNDLE_NAME_FOR_INVALID_CONTEXTS = "com.hap.selftest_invalid";
const static std::string TEST_HAP_BUNDLE_NAME_FOR_TEST_SANDBOX = "com.hap.test_sandbox";

const static std::string TEST_HAP_DATA_FILE_LABEL = "u:object_r:selftest_hap_data_file:s0";

const static std::string TEST_HAP_DOMAIN = "u:r:selftest:s0";
const static std::string TEST_HAP_DATA_TYPE = "u:r:selftest_hap_data_file:s0";
const static std::string DLP_HAP_DOMAIN = "u:r:dlp_sandbox_hap:s0";
const static std::string DLP_HAP_DATA_TYPE = "u:r:dlp_sandbox_hap_data_file:s0";
const static std::string TEST_NORMAL_DOMAIN = "u:r:normal_hap:s0";
const static std::string TEST_NOMAL_TYPE = "u:r:normal_hap_data_file:s0";
const static std::string TEST_EXTENSION_DOMAIN = "u:r:extension_test_hap:s0";
const static std::string TEST_EXTENSION_SAME_DOMAIN = "u:r:extension_test_same_hap:s0";
const static std::string TEST_EXTENSION_DEBUG_DOMAIN = "u:r:extension_test_debug_hap:s0";
const static std::string TEST_EXTENSION_PREINSTALL_DOMAIN = "u:r:extension_test_preinstall_hap:s0";
const static std::string TEST_EXTENSION = "extension_test_ability";
const static std::string TEST_SAME_EXTENSION = "extension_same_ability";
const static std::string TEST_DEBUG_EXTENSION = "extension_test_debug_ability";
const static std::string TEST_NORMAL_DOMAIN_WITH_CATEGORY = "o:r:normal_hap:s0:x214,x486,x514,x868,x1024";
const static std::string TEST_NORMAL_DOMAIN_WITH_CATEGORY_USER = "o:r:normal_hap:s0:x868,x1024";
const static std::string TEST_NORMAL_DOMAIN_WITH_CATEGORY_APP = "o:r:normal_hap:s0:x214,x486,x514";
const static std::string TEST_SANDBOX_HAP_DOMAIN = "u:r:test_sandbox_hap:s0";
const static std::string TEST_SANDBOX_HAP_DATA_TYPE = "u:r:test_sandbox_hap_data_file:s0";
const static uint32_t TEST_UID = 20190166;
const static uint32_t TEST_UID_FAILED = 20008;

const static std::string SEHAP_CONTEXTS_FILE = "/data/test/sehap_contexts";

static HapFileInfo g_hapFileInfoWithoutFlags = {
    .pathNameOrig = {TEST_SUB_PATH_1},
    .apl = SYSTEM_CORE_APL,
    .packageName = TEST_HAP_BUNDLE_NAME,
    .flags = 0,
    .hapFlags = 1,
};

static HapFileInfo g_hapFileInfoWithFlags = {
    .pathNameOrig = {TEST_HAP_PATH},
    .apl = SYSTEM_CORE_APL,
    .packageName = TEST_HAP_BUNDLE_NAME,
    .flags = 1,
    .hapFlags = 1,
};

static HapFileInfo g_hapFileInfoWithAplEmpty = {
    .pathNameOrig = {TEST_HAP_PATH},
    .apl = "",
    .packageName = TEST_HAP_BUNDLE_NAME,
    .flags = 0,
    .hapFlags = 1,
};

static HapFileInfo g_hapFileInfoWithPathEmpty = {
    .pathNameOrig = {},
    .apl = SYSTEM_CORE_APL,
    .packageName = TEST_HAP_BUNDLE_NAME,
    .flags = 0,
    .hapFlags = 1,
};

static HapFileInfo g_hapFileInfoWithAplInvalid = {
    .pathNameOrig = {TEST_HAP_PATH},
    .apl = INVALID_APL,
    .packageName = TEST_HAP_BUNDLE_NAME,
    .flags = 0,
    .hapFlags = 1,
};

static HapFileInfo g_hapFileInfoWithCannotFindContexts = {
    .pathNameOrig = {TEST_HAP_PATH},
    .apl = SYSTEM_CORE_APL,
    .packageName = TEST_HAP_BUNDLE_NAME_WITH_NO_CONTEXTS,
    .flags = 0,
    .hapFlags = 1,
};

static HapFileInfo g_hapFileInfoForRepeatLabel = {
    .pathNameOrig = {TEST_SUB_PATH_1},
    .apl = SYSTEM_CORE_APL,
    .packageName = TEST_HAP_BUNDLE_NAME,
    .flags = 0,
    .hapFlags = 1,
};

static HapFileInfo g_hapFileInfoWithPreinstallHap = {
    .pathNameOrig = {TEST_SUB_PATH_1},
    .apl = SYSTEM_CORE_APL,
    .packageName = TEST_HAP_BUNDLE_NAME,
    .flags = 0,
    .hapFlags = 0,
};

static HapFileInfo g_hapFileInfoWithInvalidPath = {
    .pathNameOrig = {TEST_SUB_PATH_1, INVALID_PATH},
    .apl = SYSTEM_CORE_APL,
    .packageName = TEST_HAP_BUNDLE_NAME,
    .flags = 0,
    .hapFlags = 1,
};

static HapFileInfo g_hapFileInfoForInvalidContexts = {
    .pathNameOrig = {TEST_HAP_PATH},
    .apl = NORMAL_APL,
    .packageName = TEST_HAP_BUNDLE_NAME_FOR_INVALID_CONTEXTS,
    .flags = 0,
    .hapFlags = 1,
};

static HapDomainInfo g_hapDomainInfoWithAplEmpty {
    .apl = "",
    .packageName = TEST_HAP_BUNDLE_NAME,
    .hapFlags = 1,
};

static HapDomainInfo g_hapDomainInfoWithInvalidApl {
    .apl = INVALID_APL,
    .packageName = TEST_HAP_BUNDLE_NAME,
    .hapFlags = 1,
};

static HapDomainInfo g_hapDomainInfo {
    .apl = SYSTEM_CORE_APL,
    .packageName = TEST_HAP_BUNDLE_NAME,
    .hapFlags = 1,
};

static HapDomainInfo g_hapDomainInfoForInvalidContexts {
    .apl = NORMAL_APL,
    .packageName = TEST_HAP_BUNDLE_NAME_FOR_INVALID_CONTEXTS,
    .hapFlags = 1,
};

static void GenerateTestFile()
{
    std::vector<std::string> sehapInfo = {
        "apl=system_core domain=system_core_hap type=system_core_hap_data_file",
        "apl=system_basic domain=system_basic_hap type=system_basic_hap_data_file",
        "apl=normal domain=normal_hap type=normal_hap_data_file levelFrom=all user=o",
        "apl=normal debuggable=true domain=debug_hap type=debug_hap_data_file levelFrom=all user=o",
        "apl=system_core name=com.ohos.test domain= type=",
        "apl=system_core domain=selftest type=selftest_hap_data_file",
        "apl=system_core name=com.hap.selftest domain=selftest type=selftest_hap_data_file",
        "apl=normal name=com.hap.selftest domain=selftest type=normal_hap_data_file",
        "apl=normal name=com.hap.selftest_invalid domain=selftest_invalid type=selftest_invalid_hap_data_file",
        "apl=normal extra=invalid_extra domain=dlp_sandbox_hap type=dlp_sandbox_hap_data_file",
        "apl=normal extra=dlp_sandbox domain=dlp_sandbox_hap type=dlp_sandbox_hap_data_file",
        "apl=normal domain=extension_test_hap extension=extension_test_ability",
        "apl=normal domain=extension_test_same_hap extension=extension_same_ability",
        "apl=normal debuggable=true domain=extension_test_debug_hap extension=extension_test_debug_ability",
        "apl=normal name=com.hap.selftest domain=extension_test_preinstall_hap extension=extension_test_ability",
        "apl=normal name=com.hap.test_sandbox extra=custom_sandbox domain=test_sandbox_hap \
        type=test_sandbox_hap_data_file",
        "apl=normal debuggable=true name=com.hap.test_sandbox extra=custom_sandbox domain=test_sandbox_hap \
        type=test_sandbox_hap_data_file"};
    ASSERT_EQ(true, WriteFile(SEHAP_CONTEXTS_FILE, sehapInfo));
}

static void RemoveTestFile()
{
    unlink(SEHAP_CONTEXTS_FILE.c_str());
}

void SelinuxUnitTest::SetUpTestCase()
{
    // make test case clean
    GenerateTestFile();
}

void SelinuxUnitTest::TearDownTestCase()
{
    RemoveTestFile();
}

void SelinuxUnitTest::SetUp() {}

void SelinuxUnitTest::TearDown() {}

void SelinuxUnitTest::CreateDataFile() const {}

/**
 * @tc.name: HapFileRestorecon001
 * @tc.desc: test HapFileRestorecon input para invalid.
 * @tc.type: FUNC
 * @tc.require: AR000GJSDQ
 */
HWTEST_F(SelinuxUnitTest, HapFileRestorecon001, TestSize.Level1)
{
    ASSERT_EQ(true, CreateDirectory(TEST_HAP_PATH));

    EXPECT_EQ(-SELINUX_ARG_INVALID, test.HapFileRestorecon(g_hapFileInfoWithAplEmpty));

    EXPECT_EQ(-SELINUX_ARG_INVALID, test.HapFileRestorecon(g_hapFileInfoWithPathEmpty));

    EXPECT_EQ(-SELINUX_ARG_INVALID, test.HapFileRestorecon(g_hapFileInfoWithAplInvalid));

    ASSERT_EQ(true, RemoveDirectory(TEST_HAP_PATH));
}

/**
 * @tc.name: HapFileRestorecon002
 * @tc.desc: test HapFileRestorecon normal branch without restorecon.
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(SelinuxUnitTest, HapFileRestorecon002, TestSize.Level1)
{
    ASSERT_EQ(true, CreateFile(TEST_SUB_PATH_1_FILE_1)); // this file should not be restorecon

    char *secontextOld = nullptr;
    getfilecon(TEST_SUB_PATH_1_FILE_1.c_str(), &secontextOld);

    int ret = test.HapFileRestorecon(g_hapFileInfoWithoutFlags);
    ASSERT_EQ(SELINUX_SUCC, ret);

    char *secontextNew = nullptr;
    getfilecon(TEST_SUB_PATH_1.c_str(), &secontextNew);
    EXPECT_STREQ(TEST_HAP_DATA_FILE_LABEL.c_str(), secontextNew);
    freecon(secontextNew);
    secontextNew = nullptr;

    getfilecon(TEST_SUB_PATH_1_FILE_1.c_str(), &secontextNew);
    EXPECT_STREQ(secontextOld, secontextNew);
    freecon(secontextNew);
    secontextNew = nullptr;

    ASSERT_EQ(true, RemoveDirectory(TEST_HAP_PATH));
}

/**
 * @tc.name: HapFileRestorecon003
 * @tc.desc: test HapFileRestorecon normal branch with restorecon.
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(SelinuxUnitTest, HapFileRestorecon003, TestSize.Level1)
{
    ASSERT_EQ(true, CreateFile(TEST_SUB_PATH_1_FILE_1));
    ASSERT_EQ(true, CreateFile(TEST_SUB_PATH_1_FILE_2));
    ASSERT_EQ(true, CreateFile(TEST_SUB_PATH_2_FILE_1));
    ASSERT_EQ(true, CreateFile(TEST_SUB_PATH_2_FILE_2));

    int ret = test.HapFileRestorecon(g_hapFileInfoWithFlags);
    ASSERT_EQ(SELINUX_SUCC, ret);

    char *secontext = nullptr;
    getfilecon(TEST_SUB_PATH_1.c_str(), &secontext);
    EXPECT_STREQ(TEST_HAP_DATA_FILE_LABEL.c_str(), secontext);
    freecon(secontext);
    secontext = nullptr;

    getfilecon(TEST_SUB_PATH_2.c_str(), &secontext);
    EXPECT_STREQ(TEST_HAP_DATA_FILE_LABEL.c_str(), secontext);
    freecon(secontext);
    secontext = nullptr;

    getfilecon(TEST_SUB_PATH_1_FILE_1.c_str(), &secontext);
    EXPECT_STREQ(TEST_HAP_DATA_FILE_LABEL.c_str(), secontext);
    freecon(secontext);
    secontext = nullptr;

    getfilecon(TEST_SUB_PATH_1_FILE_2.c_str(), &secontext);
    EXPECT_STREQ(TEST_HAP_DATA_FILE_LABEL.c_str(), secontext);
    freecon(secontext);
    secontext = nullptr;

    getfilecon(TEST_SUB_PATH_2_FILE_1.c_str(), &secontext);
    EXPECT_STREQ(TEST_HAP_DATA_FILE_LABEL.c_str(), secontext);
    freecon(secontext);
    secontext = nullptr;

    getfilecon(TEST_SUB_PATH_2_FILE_2.c_str(), &secontext);
    EXPECT_STREQ(TEST_HAP_DATA_FILE_LABEL.c_str(), secontext);
    freecon(secontext);
    secontext = nullptr;

    ASSERT_EQ(true, RemoveDirectory(TEST_HAP_PATH));
}

/**
 * @tc.name: HapFileRestorecon004
 * @tc.desc: test HapFileRestorecon with single path input para invalid.
 * @tc.type: FUNC
 * @tc.require: AR000GJSDQ
 */
HWTEST_F(SelinuxUnitTest, HapFileRestorecon004, TestSize.Level1)
{
    ASSERT_EQ(true, CreateDirectory(TEST_HAP_PATH));

    EXPECT_EQ(-SELINUX_ARG_INVALID, test.HapFileRestorecon(TEST_HAP_PATH, g_hapFileInfoWithAplEmpty));

    EXPECT_EQ(-SELINUX_ARG_INVALID, test.HapFileRestorecon(EMPTY_STRING, g_hapFileInfoWithPathEmpty));

    EXPECT_EQ(-SELINUX_ARG_INVALID, test.HapFileRestorecon(TEST_HAP_PATH, g_hapFileInfoWithAplInvalid));

    EXPECT_EQ(-SELINUX_CHECK_CONTEXT_ERROR, test.HapFileRestorecon(TEST_HAP_PATH, g_hapFileInfoForInvalidContexts));

    ASSERT_EQ(true, RemoveDirectory(TEST_HAP_PATH));
}

/**
 * @tc.name: HapFileRestorecon005
 * @tc.desc: test HapFileRestorecon with no recurce.
 * @tc.type: FUNC
 * @tc.require: AR000GJSDQ
 */
HWTEST_F(SelinuxUnitTest, HapFileRestorecon005, TestSize.Level1)
{
    ASSERT_EQ(true, CreateFile(TEST_SUB_PATH_1_FILE_1));

    EXPECT_EQ(SELINUX_SUCC, test.HapFileRestorecon(TEST_HAP_PATH, g_hapFileInfoWithoutFlags));

    ASSERT_EQ(true, RemoveDirectory(TEST_HAP_PATH));
}

/**
 * @tc.name: HapFileRestorecon006
 * @tc.desc: test HapFileRestorecon checkPath fail.
 * @tc.type: FUNC
 * @tc.require: AR000GJSDQ
 */
HWTEST_F(SelinuxUnitTest, HapFileRestorecon006, TestSize.Level1)
{
    ASSERT_EQ(true, CreateFile(TEST_SUB_PATH_1_FILE_1));

    EXPECT_EQ(-SELINUX_PATH_INVALID, test.HapFileRestorecon(INVALID_PATH, g_hapFileInfoWithoutFlags));

    ASSERT_EQ(true, RemoveDirectory(TEST_HAP_PATH));
}

/**
 * @tc.name: HapFileRestorecon007
 * @tc.desc: test HapFileRestorecon with accounts path.
 * @tc.type: FUNC
 * @tc.require: AR000GJSDQ
 */
HWTEST_F(SelinuxUnitTest, HapFileRestorecon007, TestSize.Level1)
{
    ASSERT_EQ(true, CreateFile(TEST_ACCOUNT_SUB_PATH_1_FILE_1));

    EXPECT_EQ(SELINUX_SUCC, test.HapFileRestorecon(TEST_ACCOUNT_SUB_PATH_1_FILE_1, g_hapFileInfoWithoutFlags));

    ASSERT_EQ(true, RemoveDirectory(ACCOUNT_PATH));
}

/**
 * @tc.name: HapFileRestorecon008
 * @tc.desc: test HapFileRestorecon type is empty.
 * @tc.type: FUNC
 * @tc.require: AR000GJSDQ
 */
HWTEST_F(SelinuxUnitTest, HapFileRestorecon008, TestSize.Level1)
{
    ASSERT_EQ(true, CreateDirectory(TEST_HAP_PATH));

    EXPECT_EQ(-SELINUX_KEY_NOT_FOUND, test.HapFileRestorecon(TEST_HAP_PATH, g_hapFileInfoWithCannotFindContexts));

    ASSERT_EQ(true, RemoveDirectory(TEST_HAP_PATH));
}

static bool CompareContexts(const std::string &path, const std::string &label)
{
    char *secontext = nullptr;
    getfilecon(path.c_str(), &secontext);
    bool res = (strcmp(label.c_str(), secontext) == 0);
    freecon(secontext);
    secontext = nullptr;
    return res;
}

/**
 * @tc.name: HapFileRestorecon009
 * @tc.desc: test HapFileRestorecon input multi path/file no recurse.
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(SelinuxUnitTest, HapFileRestorecon009, TestSize.Level1)
{
    ASSERT_EQ(true, CreateDirectory(TEST_SUB_PATH_4));
    ASSERT_EQ(true, CreateFile(TEST_SUB_PATH_1_FILE_1));
    ASSERT_EQ(true, CreateFile(TEST_SUB_PATH_1_FILE_2));
    ASSERT_EQ(true, CreateFile(TEST_SUB_PATH_2_FILE_1)); // should not be restorecon
    ASSERT_EQ(true, CreateFile(TEST_SUB_PATH_3_FILE_1));

    char *secontextOld = nullptr;
    getfilecon(TEST_SUB_PATH_2_FILE_1.c_str(), &secontextOld);

    HapFileInfo hapFileInfo = {
        .pathNameOrig = {TEST_SUB_PATH_1, TEST_SUB_PATH_2, TEST_SUB_PATH_1_FILE_1, TEST_SUB_PATH_1_FILE_2,
                         TEST_UNSIMPLIFY_FILE, TEST_UNSIMPLIFY_PATH},
        .apl = SYSTEM_CORE_APL,
        .packageName = TEST_HAP_BUNDLE_NAME,
        .flags = 0,
        .hapFlags = 1,
    };

    ASSERT_EQ(SELINUX_SUCC, test.HapFileRestorecon(hapFileInfo));
    EXPECT_TRUE(CompareContexts(TEST_SUB_PATH_1, TEST_HAP_DATA_FILE_LABEL));
    EXPECT_TRUE(CompareContexts(TEST_SUB_PATH_2, TEST_HAP_DATA_FILE_LABEL));
    EXPECT_TRUE(CompareContexts(TEST_SUB_PATH_1_FILE_1, TEST_HAP_DATA_FILE_LABEL));
    EXPECT_TRUE(CompareContexts(TEST_SUB_PATH_1_FILE_2, TEST_HAP_DATA_FILE_LABEL));
    EXPECT_TRUE(CompareContexts(TEST_SUB_PATH_3_FILE_1, TEST_HAP_DATA_FILE_LABEL));
    EXPECT_TRUE(CompareContexts(TEST_SUB_PATH_4, TEST_HAP_DATA_FILE_LABEL));

    char *secontext = nullptr;
    getfilecon(TEST_SUB_PATH_2_FILE_1.c_str(), &secontext); // this file should not be restorecon
    EXPECT_STREQ(secontextOld, secontext);
    freecon(secontext);
    freecon(secontextOld);
    secontext = nullptr;
    secontextOld = nullptr;

    ASSERT_EQ(true, RemoveDirectory(TEST_HAP_PATH));
}

/**
 * @tc.name: HapFileRestorecon010
 * @tc.desc: test HapFileRestorecon input multi path/file recurse.
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(SelinuxUnitTest, HapFileRestorecon010, TestSize.Level1)
{
    ASSERT_EQ(true, CreateFile(TEST_SUB_PATH_1_FILE_1));
    ASSERT_EQ(true, CreateFile(TEST_SUB_PATH_1_FILE_2));
    ASSERT_EQ(true, CreateFile(TEST_SUB_PATH_2_FILE_1));
    ASSERT_EQ(true, CreateFile(TEST_SUB_PATH_2_FILE_2));
    ASSERT_EQ(true, CreateFile(TEST_SUB_PATH_3_FILE_1));
    ASSERT_EQ(true, CreateFile(TEST_SUB_PATH_3_FILE_2)); // this file should not be restorecon
    ASSERT_EQ(true, CreateFile(TEST_SUB_PATH_4_FILE_1));
    ASSERT_EQ(true, CreateFile(TEST_SUB_PATH_4_FILE_2));

    char *secontextOld = nullptr;
    getfilecon(TEST_SUB_PATH_3_FILE_2.c_str(), &secontextOld);

    HapFileInfo hapFileInfo = {
        .pathNameOrig = { TEST_SUB_PATH_1, TEST_SUB_PATH_2, TEST_UNSIMPLIFY_FILE, TEST_UNSIMPLIFY_PATH },
        .apl = SYSTEM_CORE_APL,
        .packageName = TEST_HAP_BUNDLE_NAME,
        .flags = 1,
        .hapFlags = 1,
    };
    ASSERT_EQ(SELINUX_SUCC, test.HapFileRestorecon(hapFileInfo));
    EXPECT_TRUE(CompareContexts(TEST_SUB_PATH_1, TEST_HAP_DATA_FILE_LABEL));
    EXPECT_TRUE(CompareContexts(TEST_SUB_PATH_2, TEST_HAP_DATA_FILE_LABEL));
    EXPECT_TRUE(CompareContexts(TEST_SUB_PATH_4, TEST_HAP_DATA_FILE_LABEL));
    EXPECT_TRUE(CompareContexts(TEST_SUB_PATH_1_FILE_1, TEST_HAP_DATA_FILE_LABEL));
    EXPECT_TRUE(CompareContexts(TEST_SUB_PATH_1_FILE_2, TEST_HAP_DATA_FILE_LABEL));
    EXPECT_TRUE(CompareContexts(TEST_SUB_PATH_2_FILE_1, TEST_HAP_DATA_FILE_LABEL));
    EXPECT_TRUE(CompareContexts(TEST_SUB_PATH_2_FILE_2, TEST_HAP_DATA_FILE_LABEL));
    EXPECT_TRUE(CompareContexts(TEST_SUB_PATH_4_FILE_1, TEST_HAP_DATA_FILE_LABEL));
    EXPECT_TRUE(CompareContexts(TEST_SUB_PATH_4_FILE_2, TEST_HAP_DATA_FILE_LABEL));
    EXPECT_TRUE(CompareContexts(TEST_SUB_PATH_3_FILE_1, TEST_HAP_DATA_FILE_LABEL));

    char *secontext = nullptr;
    getfilecon(TEST_SUB_PATH_3_FILE_2.c_str(), &secontext);
    EXPECT_STREQ(secontextOld, secontext);
    freecon(secontext);
    freecon(secontextOld);
    secontext = nullptr;
    secontextOld = nullptr;

    ASSERT_EQ(true, RemoveDirectory(TEST_HAP_PATH));
}

/**
 * @tc.name: HapFileRestorecon011
 * @tc.desc: test HapFileRestorecon repeat label.
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(SelinuxUnitTest, HapFileRestorecon011, TestSize.Level1)
{
    ASSERT_EQ(true, CreateDirectory(TEST_SUB_PATH_1));
    int ret = test.HapFileRestorecon(g_hapFileInfoForRepeatLabel);
    ASSERT_EQ(SELINUX_SUCC, ret);

    char *secontext = nullptr;
    getfilecon(TEST_SUB_PATH_1.c_str(), &secontext);
    EXPECT_STREQ(TEST_HAP_DATA_FILE_LABEL.c_str(), secontext);
    freecon(secontext);
    secontext = nullptr;

    char *secontextOld = nullptr;
    getfilecon(TEST_SUB_PATH_1.c_str(), &secontextOld);

    ret = test.HapFileRestorecon(g_hapFileInfoForRepeatLabel); // double restorcon
    ASSERT_EQ(SELINUX_SUCC, ret);

    getfilecon(TEST_SUB_PATH_1.c_str(), &secontext);
    EXPECT_STREQ(secontextOld, secontext);
    freecon(secontext);
    freecon(secontextOld);
    secontext = nullptr;
    secontextOld = nullptr;

    ASSERT_EQ(true, RemoveDirectory(TEST_HAP_PATH));
}

/**
 * @tc.name: HapFileRestorecon012
 * @tc.desc: test HapFileRestorecon normal branch with preinstalled app.
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(SelinuxUnitTest, HapFileRestorecon012, TestSize.Level1)
{
    ASSERT_EQ(true, CreateFile(TEST_SUB_PATH_1_FILE_1));

    int ret = test.HapFileRestorecon(g_hapFileInfoWithPreinstallHap);
    ASSERT_EQ(SELINUX_SUCC, ret);

    char *secontextNew = nullptr;
    getfilecon(TEST_SUB_PATH_1.c_str(), &secontextNew);
    EXPECT_STREQ(TEST_HAP_DATA_FILE_LABEL.c_str(), secontextNew);
    freecon(secontextNew);
    secontextNew = nullptr;

    ASSERT_EQ(true, RemoveDirectory(TEST_HAP_PATH));
}

/**
 * @tc.name: HapFileRestorecon013
 * @tc.desc: test HapFileRestorecon with multi path failed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SelinuxUnitTest, HapFileRestorecon013, TestSize.Level1)
{
    ASSERT_EQ(true, CreateFile(TEST_SUB_PATH_1_FILE_1));
    ASSERT_EQ(true, CreateFile(INVALID_PATH));

    ASSERT_EQ(-SELINUX_RESTORECON_ERROR, test.HapFileRestorecon(g_hapFileInfoWithInvalidPath));

    ASSERT_EQ(true, RemoveDirectory(TEST_HAP_PATH));
    ASSERT_EQ(true, RemoveDirectory(INVALID_PATH));
}

/**
 * @tc.name: HapFileRecurseRestorecon001
 * @tc.desc: test HapFileRecurseRestorecon realPath is nullptr.
 * @tc.type: FUNC
 * @tc.require: AR000GJSDQ
 */
HWTEST_F(SelinuxUnitTest, HapFileRecurseRestorecon001, TestSize.Level1)
{
    int ret = test.HapFileRecurseRestorecon(nullptr, g_hapFileInfoWithCannotFindContexts);
    ASSERT_EQ(-SELINUX_FTS_OPEN_ERROR, ret);
}

/**
 * @tc.name: RestoreconSb001
 * @tc.desc: test RestoreconSb with repeat label.
 * @tc.type: FUNC
 * @tc.require: AR000GJSDQ
 */
HWTEST_F(SelinuxUnitTest, RestoreconSb001, TestSize.Level1)
{
    ASSERT_EQ(true, CreateDirectory(TEST_SUB_PATH_1));

    ASSERT_EQ(SELINUX_SUCC, test.RestoreconSb(TEST_SUB_PATH_1, g_hapFileInfoForRepeatLabel));
    char *secontextOld = nullptr;
    getfilecon(TEST_SUB_PATH_1.c_str(), &secontextOld);
    EXPECT_STREQ(secontextOld, TEST_HAP_DATA_FILE_LABEL.c_str());
    freecon(secontextOld);

    ASSERT_EQ(SELINUX_SUCC, test.RestoreconSb(TEST_SUB_PATH_1, g_hapFileInfoForRepeatLabel)); // double restorcon
    char *secontextNew = nullptr;
    getfilecon(TEST_SUB_PATH_1.c_str(), &secontextNew);
    EXPECT_STREQ(secontextNew, TEST_HAP_DATA_FILE_LABEL.c_str());
    freecon(secontextNew);

    ASSERT_EQ(true, RemoveDirectory(TEST_HAP_PATH));
}

/**
 * @tc.name: HapDomainSetcontext001
 * @tc.desc: test HapDomainSetcontext input para invalid.
 * @tc.type: FUNC
 * @tc.require: issueI6JV34
 */
HWTEST_F(SelinuxUnitTest, HapDomainSetcontext001, TestSize.Level1)
{
    ASSERT_EQ(true, CreateDirectory(TEST_HAP_PATH));

    EXPECT_EQ(-SELINUX_ARG_INVALID, test.HapDomainSetcontext(g_hapDomainInfoWithAplEmpty));
    EXPECT_EQ(-SELINUX_ARG_INVALID, test.HapDomainSetcontext(g_hapDomainInfoWithInvalidApl));

    ASSERT_EQ(true, RemoveDirectory(TEST_HAP_PATH));
}

/**
 * @tc.name: HapDomainSetcontext002
 * @tc.desc: test HapDomainSetcontext must succeed
 * @tc.type: FUNC
 * @tc.require: issueI6JV34
 */
HWTEST_F(SelinuxUnitTest, HapDomainSetcontext002, TestSize.Level1)
{
    pid_t pid = fork();
    ASSERT_TRUE(pid >= 0);
    if (pid == 0) {
        EXPECT_EQ(SELINUX_SUCC, test.HapDomainSetcontext(g_hapDomainInfo));
        usleep(200000); // sleep 200ms
        exit(0);
    } else {
        usleep(150000); // sleep 150ms
        char *con = nullptr;
        ASSERT_EQ(0, getpidcon(pid, &con));
        EXPECT_STREQ(con, TEST_HAP_DOMAIN.c_str());
        freecon(con);
    }
}

/**
 * @tc.name: HapDomainSetcontext003
 * @tc.desc: test HapDomainSetcontext setcon normal_hap.
 * @tc.type: FUNC
 * @tc.require: issueI6JV34
 */
HWTEST_F(SelinuxUnitTest, HapDomainSetcontext003, TestSize.Level1)
{
    pid_t pid = fork();
    ASSERT_TRUE(pid >= 0);
    if (pid == 0) {
        EXPECT_EQ(-SELINUX_CHECK_CONTEXT_ERROR, test.HapDomainSetcontext(g_hapDomainInfoForInvalidContexts));
        exit(0);
    }
}

/**
 * @tc.name: HapContextsLookup001
 * @tc.desc: test HapContextsLookup must succeed
 * @tc.type: FUNC
 * @tc.require: issueI9MCSP
 */
HWTEST_F(SelinuxUnitTest, HapContextsLookup001, TestSize.Level1)
{
    char *oldTypeContext = nullptr;
    ASSERT_EQ(SELINUX_SUCC, getcon(&oldTypeContext));
    context_t con = context_new(oldTypeContext);

    HapContextParams params;
    params.apl = SYSTEM_CORE_APL;
    params.packageName = EMPTY_STRING;
    params.hapFlags = 0;
    params.isDomain = true;
    EXPECT_EQ(SELINUX_SUCC, test.HapContextsLookup(params, con));
    EXPECT_STREQ(context_str(con), TEST_HAP_DOMAIN.c_str());

    params.apl = NORMAL_APL;
    params.packageName = TEST_HAP_BUNDLE_NAME;
    params.hapFlags = SELINUX_HAP_RESTORECON_PREINSTALLED_APP;
    params.isDomain = true;
    EXPECT_EQ(SELINUX_SUCC, test.HapContextsLookup(params, con));
    EXPECT_STREQ(context_str(con), TEST_HAP_DOMAIN.c_str());

    params.apl = NORMAL_APL;
    params.packageName = EMPTY_STRING;
    params.hapFlags = SELINUX_HAP_DLP;
    params.isDomain = true;
    EXPECT_EQ(SELINUX_SUCC, test.HapContextsLookup(params, con));
    EXPECT_STREQ(context_str(con), DLP_HAP_DOMAIN.c_str());

    params.apl = NORMAL_APL;
    params.packageName = EMPTY_STRING;
    params.hapFlags = SELINUX_HAP_DLP | SELINUX_HAP_DEBUGGABLE;
    params.isDomain = true;
    EXPECT_EQ(SELINUX_SUCC, test.HapContextsLookup(params, con));
    EXPECT_STREQ(context_str(con), DLP_HAP_DOMAIN.c_str());

    params.apl = NORMAL_APL;
    params.packageName = TEST_HAP_BUNDLE_NAME_FOR_TEST_SANDBOX;
    params.hapFlags = SELINUX_HAP_CUSTOM_SANDBOX;
    params.isDomain = true;
    EXPECT_EQ(SELINUX_SUCC, test.HapContextsLookup(params, con));
    EXPECT_STREQ(context_str(con), TEST_SANDBOX_HAP_DOMAIN.c_str());

    params.apl = NORMAL_APL;
    params.packageName = TEST_HAP_BUNDLE_NAME_FOR_TEST_SANDBOX;
    params.hapFlags = SELINUX_HAP_CUSTOM_SANDBOX | SELINUX_HAP_DEBUGGABLE;
    params.isDomain = true;
    EXPECT_EQ(SELINUX_SUCC, test.HapContextsLookup(params, con));
    EXPECT_STREQ(context_str(con), TEST_SANDBOX_HAP_DOMAIN.c_str());

    freecon(oldTypeContext);
    context_free(con);
}

/**
 * @tc.name: HapContextsLookup002
 * @tc.desc: test HapContextsLookup must succeed
 * @tc.type: FUNC
 * @tc.require: issueI9MCSP
 */
HWTEST_F(SelinuxUnitTest, HapContextsLookup002, TestSize.Level1)
{
    char *oldTypeContext = nullptr;
    ASSERT_EQ(SELINUX_SUCC, getcon(&oldTypeContext));
    context_t con = context_new(oldTypeContext);

    HapContextParams params;
    params.apl = SYSTEM_CORE_APL;
    params.packageName = EMPTY_STRING;
    params.hapFlags = 0;
    params.isDomain = false;
    EXPECT_EQ(SELINUX_SUCC, test.HapContextsLookup(params, con));
    EXPECT_STREQ(context_str(con), TEST_HAP_DATA_TYPE.c_str());

    params.apl = NORMAL_APL;
    params.packageName = EMPTY_STRING;
    params.hapFlags = 0;
    params.isDomain = false;
    EXPECT_EQ(SELINUX_SUCC, test.HapContextsLookup(params, con));
    EXPECT_STREQ(context_str(con), TEST_NOMAL_TYPE.c_str());

    params.apl = NORMAL_APL;
    params.packageName = TEST_HAP_BUNDLE_NAME;
    params.hapFlags = SELINUX_HAP_RESTORECON_PREINSTALLED_APP;
    params.isDomain = false;
    EXPECT_EQ(SELINUX_SUCC, test.HapContextsLookup(params, con));
    EXPECT_STREQ(context_str(con), TEST_NOMAL_TYPE.c_str());

    params.apl = NORMAL_APL;
    params.packageName = EMPTY_STRING;
    params.hapFlags = SELINUX_HAP_DLP;
    params.isDomain = false;
    EXPECT_EQ(SELINUX_SUCC, test.HapContextsLookup(params, con));
    EXPECT_STREQ(context_str(con), DLP_HAP_DATA_TYPE.c_str());

    params.apl = NORMAL_APL;
    params.packageName = EMPTY_STRING;
    params.hapFlags = SELINUX_HAP_DLP | SELINUX_HAP_DEBUGGABLE;
    params.isDomain = false;
    EXPECT_EQ(SELINUX_SUCC, test.HapContextsLookup(params, con));
    EXPECT_STREQ(context_str(con), DLP_HAP_DATA_TYPE.c_str());

    params.apl = NORMAL_APL;
    params.packageName = TEST_HAP_BUNDLE_NAME_FOR_TEST_SANDBOX;
    params.hapFlags = SELINUX_HAP_CUSTOM_SANDBOX;
    params.isDomain = false;
    EXPECT_EQ(SELINUX_SUCC, test.HapContextsLookup(params, con));
    EXPECT_STREQ(context_str(con), TEST_SANDBOX_HAP_DATA_TYPE.c_str());

    params.apl = NORMAL_APL;
    params.packageName = TEST_HAP_BUNDLE_NAME_FOR_TEST_SANDBOX;
    params.hapFlags = SELINUX_HAP_CUSTOM_SANDBOX | SELINUX_HAP_DEBUGGABLE;
    params.isDomain = false;
    EXPECT_EQ(SELINUX_SUCC, test.HapContextsLookup(params, con));
    EXPECT_STREQ(context_str(con), TEST_SANDBOX_HAP_DATA_TYPE.c_str());

    freecon(oldTypeContext);
    context_free(con);
}

/**
 * @tc.name: HapContextsLookup003
 * @tc.desc: test HapContextsLookup must succeed
 * @tc.type: FUNC
 * @tc.require: issueI9MCSP
 */
HWTEST_F(SelinuxUnitTest, HapContextsLookup003, TestSize.Level1)
{
    char *oldTypeContext = nullptr;
    ASSERT_EQ(SELINUX_SUCC, getcon(&oldTypeContext));
    context_t con = context_new(oldTypeContext);
    //1.normal
    HapContextParams params;
    params.apl = NORMAL_APL;
    params.packageName = EMPTY_STRING;
    params.hapFlags = 0;
    params.extension = TEST_EXTENSION;
    params.isDomain = true;
    int res = test.HapContextsLookup(params, con);
    EXPECT_EQ(res, SELINUX_SUCC);
    EXPECT_STREQ(context_str(con), TEST_EXTENSION_DOMAIN.c_str());
    //2.debug
    params.apl = NORMAL_APL;
    params.packageName = EMPTY_STRING;
    params.hapFlags = SELINUX_HAP_DEBUGGABLE;
    params.extension = TEST_DEBUG_EXTENSION;
    params.isDomain = true;
    res = test.HapContextsLookup(params, con);
    EXPECT_EQ(res, SELINUX_SUCC);
    EXPECT_STREQ(context_str(con), TEST_EXTENSION_DEBUG_DOMAIN.c_str());
    //4.preinstall
    params.apl = NORMAL_APL;
    params.packageName = TEST_HAP_BUNDLE_NAME;
    params.hapFlags = SELINUX_HAP_RESTORECON_PREINSTALLED_APP;
    params.extension = "NOT_SET";
    params.isDomain = true;
    res = test.HapContextsLookup(params, con);
    EXPECT_EQ(res, SELINUX_SUCC);
    EXPECT_STREQ(context_str(con), TEST_HAP_DOMAIN.c_str());

    freecon(oldTypeContext);
    context_free(con);
}

/**
 * @tc.name: HapContextsLookup004
 * @tc.desc: test HapContextsLookup must succeed
 * @tc.type: FUNC
 * @tc.require: issueI9MCSP
 */
HWTEST_F(SelinuxUnitTest, HapContextsLookup004, TestSize.Level1)
{
    char *oldTypeContext = nullptr;
    ASSERT_EQ(SELINUX_SUCC, getcon(&oldTypeContext));
    context_t con = context_new(oldTypeContext);
    HapContextParams params;
    //5.preinstall
    params.apl = NORMAL_APL;
    params.packageName = TEST_HAP_BUNDLE_NAME;
    params.hapFlags = SELINUX_HAP_RESTORECON_PREINSTALLED_APP;
    params.extension = TEST_EXTENSION;
    params.isDomain = true;
    int res = test.HapContextsLookup(params, con);
    EXPECT_EQ(res, SELINUX_SUCC);
    EXPECT_STREQ(context_str(con), TEST_EXTENSION_PREINSTALL_DOMAIN.c_str());
    //6.preinstall
    params.apl = NORMAL_APL;
    params.packageName = TEST_HAP_BUNDLE_NAME;
    params.hapFlags = SELINUX_HAP_RESTORECON_PREINSTALLED_APP;
    params.extension = "NOT_SET";
    params.isDomain = true;
    res = test.HapContextsLookup(params, con);
    EXPECT_EQ(res, SELINUX_SUCC);
    EXPECT_STREQ(context_str(con), TEST_HAP_DOMAIN.c_str());
    //7.preinstall
    params.apl = NORMAL_APL;
    params.packageName = "NOT_SET";
    params.hapFlags = SELINUX_HAP_RESTORECON_PREINSTALLED_APP;
    params.extension = TEST_SAME_EXTENSION;
    params.isDomain = true;
    res = test.HapContextsLookup(params, con);
    EXPECT_EQ(res, SELINUX_SUCC);
    EXPECT_STREQ(context_str(con), TEST_EXTENSION_SAME_DOMAIN.c_str());

    freecon(oldTypeContext);
    context_free(con);
}

/**
 * @tc.name: HapContextsLookup005
 * @tc.desc: test HapContextsLookup must succeed with mcs userid=0
 * @tc.type: FUNC
 * @tc.require: issueI9MCSP
 */
HWTEST_F(SelinuxUnitTest, HapContextsLookup005, TestSize.Level1)
{
    char *oldTypeContext = nullptr;
    ASSERT_EQ(SELINUX_SUCC, getcon(&oldTypeContext));
    context_t con = context_new(oldTypeContext);

    HapContextParams params;
    params.apl = NORMAL_APL;
    params.packageName = EMPTY_STRING;
    params.hapFlags = 0;
    params.isDomain = true;
#ifdef MCS_ENABLE
    EXPECT_EQ(SELINUX_SUCC, test.HapContextsLookup(params, con));
    EXPECT_STREQ(context_str(con), TEST_NORMAL_DOMAIN.c_str());
#else
    EXPECT_EQ(SELINUX_SUCC, test.HapContextsLookup(params, con));
    EXPECT_STREQ(context_str(con), TEST_NORMAL_DOMAIN.c_str());
#endif

    freecon(oldTypeContext);
    context_free(con);
}

/**
 * @tc.name: HapContextsLookup006
 * @tc.desc: test HapContextsLookup must succeed with mcs 0<userid<100
 * @tc.type: FUNC
 * @tc.require: issueI9MCSP
 */
HWTEST_F(SelinuxUnitTest, HapContextsLookup006, TestSize.Level1)
{
    char *oldTypeContext = nullptr;
    ASSERT_EQ(SELINUX_SUCC, getcon(&oldTypeContext));
    context_t con = context_new(oldTypeContext);

    HapContextParams params;
    params.apl = NORMAL_APL;
    params.packageName = EMPTY_STRING;
    params.hapFlags = 0;
    params.isDomain = true;
#ifdef MCS_ENABLE
    params.uid = TEST_UID_FAILED;
    EXPECT_EQ(SELINUX_SUCC, test.HapContextsLookup(params, con));
    EXPECT_STREQ(context_str(con), TEST_NORMAL_DOMAIN.c_str());
#else
    EXPECT_EQ(SELINUX_SUCC, test.HapContextsLookup(params, con));
    EXPECT_STREQ(context_str(con), TEST_NORMAL_DOMAIN.c_str());
#endif

    freecon(oldTypeContext);
    context_free(con);
}

/**
 * @tc.name: HapContextsLookup007
 * @tc.desc: test HapContextsLookup must succeed with mcs userid>=100
 * @tc.type: FUNC
 * @tc.require: issueI9MCSP
 */
HWTEST_F(SelinuxUnitTest, HapContextsLookup007, TestSize.Level1)
{
    char *oldTypeContext = nullptr;
    ASSERT_EQ(SELINUX_SUCC, getcon(&oldTypeContext));
    context_t con = context_new(oldTypeContext);

    HapContextParams params;
    params.apl = NORMAL_APL;
    params.packageName = EMPTY_STRING;
    params.hapFlags = 0;
    params.isDomain = true;
#ifdef MCS_ENABLE
    params.uid = TEST_UID;
    EXPECT_EQ(SELINUX_SUCC, test.HapContextsLookup(params, con));
    EXPECT_STREQ(context_str(con), TEST_NORMAL_DOMAIN_WITH_CATEGORY.c_str());
#else
    EXPECT_EQ(SELINUX_SUCC, test.HapContextsLookup(params, con));
    EXPECT_STREQ(context_str(con), TEST_NORMAL_DOMAIN.c_str());
#endif

    freecon(oldTypeContext);
    context_free(con);
}

/**
 * @tc.name: HapContextsLookup008
 * @tc.desc: test HapContextsLookup must succeed with isDomain=false
 * @tc.type: FUNC
 * @tc.require: issueI9MCSP
 */
HWTEST_F(SelinuxUnitTest, HapContextsLookup008, TestSize.Level1)
{
    char *oldTypeContext = nullptr;
    ASSERT_EQ(SELINUX_SUCC, getcon(&oldTypeContext));
    context_t con = context_new(oldTypeContext);

    //3.preinstall
    HapContextParams params;
    params.apl = NORMAL_APL;
    params.packageName = "NOT_SET";
    params.hapFlags = SELINUX_HAP_RESTORECON_PREINSTALLED_APP;
    params.extension = "NOT_SET";
    params.uid = TEST_UID;
#ifdef MCS_ENABLE
    EXPECT_EQ(test.HapContextsLookup(params, con), SELINUX_SUCC);
    EXPECT_STREQ(context_str(con), TEST_NOMAL_TYPE.c_str());
#else
    EXPECT_EQ(test.HapContextsLookup(params, con), SELINUX_SUCC);
    EXPECT_STREQ(context_str(con), TEST_NOMAL_TYPE.c_str());
#endif

    freecon(oldTypeContext);
    context_free(con);
}

/**
 * @tc.name: HapContextsLookup009
 * @tc.desc: test HapContextsLookup must succeed with isDomain=true
 * @tc.type: FUNC
 * @tc.require: issueI9MCSP
 */
HWTEST_F(SelinuxUnitTest, HapContextsLookup009, TestSize.Level1)
{
    char *oldTypeContext = nullptr;
    ASSERT_EQ(SELINUX_SUCC, getcon(&oldTypeContext));
    context_t con = context_new(oldTypeContext);

    //3.preinstall
    HapContextParams params;
    params.apl = NORMAL_APL;
    params.packageName = "NOT_SET";
    params.hapFlags = SELINUX_HAP_RESTORECON_PREINSTALLED_APP;
    params.extension = "NOT_SET";
    params.uid = TEST_UID;
#ifdef MCS_ENABLE
    params.isDomain = true;
    EXPECT_EQ(test.HapContextsLookup(params, con), SELINUX_SUCC);
    EXPECT_STREQ(context_str(con), TEST_NORMAL_DOMAIN_WITH_CATEGORY.c_str());
#else
    EXPECT_EQ(test.HapContextsLookup(params, con), SELINUX_SUCC);
    EXPECT_STREQ(context_str(con), TEST_NOMAL_TYPE.c_str());
#endif

    freecon(oldTypeContext);
    context_free(con);
}

/**
 * @tc.name: TypeSet001
 * @tc.desc: test TypeSet type is empty.
 * @tc.type: FUNC
 * @tc.require: issueI6JV34
 */
HWTEST_F(SelinuxUnitTest, TypeSet001, TestSize.Level1)
{
    ASSERT_EQ(-SELINUX_ARG_INVALID, test.TypeSet(EMPTY_STRING, nullptr));
}

/**
 * @tc.name: UserAndMCSRangeSet001
 * @tc.desc: test UserAndMCSRangeSet with different level.
 * @tc.type: FUNC
 * @tc.require: issueI6JV34
 */
HWTEST_F(SelinuxUnitTest, UserAndMCSRangeSet001, TestSize.Level1)
{
    char *oldTypeContext = nullptr;
    ASSERT_EQ(SELINUX_SUCC, getcon(&oldTypeContext));
    context_t con = context_new(oldTypeContext);
    ASSERT_EQ(SELINUX_SUCC, test.TypeSet("normal_hap", con));
#ifdef MCS_ENABLE
    EXPECT_EQ(test.UserAndMCSRangeSet(TEST_UID, con, LEVELFROM_ALL, "o"), SELINUX_SUCC);
    EXPECT_STREQ(context_str(con), TEST_NORMAL_DOMAIN_WITH_CATEGORY.c_str());

    EXPECT_EQ(test.UserAndMCSRangeSet(TEST_UID, con, LEVELFROM_USER, "o"), SELINUX_SUCC);
    EXPECT_STREQ(context_str(con), TEST_NORMAL_DOMAIN_WITH_CATEGORY_USER.c_str());

    EXPECT_EQ(test.UserAndMCSRangeSet(TEST_UID, con, LEVELFROM_APP, "o"), SELINUX_SUCC);
    EXPECT_STREQ(context_str(con), TEST_NORMAL_DOMAIN_WITH_CATEGORY_APP.c_str());
#endif
    freecon(oldTypeContext);
    context_free(con);
}
} // namespace SelinuxUnitTest
} // namespace Security
} // namespace OHOS
