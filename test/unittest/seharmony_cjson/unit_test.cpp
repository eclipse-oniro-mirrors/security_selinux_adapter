/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <fcntl.h>
#include <selinux/selinux.h>
#include <string>
#include <sys/types.h>
#include <sys/stat.h>

#include "selinux_error.h"
#include "test_common.h"

namespace OHOS {
namespace Security {
namespace SelinuxUnitTest {
using namespace testing::ext;
using namespace Selinux;

const static std::string TEST_TARGET1_PATH = "/data/seharmony_cjson_test1";
const static std::string TEST_TARGET2_PATH = "/data/seharmony_cjson_test2";
const static std::string TEST_TARGET3_PATH = "/data/seharmony_cjson_test3";
const static std::string TEST_TARGET4_PATH = "/data/seharmony_cjson_test4";
const static std::string TEST_TARGET5_PATH = "/data/seharmony_cjson_test5";
const static std::string RESTORECON_HAP_DATA_BASE =
    "/data/seharmony_cjson_test";
const static std::string RESTORECON_HAP_DATA_DIR =
    "/data/seharmony_cjson_test/100/bms/bundle_manager_service";
const static std::string RESTORECON_HAP_DATA_FILE =
    "/data/seharmony_cjson_test/100/bms/bundle_manager_service/restorecon_hap_data.json";
const static uint32_t TEST_UID = 20020087;
const static uint32_t TEST_USERID = 100;

void SelinuxUnitTest::SetUpTestCase() {}

void SelinuxUnitTest::TearDownTestCase() {}

void SelinuxUnitTest::SetUp() {}

void SelinuxUnitTest::TearDown()
{
    RemoveDirectory(TEST_TARGET1_PATH);
    RemoveDirectory(TEST_TARGET2_PATH);
    RemoveDirectory(TEST_TARGET3_PATH);
    RemoveDirectory(TEST_TARGET4_PATH);
    RemoveDirectory(TEST_TARGET5_PATH);
    RemoveDirectory(RESTORECON_HAP_DATA_BASE);
}

static int32_t RemoveFile(const std::string& fileName)
{
    return unlink(fileName.c_str());
}

static bool CreateCfgFile(const std::string& fileName)
{
    int32_t fd = creat(fileName.c_str(), S_IRUSR | S_IWUSR);
    if (fd < 0) {
        return false;
    }
    close(fd);
    return true;
}

/**
 * @tc.name: ReadRefreshInfo001
 * @tc.desc: test ReadRefreshInfo with invalid param.
 * @tc.type: FUNC
 * @tc.require: 4622
 */
HWTEST_F(SelinuxUnitTest, ReadRefreshInfo001, TestSize.Level1)
{
    RefreshInfo readInfo;
    std::vector<std::string> pathNameOrig;
    // bundleName is empty
    EXPECT_EQ(-SELINUX_PATH_INVALID, ReadRefreshInfo(readInfo, pathNameOrig));
    // pathNameOrig is empty
    readInfo.bundleName = "com.ohos.test";
    EXPECT_EQ(-SELINUX_PATH_INVALID, ReadRefreshInfo(readInfo, pathNameOrig));
    // pathNameOrig contains paths, which all do not exist
    pathNameOrig.push_back(TEST_TARGET1_PATH);
    pathNameOrig.push_back(TEST_TARGET2_PATH);
    pathNameOrig.push_back(TEST_TARGET3_PATH);
    EXPECT_EQ(-SELINUX_NO_FOUND_PATHS, ReadRefreshInfo(readInfo, pathNameOrig));
    ASSERT_EQ(0, readInfo.paths.size());
}

/**
 * @tc.name: ReadRefreshInfo002
 * @tc.desc: test ReadRefreshInfo without a json file, part of paths do not exist.
 * @tc.type: FUNC
 * @tc.require: 4622
 */
HWTEST_F(SelinuxUnitTest, ReadRefreshInfo002, TestSize.Level1)
{
    RefreshInfo readInfo;
    readInfo.bundleName = "com.ohos.test";
    readInfo.uid = TEST_UID;
    std::vector<std::string> pathNameOrig;
    pathNameOrig.push_back(TEST_TARGET1_PATH);
    pathNameOrig.push_back(TEST_TARGET2_PATH);
    pathNameOrig.push_back(TEST_TARGET3_PATH);

    // pathNameOrig contains paths, part of which do not exist
    ASSERT_EQ(true, CreateDirectory(TEST_TARGET2_PATH));

    EXPECT_EQ(SELINUX_SUCC, ReadRefreshInfo(readInfo, pathNameOrig));
    ASSERT_EQ(1, readInfo.paths.size());
    ASSERT_NE(nullptr, readInfo.paths[TEST_TARGET2_PATH]);
    ASSERT_EQ(TEST_TARGET2_PATH, readInfo.paths[TEST_TARGET2_PATH]->target);
    ASSERT_EQ(true, readInfo.paths[TEST_TARGET2_PATH]->finished.empty());
    ASSERT_EQ(false, readInfo.paths[TEST_TARGET2_PATH]->done);

    ASSERT_EQ(true, RemoveDirectory(TEST_TARGET2_PATH));
}

/**
 * @tc.name: ReadRefreshInfo003
 * @tc.desc: test ReadRefreshInfo without a json file, all of paths do exist.
 * @tc.type: FUNC
 * @tc.require: 4622
 */
HWTEST_F(SelinuxUnitTest, ReadRefreshInfo003, TestSize.Level1)
{
    RefreshInfo readInfo;
    readInfo.bundleName = "com.ohos.test";
    readInfo.uid = TEST_UID;
    std::vector<std::string> pathNameOrig;
    pathNameOrig.push_back(TEST_TARGET1_PATH);
    pathNameOrig.push_back(TEST_TARGET2_PATH);
    pathNameOrig.push_back(TEST_TARGET3_PATH);

    // pathNameOrig contains paths, part of which all exist
    ASSERT_EQ(true, CreateDirectory(TEST_TARGET1_PATH));
    ASSERT_EQ(true, CreateDirectory(TEST_TARGET2_PATH));
    ASSERT_EQ(true, CreateDirectory(TEST_TARGET3_PATH));

    EXPECT_EQ(SELINUX_SUCC, ReadRefreshInfo(readInfo, pathNameOrig));
    ASSERT_EQ(pathNameOrig.size(), readInfo.paths.size());
    ASSERT_NE(nullptr, readInfo.paths[TEST_TARGET1_PATH]);
    ASSERT_NE(nullptr, readInfo.paths[TEST_TARGET2_PATH]);
    ASSERT_NE(nullptr, readInfo.paths[TEST_TARGET3_PATH]);
    ASSERT_EQ(TEST_TARGET1_PATH, readInfo.paths[TEST_TARGET1_PATH]->target);
    ASSERT_EQ(TEST_TARGET2_PATH, readInfo.paths[TEST_TARGET2_PATH]->target);
    ASSERT_EQ(TEST_TARGET3_PATH, readInfo.paths[TEST_TARGET3_PATH]->target);

    ASSERT_EQ(true, RemoveDirectory(TEST_TARGET1_PATH));
    ASSERT_EQ(true, RemoveDirectory(TEST_TARGET2_PATH));
    ASSERT_EQ(true, RemoveDirectory(TEST_TARGET3_PATH));
}

/**
 * @tc.name: ReadRefreshInfo004
 * @tc.desc: test ReadRefreshInfo with an empty json file.
 * @tc.type: FUNC
 * @tc.require: 4622
 */
HWTEST_F(SelinuxUnitTest, ReadRefreshInfo004, TestSize.Level1)
{
    RefreshInfo readInfo;
    readInfo.bundleName = "com.ohos.test";
    readInfo.uid = TEST_UID;
    std::vector<std::string> pathNameOrig;
    pathNameOrig.push_back(TEST_TARGET1_PATH);
    pathNameOrig.push_back(TEST_TARGET2_PATH);
    pathNameOrig.push_back(TEST_TARGET3_PATH);

    // Create an empty json file
    ASSERT_EQ(true, CreateDirectory(RESTORECON_HAP_DATA_DIR));
    ASSERT_EQ(true, CreateCfgFile(RESTORECON_HAP_DATA_FILE));
    // pathNameOrig contains paths, part of which do not exist
    ASSERT_EQ(true, CreateDirectory(TEST_TARGET1_PATH));

    EXPECT_EQ(SELINUX_SUCC, ReadRefreshInfo(readInfo, pathNameOrig));
    ASSERT_EQ(1, readInfo.paths.size());
    ASSERT_NE(nullptr, readInfo.paths[TEST_TARGET1_PATH]);
    ASSERT_EQ(TEST_TARGET1_PATH, readInfo.paths[TEST_TARGET1_PATH]->target);
    ASSERT_EQ(true, readInfo.paths[TEST_TARGET1_PATH]->finished.empty());
    ASSERT_EQ(false, readInfo.paths[TEST_TARGET1_PATH]->done);

    ASSERT_EQ(true, RemoveDirectory(TEST_TARGET1_PATH));
    ASSERT_EQ(0, RemoveFile(RESTORECON_HAP_DATA_FILE));
    ASSERT_EQ(true, RemoveDirectory(RESTORECON_HAP_DATA_BASE));
}

/**
 * @tc.name: ReadRefreshInfo005
 * @tc.desc: test ReadRefreshInfo with a json file of wrong format.
 * @tc.type: FUNC
 * @tc.require: 4622
 */
HWTEST_F(SelinuxUnitTest, ReadRefreshInfo005, TestSize.Level1)
{
    // Create an empty json file
    ASSERT_EQ(true, CreateDirectory(RESTORECON_HAP_DATA_DIR));
    ASSERT_EQ(true, CreateCfgFile(RESTORECON_HAP_DATA_FILE));
    // Write something of not json format
    std::string content = R"({"bundleName":"com.ohos.test","uid":20020087,"path":[{"target": "xxx", "finished": "xxx",
        "count": 2, "done": false}]}])";
    std::vector<std::string> writeContent;
    writeContent.push_back(content);
    ASSERT_EQ(true, WriteFile(RESTORECON_HAP_DATA_FILE, writeContent));

    RefreshInfo readInfo;
    readInfo.bundleName = "com.ohos.test";
    readInfo.uid = TEST_UID;
    std::vector<std::string> pathNameOrig;
    pathNameOrig.push_back(TEST_TARGET1_PATH);
    // pathNameOrig contains paths, part of which do not exist
    ASSERT_EQ(true, CreateDirectory(TEST_TARGET1_PATH));
    EXPECT_EQ(SELINUX_SUCC, ReadRefreshInfo(readInfo, pathNameOrig));
    ASSERT_EQ(-1, RemoveFile(RESTORECON_HAP_DATA_FILE));

    ASSERT_EQ(true, CreateCfgFile(RESTORECON_HAP_DATA_FILE));
    // Write something of not json format
    content = R"(["bundleName":"com.ohos.test","uid":20020087,"path":[{"target": "xxx", "finished": "xxx",
        "count": 2, "done": false}]}])";
    writeContent[0] = content;
    ASSERT_EQ(true, WriteFile(RESTORECON_HAP_DATA_FILE, writeContent));
    EXPECT_EQ(SELINUX_SUCC, ReadRefreshInfo(readInfo, pathNameOrig));
    ASSERT_EQ(-1, RemoveFile(RESTORECON_HAP_DATA_FILE));

    ASSERT_EQ(true, CreateCfgFile(RESTORECON_HAP_DATA_FILE));
    // Write something of not json format
    content = R"([{"bundleNa":"com.ohos.test","uid":20020087,"path":[{"target": "xxx", "finished": "xxx",
        "count": 2, "done": false}]}])";
    writeContent[0] = content;
    ASSERT_EQ(true, WriteFile(RESTORECON_HAP_DATA_FILE, writeContent));
    EXPECT_EQ(SELINUX_SUCC, ReadRefreshInfo(readInfo, pathNameOrig));
    ASSERT_EQ(-1, RemoveFile(RESTORECON_HAP_DATA_FILE));

    ASSERT_EQ(true, CreateCfgFile(RESTORECON_HAP_DATA_FILE));
    // Write something of not json format
    content = R"([{"bundleName":"com.ohos.test","uid":20020087,"path":{"target": "xxx", "finished": "xxx",
        "count": 2, "done": false}]}])";
    writeContent[0] = content;
    ASSERT_EQ(true, WriteFile(RESTORECON_HAP_DATA_FILE, writeContent));
    EXPECT_EQ(SELINUX_SUCC, ReadRefreshInfo(readInfo, pathNameOrig));
    ASSERT_EQ(-1, RemoveFile(RESTORECON_HAP_DATA_FILE));

    ASSERT_EQ(true, CreateCfgFile(RESTORECON_HAP_DATA_FILE));
    // Write something of not json format
    content = R"([{"bundleName":"com.ohos.test","uid":20020087,"path":["target": "xxx", "finished": "xxx",
        "count": 2, "done": false}]}])";
    writeContent[0] = content;
    ASSERT_EQ(true, WriteFile(RESTORECON_HAP_DATA_FILE, writeContent));
    EXPECT_EQ(SELINUX_SUCC, ReadRefreshInfo(readInfo, pathNameOrig));
    ASSERT_EQ(-1, RemoveFile(RESTORECON_HAP_DATA_FILE));

    ASSERT_EQ(true, CreateCfgFile(RESTORECON_HAP_DATA_FILE));
    // Write something of not json format
    content = R"([{"bundleName":"com.ohos.test","uid":20020087,"path":[{"targe": "xxx", "finished": "xxx",
        "count": 2, "done": false}]}])";
    writeContent[0] = content;
    ASSERT_EQ(true, WriteFile(RESTORECON_HAP_DATA_FILE, writeContent));
    EXPECT_EQ(SELINUX_SUCC, ReadRefreshInfo(readInfo, pathNameOrig));
    ASSERT_EQ(-1, RemoveFile(RESTORECON_HAP_DATA_FILE));

    ASSERT_EQ(true, CreateCfgFile(RESTORECON_HAP_DATA_FILE));
    // Write something of not json format
    content = R"([{"bundleName":"com.ohos.test","uid":20020087,"path":[{"target": "xxx", "finished": "xxx",
        "count": 2, "done": false}]}])";
    writeContent[0] = content;
    ASSERT_EQ(true, WriteFile(RESTORECON_HAP_DATA_FILE, writeContent));
    EXPECT_EQ(SELINUX_SUCC, ReadRefreshInfo(readInfo, pathNameOrig));

    ASSERT_EQ(true, RemoveDirectory(TEST_TARGET1_PATH));
    ASSERT_EQ(-1, RemoveFile(RESTORECON_HAP_DATA_FILE));
    ASSERT_EQ(true, RemoveDirectory(RESTORECON_HAP_DATA_BASE));
}

/**
 * @tc.name: ReadRefreshInfo006
 * @tc.desc: test ReadRefreshInfo with a json file of mismatching the bundle name.
 * @tc.type: FUNC
 * @tc.require: 4622
 */
HWTEST_F(SelinuxUnitTest, ReadRefreshInfo006, TestSize.Level1)
{
    RefreshInfo writeInfo;
    writeInfo.bundleName = "com.ohos.demo";
    writeInfo.uid = TEST_UID;
    auto pathInfo = std::make_shared<PathInfo>();
    pathInfo->target = TEST_TARGET1_PATH;
    pathInfo->finished = TEST_TARGET1_PATH;
    pathInfo->count = 1;
    pathInfo->done = false;
    writeInfo.paths[TEST_TARGET1_PATH] = pathInfo;

    ASSERT_EQ(true, CreateDirectory(RESTORECON_HAP_DATA_BASE + "/" + std::to_string(TEST_USERID)));
    EXPECT_EQ(SELINUX_SUCC, WriteRefreshInfo(writeInfo));

    RefreshInfo readInfo;
    readInfo.bundleName = "com.ohos.test";
    readInfo.uid = TEST_UID;
    std::vector<std::string> pathNameOrig;
    pathNameOrig.push_back(TEST_TARGET1_PATH);
    pathNameOrig.push_back(TEST_TARGET2_PATH);
    pathNameOrig.push_back(TEST_TARGET3_PATH);

    // pathNameOrig contains paths, part of which does not exist
    ASSERT_EQ(true, CreateDirectory(TEST_TARGET1_PATH));

    EXPECT_EQ(SELINUX_SUCC, ReadRefreshInfo(readInfo, pathNameOrig));
    ASSERT_EQ(1, readInfo.paths.size());
    ASSERT_NE(nullptr, readInfo.paths[TEST_TARGET1_PATH]);
    ASSERT_EQ(TEST_TARGET1_PATH, readInfo.paths[TEST_TARGET1_PATH]->target);
    ASSERT_EQ(true, readInfo.paths[TEST_TARGET1_PATH]->finished.empty());
    ASSERT_EQ(0, readInfo.paths[TEST_TARGET1_PATH]->count);
    ASSERT_EQ(false, readInfo.paths[TEST_TARGET1_PATH]->done);

    ASSERT_EQ(true, RemoveDirectory(TEST_TARGET1_PATH));
    ASSERT_EQ(0, RemoveFile(RESTORECON_HAP_DATA_FILE));
    ASSERT_EQ(true, RemoveDirectory(RESTORECON_HAP_DATA_BASE));
}

/**
 * @tc.name: ReadRefreshInfo007
 * @tc.desc: test ReadRefreshInfo with a json file of matching the bundle name, but the paths mismatch.
 * @tc.type: FUNC
 * @tc.require: 4622
 */
HWTEST_F(SelinuxUnitTest, ReadRefreshInfo007, TestSize.Level1)
{
    RefreshInfo writeInfo;
    writeInfo.bundleName = "com.ohos.test";
    writeInfo.uid = TEST_UID;
    auto pathInfo = std::make_shared<PathInfo>();
    pathInfo->target = TEST_TARGET5_PATH;
    pathInfo->finished = TEST_TARGET5_PATH;
    pathInfo->count = 1;
    pathInfo->done = false;
    writeInfo.paths[TEST_TARGET5_PATH] = pathInfo;

    ASSERT_EQ(true, CreateDirectory(RESTORECON_HAP_DATA_BASE + "/" + std::to_string(TEST_USERID)));
    EXPECT_EQ(SELINUX_SUCC, WriteRefreshInfo(writeInfo));

    RefreshInfo readInfo;
    readInfo.bundleName = "com.ohos.test";
    readInfo.uid = TEST_UID;
    std::vector<std::string> pathNameOrig;
    pathNameOrig.push_back(TEST_TARGET1_PATH);
    pathNameOrig.push_back(TEST_TARGET2_PATH);
    pathNameOrig.push_back(TEST_TARGET3_PATH);

    // pathNameOrig contains paths, part of which does not exist
    ASSERT_EQ(true, CreateDirectory(TEST_TARGET1_PATH));

    EXPECT_EQ(SELINUX_SUCC, ReadRefreshInfo(readInfo, pathNameOrig));
    ASSERT_EQ(1, readInfo.paths.size());
    ASSERT_EQ(TEST_TARGET1_PATH, readInfo.paths[TEST_TARGET1_PATH]->target);
    ASSERT_EQ(true, readInfo.paths[TEST_TARGET1_PATH]->finished.empty());
    ASSERT_EQ(0, readInfo.paths[TEST_TARGET1_PATH]->count);
    ASSERT_EQ(false, readInfo.paths[TEST_TARGET1_PATH]->done);

    ASSERT_EQ(true, RemoveDirectory(TEST_TARGET1_PATH));
    ASSERT_EQ(0, RemoveFile(RESTORECON_HAP_DATA_FILE));
    ASSERT_EQ(true, RemoveDirectory(RESTORECON_HAP_DATA_BASE));
}

/**
 * @tc.name: ReadRefreshInfo008
 * @tc.desc: test ReadRefreshInfo with a json file of matching the bundle name, the paths part match.
 * @tc.type: FUNC
 * @tc.require: 4622
 */
HWTEST_F(SelinuxUnitTest, ReadRefreshInfo008, TestSize.Level1)
{
    RefreshInfo writeInfo;
    writeInfo.bundleName = "com.ohos.test";
    writeInfo.uid = TEST_UID;
    auto pathInfo = std::make_shared<PathInfo>();
    pathInfo->target = TEST_TARGET1_PATH;
    pathInfo->finished = TEST_TARGET1_PATH;
    pathInfo->count = 1;
    pathInfo->done = false;
    writeInfo.paths[TEST_TARGET1_PATH] = pathInfo;

    ASSERT_EQ(true, CreateDirectory(RESTORECON_HAP_DATA_BASE + "/" + std::to_string(TEST_USERID)));
    EXPECT_EQ(SELINUX_SUCC, WriteRefreshInfo(writeInfo));

    RefreshInfo readInfo;
    readInfo.bundleName = "com.ohos.test";
    readInfo.uid = TEST_UID;
    std::vector<std::string> pathNameOrig;
    pathNameOrig.push_back(TEST_TARGET1_PATH);
    pathNameOrig.push_back(TEST_TARGET2_PATH);
    pathNameOrig.push_back(TEST_TARGET3_PATH);

    // pathNameOrig contains paths, part of which does not exist
    ASSERT_EQ(true, CreateDirectory(TEST_TARGET1_PATH));
    ASSERT_EQ(true, CreateDirectory(TEST_TARGET2_PATH));

    EXPECT_EQ(SELINUX_SUCC, ReadRefreshInfo(readInfo, pathNameOrig));
    ASSERT_EQ(2, readInfo.paths.size());
    ASSERT_NE(nullptr, readInfo.paths[TEST_TARGET1_PATH]);
    ASSERT_EQ(TEST_TARGET1_PATH, readInfo.paths[TEST_TARGET1_PATH]->target);
    ASSERT_EQ(TEST_TARGET1_PATH, readInfo.paths[TEST_TARGET1_PATH]->finished);
    ASSERT_EQ(1, readInfo.paths[TEST_TARGET1_PATH]->count);
    ASSERT_EQ(false, readInfo.paths[TEST_TARGET1_PATH]->done);
    ASSERT_NE(nullptr, readInfo.paths[TEST_TARGET2_PATH]);
    ASSERT_EQ(TEST_TARGET2_PATH, readInfo.paths[TEST_TARGET2_PATH]->target);
    ASSERT_EQ(true, readInfo.paths[TEST_TARGET2_PATH]->finished.empty());
    ASSERT_EQ(0, readInfo.paths[TEST_TARGET2_PATH]->count);
    ASSERT_EQ(false, readInfo.paths[TEST_TARGET2_PATH]->done);

    ASSERT_EQ(true, RemoveDirectory(TEST_TARGET1_PATH));
    ASSERT_EQ(true, RemoveDirectory(TEST_TARGET2_PATH));
    ASSERT_EQ(0, RemoveFile(RESTORECON_HAP_DATA_FILE));
    ASSERT_EQ(true, RemoveDirectory(RESTORECON_HAP_DATA_BASE));
}

/**
 * @tc.name: WriteRefreshInfo001
 * @tc.desc: test WriteRefreshInfo with invalid param.
 * @tc.type: FUNC
 * @tc.require: 4622
 */
HWTEST_F(SelinuxUnitTest, WriteRefreshInfo001, TestSize.Level1)
{
    RefreshInfo writeInfo;
    EXPECT_EQ(-SELINUX_ARG_INVALID, WriteRefreshInfo(writeInfo));
    writeInfo.bundleName = "com.ohos.test";
    EXPECT_EQ(-SELINUX_ARG_INVALID, WriteRefreshInfo(writeInfo));
    auto pathInfo = std::make_shared<PathInfo>();
    writeInfo.paths[TEST_TARGET1_PATH] = pathInfo;
    EXPECT_EQ(-SELINUX_ARG_INVALID, WriteRefreshInfo(writeInfo));
}

/**
 * @tc.name: WriteRefreshInfo002
 * @tc.desc: test WriteRefreshInfo without a json file, part done of paths are false.
 * @tc.type: FUNC
 * @tc.require: 4622
 */
HWTEST_F(SelinuxUnitTest, WriteRefreshInfo002, TestSize.Level1)
{
    RefreshInfo writeInfo;
    writeInfo.bundleName = "com.ohos.test";
    writeInfo.uid = TEST_UID;
    auto pathInfo1 = std::make_shared<PathInfo>();
    pathInfo1->target = TEST_TARGET1_PATH;
    pathInfo1->finished = TEST_TARGET1_PATH;
    pathInfo1->count = 1;
    pathInfo1->done = false;
    auto pathInfo2 = std::make_shared<PathInfo>();
    pathInfo2->target = TEST_TARGET2_PATH;
    pathInfo2->finished = TEST_TARGET2_PATH;
    pathInfo2->count = 1;
    pathInfo2->done = true;
    writeInfo.paths[TEST_TARGET1_PATH] = pathInfo1;
    writeInfo.paths[TEST_TARGET2_PATH] = pathInfo2;

    ASSERT_EQ(true, CreateDirectory(RESTORECON_HAP_DATA_BASE + "/" + std::to_string(TEST_USERID)));
    EXPECT_EQ(SELINUX_SUCC, WriteRefreshInfo(writeInfo));

    RefreshInfo readInfo = {
        .bundleName = "com.ohos.test",
        .uid = TEST_UID,
    };
    std::vector<std::string> pathName;
    pathName.push_back(TEST_TARGET1_PATH);
    pathName.push_back(TEST_TARGET2_PATH);

    ASSERT_EQ(true, CreateDirectory(TEST_TARGET1_PATH));
    ASSERT_EQ(true, CreateDirectory(TEST_TARGET2_PATH));

    EXPECT_EQ(SELINUX_SUCC, ReadRefreshInfo(readInfo, pathName));
    ASSERT_EQ(pathName.size(), readInfo.paths.size());
    ASSERT_NE(nullptr, readInfo.paths[TEST_TARGET1_PATH]);
    ASSERT_EQ(TEST_TARGET1_PATH, readInfo.paths[TEST_TARGET1_PATH]->target);
    ASSERT_EQ(TEST_TARGET1_PATH, readInfo.paths[TEST_TARGET1_PATH]->finished);
    ASSERT_EQ(1, readInfo.paths[TEST_TARGET1_PATH]->count);
    ASSERT_EQ(false, readInfo.paths[TEST_TARGET1_PATH]->done);
    ASSERT_NE(nullptr, readInfo.paths[TEST_TARGET2_PATH]);
    ASSERT_EQ(TEST_TARGET2_PATH, readInfo.paths[TEST_TARGET2_PATH]->target);
    ASSERT_EQ(TEST_TARGET2_PATH, readInfo.paths[TEST_TARGET2_PATH]->finished);
    ASSERT_EQ(1, readInfo.paths[TEST_TARGET2_PATH]->count);
    ASSERT_EQ(true, readInfo.paths[TEST_TARGET2_PATH]->done);

    ASSERT_EQ(true, RemoveDirectory(TEST_TARGET1_PATH));
    ASSERT_EQ(true, RemoveDirectory(TEST_TARGET2_PATH));
    ASSERT_EQ(0, RemoveFile(RESTORECON_HAP_DATA_FILE));
    ASSERT_EQ(true, RemoveDirectory(RESTORECON_HAP_DATA_BASE));
}

/**
 * @tc.name: WriteRefreshInfo003
 * @tc.desc: test WriteRefreshInfo without a json file, all done are true.
 * @tc.type: FUNC
 * @tc.require: 4622
 */
HWTEST_F(SelinuxUnitTest, WriteRefreshInfo003, TestSize.Level1)
{
    RefreshInfo writeInfo;
    writeInfo.bundleName = "com.ohos.test";
    writeInfo.uid = TEST_UID;
    auto pathInfo1 = std::make_shared<PathInfo>();
    pathInfo1->target = TEST_TARGET1_PATH;
    pathInfo1->done = true;
    auto pathInfo2 = std::make_shared<PathInfo>();
    pathInfo2->target = TEST_TARGET2_PATH;
    pathInfo2->done = true;
    writeInfo.paths[TEST_TARGET1_PATH] = pathInfo1;
    writeInfo.paths[TEST_TARGET2_PATH] = pathInfo2;

    ASSERT_EQ(true, CreateDirectory(RESTORECON_HAP_DATA_BASE + "/" + std::to_string(TEST_USERID)));
    EXPECT_EQ(SELINUX_SUCC, WriteRefreshInfo(writeInfo));

    RefreshInfo readInfo = {
        .bundleName = "com.ohos.test",
        .uid = TEST_UID,
    };
    std::vector<std::string> pathName;
    pathName.push_back(TEST_TARGET1_PATH);
    pathName.push_back(TEST_TARGET2_PATH);

    ASSERT_EQ(true, CreateDirectory(TEST_TARGET1_PATH));
    ASSERT_EQ(true, CreateDirectory(TEST_TARGET2_PATH));

    EXPECT_EQ(SELINUX_SUCC, ReadRefreshInfo(readInfo, pathName));
    ASSERT_EQ(pathName.size(), readInfo.paths.size());
    ASSERT_NE(nullptr, readInfo.paths[TEST_TARGET1_PATH]);
    ASSERT_EQ(TEST_TARGET1_PATH, readInfo.paths[TEST_TARGET1_PATH]->target);
    ASSERT_EQ(true, readInfo.paths[TEST_TARGET1_PATH]->finished.empty());
    ASSERT_EQ(0, readInfo.paths[TEST_TARGET1_PATH]->count);
    ASSERT_EQ(false, readInfo.paths[TEST_TARGET1_PATH]->done);
    ASSERT_NE(nullptr, readInfo.paths[TEST_TARGET2_PATH]);
    ASSERT_EQ(TEST_TARGET2_PATH, readInfo.paths[TEST_TARGET2_PATH]->target);
    ASSERT_EQ(true, readInfo.paths[TEST_TARGET2_PATH]->finished.empty());
    ASSERT_EQ(0, readInfo.paths[TEST_TARGET2_PATH]->count);
    ASSERT_EQ(false, readInfo.paths[TEST_TARGET2_PATH]->done);

    ASSERT_EQ(true, RemoveDirectory(TEST_TARGET1_PATH));
    ASSERT_EQ(true, RemoveDirectory(TEST_TARGET2_PATH));
    ASSERT_EQ(0, RemoveFile(RESTORECON_HAP_DATA_FILE));
    ASSERT_EQ(true, RemoveDirectory(RESTORECON_HAP_DATA_BASE));
}

/**
 * @tc.name: WriteRefreshInfo004
 * @tc.desc: test WriteRefreshInfo with a json file of wrong format.
 * @tc.type: FUNC
 * @tc.require: 4622
 */
HWTEST_F(SelinuxUnitTest, WriteRefreshInfo004, TestSize.Level1)
{
    // Create an empty json file
    ASSERT_EQ(true, CreateDirectory(RESTORECON_HAP_DATA_DIR));
    ASSERT_EQ(true, CreateCfgFile(RESTORECON_HAP_DATA_FILE));
    // Write something of not json format
    std::string content = R"([{"bundleName":"com.ohos.test","uid":20020087,"path":[]}])";
    std::vector<std::string> writeContent;
    writeContent.push_back(content);
    ASSERT_EQ(true, WriteFile(RESTORECON_HAP_DATA_FILE, writeContent));

    RefreshInfo writeInfo;
    writeInfo.bundleName = "com.ohos.test";
    writeInfo.uid = TEST_UID;
    auto pathInfo1 = std::make_shared<PathInfo>();
    pathInfo1->target = TEST_TARGET1_PATH;
    pathInfo1->done = true;
    auto pathInfo2 = std::make_shared<PathInfo>();
    pathInfo2->target = TEST_TARGET2_PATH;
    pathInfo2->done = false;
    writeInfo.paths[TEST_TARGET1_PATH] = pathInfo1;
    writeInfo.paths[TEST_TARGET2_PATH] = pathInfo2;

    EXPECT_EQ(-SELINUX_PTR_NULL, WriteRefreshInfo(writeInfo));

    ASSERT_EQ(true, RemoveDirectory(TEST_TARGET1_PATH));
    ASSERT_EQ(-1, RemoveFile(RESTORECON_HAP_DATA_FILE));
    ASSERT_EQ(true, RemoveDirectory(RESTORECON_HAP_DATA_BASE));
}

/**
 * @tc.name: WriteRefreshInfo005
 * @tc.desc: test WriteRefreshInfo with a json file, part of done of paths are false.
 * @tc.type: FUNC
 * @tc.require: 4622
 */
HWTEST_F(SelinuxUnitTest, WriteRefreshInfo005, TestSize.Level1)
{
    RefreshInfo writeInfo1;
    writeInfo1.bundleName = "com.ohos.test";
    writeInfo1.uid = TEST_UID;
    auto pathInfo1 = std::make_shared<PathInfo>();
    pathInfo1->target = TEST_TARGET1_PATH;
    pathInfo1->finished = TEST_TARGET1_PATH;
    pathInfo1->count = 1;
    pathInfo1->done = true;
    auto pathInfo2 = std::make_shared<PathInfo>();
    pathInfo2->target = TEST_TARGET2_PATH;
    pathInfo2->finished = TEST_TARGET2_PATH;
    pathInfo2->count = 1;
    pathInfo2->done = false;
    writeInfo1.paths[TEST_TARGET1_PATH] = pathInfo1;
    writeInfo1.paths[TEST_TARGET2_PATH] = pathInfo2;

    ASSERT_EQ(true, CreateDirectory(RESTORECON_HAP_DATA_BASE + "/" + std::to_string(TEST_USERID)));
    EXPECT_EQ(SELINUX_SUCC, WriteRefreshInfo(writeInfo1));

    RefreshInfo writeInfo2;
    writeInfo2.bundleName = "com.ohos.test";
    writeInfo2.uid = TEST_UID;
    auto pathInfo3 = std::make_shared<PathInfo>();
    pathInfo3->target = TEST_TARGET3_PATH;
    pathInfo3->finished = TEST_TARGET3_PATH;
    pathInfo3->count = 1;
    pathInfo3->done = false;
    auto pathInfo4 = std::make_shared<PathInfo>();
    pathInfo4->target = TEST_TARGET4_PATH;
    pathInfo4->done = true;
    writeInfo2.paths[TEST_TARGET3_PATH] = pathInfo3;
    writeInfo2.paths[TEST_TARGET4_PATH] = pathInfo4;
    EXPECT_EQ(SELINUX_SUCC, WriteRefreshInfo(writeInfo2));

    RefreshInfo readInfo = {
        .bundleName = "com.ohos.test",
        .uid = TEST_UID,
    };
    std::vector<std::string> pathName;
    pathName.push_back(TEST_TARGET1_PATH);
    pathName.push_back(TEST_TARGET2_PATH);
    pathName.push_back(TEST_TARGET3_PATH);
    pathName.push_back(TEST_TARGET4_PATH);

    ASSERT_EQ(true, CreateDirectory(TEST_TARGET1_PATH));
    ASSERT_EQ(true, CreateDirectory(TEST_TARGET2_PATH));
    ASSERT_EQ(true, CreateDirectory(TEST_TARGET3_PATH));
    ASSERT_EQ(true, CreateDirectory(TEST_TARGET4_PATH));

    EXPECT_EQ(SELINUX_SUCC, ReadRefreshInfo(readInfo, pathName));
    ASSERT_EQ(pathName.size(), readInfo.paths.size());
    ASSERT_NE(nullptr, readInfo.paths[TEST_TARGET1_PATH]);
    ASSERT_NE(nullptr, readInfo.paths[TEST_TARGET2_PATH]);
    ASSERT_NE(nullptr, readInfo.paths[TEST_TARGET3_PATH]);
    ASSERT_NE(nullptr, readInfo.paths[TEST_TARGET4_PATH]);
    ASSERT_EQ(TEST_TARGET1_PATH, readInfo.paths[TEST_TARGET1_PATH]->target);
    ASSERT_EQ(TEST_TARGET2_PATH, readInfo.paths[TEST_TARGET2_PATH]->target);
    ASSERT_EQ(TEST_TARGET3_PATH, readInfo.paths[TEST_TARGET3_PATH]->target);
    ASSERT_EQ(TEST_TARGET4_PATH, readInfo.paths[TEST_TARGET4_PATH]->target);
    ASSERT_EQ(true, readInfo.paths[TEST_TARGET1_PATH]->finished.empty());
    ASSERT_EQ(true, readInfo.paths[TEST_TARGET2_PATH]->finished.empty());
    ASSERT_EQ(false, readInfo.paths[TEST_TARGET3_PATH]->finished.empty());
    ASSERT_EQ(true, readInfo.paths[TEST_TARGET4_PATH]->finished.empty());
    ASSERT_EQ(TEST_TARGET3_PATH, readInfo.paths[TEST_TARGET3_PATH]->finished);
    ASSERT_EQ(false, readInfo.paths[TEST_TARGET1_PATH]->done);
    ASSERT_EQ(true, readInfo.paths[TEST_TARGET4_PATH]->done);

    ASSERT_EQ(true, RemoveDirectory(TEST_TARGET1_PATH));
    ASSERT_EQ(true, RemoveDirectory(TEST_TARGET2_PATH));
    ASSERT_EQ(true, RemoveDirectory(TEST_TARGET3_PATH));
    ASSERT_EQ(true, RemoveDirectory(TEST_TARGET4_PATH));
    ASSERT_EQ(0, RemoveFile(RESTORECON_HAP_DATA_FILE));
    ASSERT_EQ(true, RemoveDirectory(RESTORECON_HAP_DATA_BASE));
}

/**
 * @tc.name: WriteRefreshInfo007
 * @tc.desc: test WriteRefreshInfo with a json file, done all true.
 * @tc.type: FUNC
 * @tc.require: 4622
 */
HWTEST_F(SelinuxUnitTest, WriteRefreshInfo007, TestSize.Level1)
{
    RefreshInfo writeInfo1;
    writeInfo1.bundleName = "com.ohos.test";
    writeInfo1.uid = TEST_UID;
    auto pathInfo1 = std::make_shared<PathInfo>();
    pathInfo1->target = TEST_TARGET1_PATH;
    pathInfo1->finished = TEST_TARGET1_PATH;
    pathInfo1->count = 1;
    pathInfo1->done = true;
    auto pathInfo2 = std::make_shared<PathInfo>();
    pathInfo2->target = TEST_TARGET2_PATH;
    pathInfo2->finished = TEST_TARGET2_PATH;
    pathInfo2->count = 1;
    pathInfo2->done = false;
    writeInfo1.paths[TEST_TARGET1_PATH] = pathInfo1;
    writeInfo1.paths[TEST_TARGET2_PATH] = pathInfo2;

    ASSERT_EQ(true, CreateDirectory(RESTORECON_HAP_DATA_BASE + "/" + std::to_string(TEST_USERID)));
    EXPECT_EQ(SELINUX_SUCC, WriteRefreshInfo(writeInfo1));

    RefreshInfo writeInfo2;
    writeInfo2.bundleName = "com.ohos.test";
    writeInfo2.uid = TEST_UID;
    auto pathInfo3 = std::make_shared<PathInfo>();
    pathInfo3->target = TEST_TARGET3_PATH;
    pathInfo3->finished = TEST_TARGET3_PATH;
    pathInfo3->count = 1;
    pathInfo3->done = true;
    auto pathInfo4 = std::make_shared<PathInfo>();
    pathInfo4->target = TEST_TARGET4_PATH;
    pathInfo4->done = true;
    // done all true.
    writeInfo2.paths[TEST_TARGET3_PATH] = pathInfo3;
    writeInfo2.paths[TEST_TARGET4_PATH] = pathInfo4;
    EXPECT_EQ(SELINUX_SUCC, WriteRefreshInfo(writeInfo2));

    RefreshInfo readInfo = {
        .bundleName = "com.ohos.test",
        .uid = TEST_UID,
    };
    std::vector<std::string> pathName;
    pathName.push_back(TEST_TARGET1_PATH);
    pathName.push_back(TEST_TARGET2_PATH);
    pathName.push_back(TEST_TARGET3_PATH);
    pathName.push_back(TEST_TARGET4_PATH);

    ASSERT_EQ(true, CreateDirectory(TEST_TARGET1_PATH));
    ASSERT_EQ(true, CreateDirectory(TEST_TARGET2_PATH));
    ASSERT_EQ(true, CreateDirectory(TEST_TARGET3_PATH));
    ASSERT_EQ(true, CreateDirectory(TEST_TARGET4_PATH));

    EXPECT_EQ(SELINUX_SUCC, ReadRefreshInfo(readInfo, pathName));
    ASSERT_EQ(pathName.size(), readInfo.paths.size());
    ASSERT_EQ(TEST_TARGET1_PATH, readInfo.paths[TEST_TARGET1_PATH]->target);
    ASSERT_EQ(TEST_TARGET2_PATH, readInfo.paths[TEST_TARGET2_PATH]->target);
    ASSERT_EQ(TEST_TARGET3_PATH, readInfo.paths[TEST_TARGET3_PATH]->target);
    ASSERT_EQ(TEST_TARGET4_PATH, readInfo.paths[TEST_TARGET4_PATH]->target);
    ASSERT_EQ(true, readInfo.paths[TEST_TARGET1_PATH]->finished.empty());
    ASSERT_EQ(true, readInfo.paths[TEST_TARGET2_PATH]->finished.empty());
    ASSERT_EQ(true, readInfo.paths[TEST_TARGET3_PATH]->finished.empty());
    ASSERT_EQ(true, readInfo.paths[TEST_TARGET4_PATH]->finished.empty());
    ASSERT_EQ(false, readInfo.paths[TEST_TARGET1_PATH]->done);
    ASSERT_EQ(false, readInfo.paths[TEST_TARGET2_PATH]->done);
    ASSERT_EQ(false, readInfo.paths[TEST_TARGET3_PATH]->done);
    ASSERT_EQ(false, readInfo.paths[TEST_TARGET4_PATH]->done);

    ASSERT_EQ(true, RemoveDirectory(TEST_TARGET1_PATH));
    ASSERT_EQ(true, RemoveDirectory(TEST_TARGET2_PATH));
    ASSERT_EQ(true, RemoveDirectory(TEST_TARGET3_PATH));
    ASSERT_EQ(true, RemoveDirectory(TEST_TARGET4_PATH));
    ASSERT_EQ(0, RemoveFile(RESTORECON_HAP_DATA_FILE));
    ASSERT_EQ(true, RemoveDirectory(RESTORECON_HAP_DATA_BASE));
}

/**
 * @tc.name: DeleteRefreshInfo001
 * @tc.desc: test DeleteRefreshInfo.
 * @tc.type: FUNC
 * @tc.require: 4622
 */
HWTEST_F(SelinuxUnitTest, DeleteRefreshInfo001, TestSize.Level1)
{
    // DeleteRefreshInfo with invalid param.
    std::string bundleName = "";
    uint32_t uid = TEST_UID;
    EXPECT_EQ(-SELINUX_ARG_INVALID, DeleteRefreshInfo(bundleName, uid));

    // DeleteRefreshInfo with no json.
    bundleName = "com.ohos.test";
    EXPECT_EQ(SELINUX_SUCC, DeleteRefreshInfo(bundleName, uid));

    // create a json file.
    RefreshInfo writeInfo;
    writeInfo.bundleName = "com.ohos.test";
    writeInfo.uid = TEST_UID;
    auto pathInfo1 = std::make_shared<PathInfo>();
    pathInfo1->target = TEST_TARGET1_PATH;
    pathInfo1->finished = TEST_TARGET1_PATH;
    pathInfo1->count = 1;
    pathInfo1->done = true;
    auto pathInfo2 = std::make_shared<PathInfo>();
    pathInfo2->target = TEST_TARGET2_PATH;
    pathInfo2->finished = TEST_TARGET2_PATH;
    pathInfo2->count = 1;
    pathInfo2->done = false;
    writeInfo.paths[TEST_TARGET1_PATH] = pathInfo1;
    writeInfo.paths[TEST_TARGET2_PATH] = pathInfo2;

    ASSERT_EQ(true, CreateDirectory(RESTORECON_HAP_DATA_BASE + "/" + std::to_string(TEST_USERID)));
    EXPECT_EQ(SELINUX_SUCC, WriteRefreshInfo(writeInfo));

    RefreshInfo readInfo1 = {
        .bundleName = "com.ohos.test",
        .uid = TEST_UID,
    };
    std::vector<std::string> pathName;
    pathName.push_back(TEST_TARGET1_PATH);
    pathName.push_back(TEST_TARGET2_PATH);

    ASSERT_EQ(true, CreateDirectory(TEST_TARGET1_PATH));
    ASSERT_EQ(true, CreateDirectory(TEST_TARGET2_PATH));

    EXPECT_EQ(SELINUX_SUCC, ReadRefreshInfo(readInfo1, pathName));
    ASSERT_EQ(pathName.size(), readInfo1.paths.size());
    ASSERT_EQ(TEST_TARGET1_PATH, readInfo1.paths[TEST_TARGET1_PATH]->target);
    ASSERT_EQ(TEST_TARGET1_PATH, readInfo1.paths[TEST_TARGET1_PATH]->finished);
    ASSERT_EQ(1, readInfo1.paths[TEST_TARGET1_PATH]->count);
    ASSERT_EQ(true, readInfo1.paths[TEST_TARGET1_PATH]->done);
    ASSERT_EQ(TEST_TARGET2_PATH, readInfo1.paths[TEST_TARGET2_PATH]->target);
    ASSERT_EQ(TEST_TARGET2_PATH, readInfo1.paths[TEST_TARGET2_PATH]->finished);
    ASSERT_EQ(1, readInfo1.paths[TEST_TARGET2_PATH]->count);
    ASSERT_EQ(false, readInfo1.paths[TEST_TARGET2_PATH]->done);

    // DeleteRefreshInfo with a json of mismatching the bundleName.
    bundleName = "com.ohos.invalid";
    EXPECT_EQ(SELINUX_SUCC, DeleteRefreshInfo(bundleName, uid));

    RefreshInfo readInfo2 = {
        .bundleName = "com.ohos.test",
        .uid = TEST_UID,
    };
    EXPECT_EQ(SELINUX_SUCC, ReadRefreshInfo(readInfo2, pathName));
    ASSERT_EQ(pathName.size(), readInfo2.paths.size());
    ASSERT_EQ(TEST_TARGET1_PATH, readInfo2.paths[TEST_TARGET1_PATH]->target);
    ASSERT_EQ(TEST_TARGET1_PATH, readInfo2.paths[TEST_TARGET1_PATH]->finished);
    ASSERT_EQ(1, readInfo2.paths[TEST_TARGET1_PATH]->count);
    ASSERT_EQ(true, readInfo2.paths[TEST_TARGET1_PATH]->done);
    ASSERT_EQ(TEST_TARGET2_PATH, readInfo2.paths[TEST_TARGET2_PATH]->target);
    ASSERT_EQ(TEST_TARGET2_PATH, readInfo2.paths[TEST_TARGET2_PATH]->finished);
    ASSERT_EQ(1, readInfo2.paths[TEST_TARGET2_PATH]->count);
    ASSERT_EQ(false, readInfo2.paths[TEST_TARGET2_PATH]->done);

    // DeleteRefreshInfo with a json of matching the bundleName.
    bundleName = "com.ohos.test";
    EXPECT_EQ(SELINUX_SUCC, DeleteRefreshInfo(bundleName, uid));
    RefreshInfo readInfo3 = {
        .bundleName = "com.ohos.test",
        .uid = TEST_UID,
    };
    EXPECT_EQ(SELINUX_SUCC, ReadRefreshInfo(readInfo3, pathName));
    ASSERT_EQ(pathName.size(), readInfo3.paths.size());
    ASSERT_NE(nullptr, readInfo3.paths[TEST_TARGET1_PATH]);
    ASSERT_EQ(TEST_TARGET1_PATH, readInfo3.paths[TEST_TARGET1_PATH]->target);
    ASSERT_EQ(true, readInfo3.paths[TEST_TARGET1_PATH]->finished.empty());
    ASSERT_EQ(0, readInfo3.paths[TEST_TARGET1_PATH]->count);
    ASSERT_EQ(false, readInfo3.paths[TEST_TARGET1_PATH]->done);
    ASSERT_NE(nullptr, readInfo3.paths[TEST_TARGET2_PATH]);
    ASSERT_EQ(TEST_TARGET2_PATH, readInfo3.paths[TEST_TARGET2_PATH]->target);
    ASSERT_EQ(true, readInfo3.paths[TEST_TARGET2_PATH]->finished.empty());
    ASSERT_EQ(0, readInfo3.paths[TEST_TARGET2_PATH]->count);
    ASSERT_EQ(false, readInfo3.paths[TEST_TARGET2_PATH]->done);

    ASSERT_EQ(true, RemoveDirectory(TEST_TARGET1_PATH));
    ASSERT_EQ(true, RemoveDirectory(TEST_TARGET2_PATH));
    ASSERT_EQ(0, RemoveFile(RESTORECON_HAP_DATA_FILE));
    ASSERT_EQ(true, RemoveDirectory(RESTORECON_HAP_DATA_BASE));
}
} // namespace SelinuxUnitTest
} // namespace Security
} // namespace OHOS
