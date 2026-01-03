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

#include "hapfile_test.h"
#include <string>
#include <thread>
#include <selinux/selinux.h>
#include "selinux_error.h"
#include "test_common.h"
#include "restore_task.h"
#include "seharmony_hisysevent_adapter.h"

namespace OHOS {
namespace Security {
namespace SelinuxUnitTest {
using namespace testing::ext;
using namespace Selinux;

const static int SLEEP_SECOND = 2;
const static int SLEEP_DURATION_1_3MS = 1300;
const static int SLEEP_DURATION_1MS = 1000;
const static std::string BASE_PATH = "/data/app/el2/100/base/";
const static std::string TEST_HAP_PATH = BASE_PATH + "com.ohos.selftest/";
const static std::string NORMAL_APL = "normal";
const static std::string SYSTEM_CORE_APL = "system_core";
const static std::string TEST_HAP_BUNDLE_NAME = "com.hap.selftest";
const static std::string TEST_HAP_BUNDLE_NAME_2 = "com.hap.selftest.other";
const static std::string SEHAP_CONTEXTS_FILE = "/data/test/sehap_contexts";
const static int LOOP_COUNT = 1000;

#ifdef MCS_ENABLE
const static std::string PRODUCT_CONFIG = "/data/test/product_config";
static const std::string DEFAULT_MCS_HAP_FILE_PREFIX_TEST = "mcsHapFileEnabled=";
static bool g_mcsHapFileEnabledTest = false;
#endif

static bool g_runningTasks = false;

static void GenerateTestFile()
{
    std::vector<std::string> sehapInfo = {
        "apl=system_core domain=system_core_hap type=system_core_hap_data_file",
        "apl=system_basic domain=system_basic_hap type=system_basic_hap_data_file",
        "apl=normal domain=normal_hap type=appdat levelFrom=all user=o",
    };
    ASSERT_EQ(true, WriteFile(SEHAP_CONTEXTS_FILE, sehapInfo));
    std::vector<std::string> productConfig = {
        "defaultLevelFrom=user",
        "mcsHapFileEnabled=true",
    };
    ASSERT_EQ(true, WriteFile(PRODUCT_CONFIG, productConfig));
}

void HapFileTest::SetUpTestCase()
{
    GenerateTestFile();
}

void HapFileTest::TearDownTestCase()
{
}

void HapFileTest::SetUp() {}

void HapFileTest::TearDown() {}

void HapFileTest::CreateDataFile() const {}

/**
 * @tc.name: CheckCurrenPath001
 * @tc.desc: test CheckCurrenPath with different path.
 * @tc.type: FUNC
 * @tc.require: 4622
 */
HWTEST_F(HapFileTest, CheckCurrenPath001, TestSize.Level0)
{
    bool skipping = true;
    EXPECT_EQ(CheckCurrenPath("/system/lib", "/system/lib64", skipping), SKIP_SUB);
    EXPECT_EQ(skipping, true);
    EXPECT_EQ(CheckCurrenPath("/system/lib/lib.so", "/system/lib64", skipping), SKIP_SUB);
    EXPECT_EQ(skipping, true);
    EXPECT_EQ(CheckCurrenPath("/system/bin", "/system/lib64", skipping), SKIP_SUB);
    EXPECT_EQ(skipping, true);
    EXPECT_EQ(CheckCurrenPath("/system/bin/tool", "/system/lib64", skipping), SKIP_SUB);
    EXPECT_EQ(skipping, true);

    EXPECT_EQ(CheckCurrenPath("/system/lib", "/system/lib64/lib.so", skipping), SKIP_SUB);
    EXPECT_EQ(skipping, true);
    EXPECT_EQ(CheckCurrenPath("/system/lib/lib.so", "/system/lib64/lib.so", skipping), SKIP_SUB);
    EXPECT_EQ(skipping, true);
    EXPECT_EQ(CheckCurrenPath("/system/bin", "/system/lib64/lib.so", skipping), SKIP_SUB);
    EXPECT_EQ(skipping, true);
    EXPECT_EQ(CheckCurrenPath("/system/bin/tool", "/system/lib64/lib.so", skipping), SKIP_SUB);
    EXPECT_EQ(skipping, true);

    EXPECT_EQ(CheckCurrenPath("/system/lib64", "/system/lib64", skipping), SKIP_THIS);
    EXPECT_EQ(skipping, true);
    EXPECT_EQ(CheckCurrenPath("/system", "/system/lib64", skipping), SKIP_THIS);
    EXPECT_EQ(skipping, true);

    EXPECT_EQ(CheckCurrenPath("/system/lib64/lib.so", "/system/lib64", skipping), TO_RESTORE);
    EXPECT_EQ(skipping, false);
    skipping = true;
    EXPECT_EQ(CheckCurrenPath("/system/service", "/system/lib64", skipping), TO_RESTORE);
    EXPECT_EQ(skipping, false);
    skipping = true;
    EXPECT_EQ(CheckCurrenPath("/system/ser/data", "/system/lib64", skipping), TO_RESTORE);
    EXPECT_EQ(skipping, false);
    skipping = true;
    EXPECT_EQ(CheckCurrenPath("/system/service/data", "/system/lib64", skipping), TO_RESTORE);
    EXPECT_EQ(skipping, false);
    skipping = true;
    EXPECT_EQ(CheckCurrenPath("/system/lib64", "/system/lib", skipping), TO_RESTORE);
    EXPECT_EQ(skipping, false);
    skipping = true;
    EXPECT_EQ(CheckCurrenPath("/system/lib64/lib.so", "/system/lib", skipping), TO_RESTORE);
    EXPECT_EQ(skipping, false);
}

/**
 * @tc.name: InheritExternInfo001
 * @tc.desc: test InheritExternInfo with same type.
 * @tc.type: FUNC
 * @tc.require: 4622
 */
HWTEST_F(HapFileTest, InheritExternInfo001, TestSize.Level0)
{
    const char *oldContext = "u:object_r:app_data_file:s0:c1,c2,c3,c4,c5";
    const char *newContext = "u:object_r:app_data_file:s0";
    char *finalContext = nullptr;
    // same type returns SELINUX_SUCC and nullptr finalContext
    EXPECT_EQ(InheritExternInfo(oldContext, newContext, &finalContext), SELINUX_SUCC);
    EXPECT_EQ(finalContext, nullptr);
}

/**
 * @tc.name: InheritExternInfo002
 * @tc.desc: test InheritExternInfo with different type.
 * @tc.type: FUNC
 * @tc.require: 4622
 */
HWTEST_F(HapFileTest, InheritExternInfo002, TestSize.Level0)
{
    const char *oldContext = "u:object_r:old_type:s1:c1,c2,c3,c4,c5";
    const char *newContext = "u:object_r:new_type:s0";
    char *finalContext = nullptr;
    EXPECT_EQ(InheritExternInfo(oldContext, newContext, &finalContext), SELINUX_SUCC);
    ASSERT_NE(finalContext, nullptr);

    context_t finalCon = context_new(finalContext);
    ASSERT_NE(finalCon, nullptr);
    EXPECT_EQ(std::string(context_user_get(finalCon)), "u");
    EXPECT_EQ(std::string(context_role_get(finalCon)), "object_r");
    EXPECT_EQ(std::string(context_type_get(finalCon)), "new_type");
    EXPECT_EQ(std::string(context_range_get(finalCon)), "s1:c1,c2,c3,c4,c5");

    context_free(finalCon);
    free(finalContext);
}

/**
 * @tc.name: AnonymizePath001
 * @tc.desc: test AnonymizePath with various paths.
 * @tc.type: FUNC
 * @tc.require: 4622
 */
HWTEST_F(HapFileTest, AnonymizePath001, TestSize.Level0)
{
    std::string path1 = "/abc/df";
    EXPECT_EQ(AnonymizePath(path1), "/a*c/d*");

    std::string path2 = "/acbd/ef";
    EXPECT_EQ(AnonymizePath(path2), "/a*b*/e*");

    std::string path3 = "/abc/com.abc.abc";
    EXPECT_EQ(AnonymizePath(path3), "/a*c/c*m*a*c*a*c");

    std::string path4 = "no_slash_data";
    EXPECT_EQ(AnonymizePath(path4), "n*_*l*s*_*a*a");

    const char *path5 = "/system/lib";
    EXPECT_EQ(AnonymizePath(path5), "/s*s*e*/l*b");
}

/**
 * @tc.name: AnonymizePathList001
 * @tc.desc: test AnonymizePathList.
 * @tc.type: FUNC
 * @tc.require: 4622
 */
HWTEST_F(HapFileTest, AnonymizePathList001, TestSize.Level0)
{
    std::vector<std::string> paths = {"/data/app", "/abc/df"};
    std::vector<std::string> result = AnonymizePathList(paths);
    ASSERT_EQ(result.size(), 2);
    EXPECT_EQ(result[0], "/d*t*/a*p");
    EXPECT_EQ(result[1], "/a*c/d*");
}

void CreateFiles(const std::string &basepath, std::vector<std::string> &filePath)
{
    std::vector<std::string> filename = {
        "aa",
        "aaa",
        "aab",
        "ab",
        "abb",
        "ba",
    };
    filePath.push_back(basepath);
    for (size_t i = 0; i < filename.size(); i++) {
        std::string dirname = basepath + "/" + filename[i];
        filePath.push_back(dirname);
        std::cout << "dirname " << dirname <<std::endl;
        EXPECT_TRUE(CreateDirectory(dirname));
        for (size_t j = 0; j < filename.size(); j++) {
            std::string subdir = dirname + "/" + filename[j];
            std::cout << "subdir " << subdir <<std::endl;
            EXPECT_TRUE(CreateDirectory(subdir));
            filePath.push_back(subdir);
        }
    }
}

/**
 * @tc.name: RestoreTask001
 * @tc.desc: test RestoreTask of stop
 * @tc.type: FUNC
 * @tc.require: 4622
 */
HWTEST_F(HapFileTest, RestoreTask001, TestSize.Level1)
{
    std::string testFilePath = "/data/test/demo1";
    EXPECT_TRUE(CreateDirectory(testFilePath));
    std::vector<std::string> filePaths;
    CreateFiles(testFilePath, filePaths);
    std::shared_ptr<RestoreTask> task =
        std::make_shared<RestoreTask>("test_bundle", 0);

    auto pathInfo = std::make_shared<PathInfo>();
    task->info.paths[testFilePath] = pathInfo;
    pathInfo->target = testFilePath;

    // restore all successfully
    EXPECT_EQ(task->RestoreTraversal(testFilePath),
        SELINUX_SUCC);
    EXPECT_EQ(pathInfo->count, filePaths.size());
    EXPECT_EQ(task->successCount, filePaths.size());
    EXPECT_TRUE(pathInfo->done);
    EXPECT_EQ(pathInfo->finished, filePaths[filePaths.size() - 1]);

    // retore skip if done
    EXPECT_EQ(task->RestoreTraversal(testFilePath),
        SELINUX_SUCC);
    EXPECT_EQ(pathInfo->count, filePaths.size());
    EXPECT_EQ(task->successCount, filePaths.size());

    // restore all successfully with initial counts
    pathInfo->done = false;
    pathInfo->finished = "";
    EXPECT_EQ(task->RestoreTraversal(testFilePath),
        SELINUX_SUCC);
    EXPECT_EQ(pathInfo->count, filePaths.size() * 2);
    EXPECT_EQ(task->successCount, filePaths.size() * 2);

    for (size_t i = 0; i < filePaths.size(); ++i) {
        pathInfo->done = false;
        pathInfo->finished = filePaths[i];
        pathInfo->count = 0;
        task->successCount = 0;
        EXPECT_EQ(task->RestoreTraversal(testFilePath),
            SELINUX_SUCC);
        EXPECT_EQ(pathInfo->count, filePaths.size() - i - 1);
        EXPECT_EQ(task->successCount, filePaths.size() - i - 1);
    }

    RemoveDirectory(testFilePath);
}


/**
 * @tc.name: RestoreTask002
 * @tc.desc: test RestoreTask with not target path
 * @tc.type: FUNC
 * @tc.require: 4622
 */
HWTEST_F(HapFileTest, RestoreTask002, TestSize.Level0)
{
    std::string testFilePath = "/data/test/demo1";
    std::shared_ptr<RestoreTask> task =
        std::make_shared<RestoreTask>("test_bundle", 0);
    auto pathInfo = std::make_shared<PathInfo>();
    task->info.paths[testFilePath] = pathInfo;
    pathInfo->target = testFilePath;
        EXPECT_EQ(task->RestoreTraversal("/data/test/demo2"),
        -SELINUX_ARG_INVALID);
}

/**
 * @tc.name: RestoreTask003
 * @tc.desc: test RestoreTask with not found path
 * @tc.type: FUNC
 * @tc.require: 4622
 */
HWTEST_F(HapFileTest, RestoreTask003, TestSize.Level0)
{
    std::string testFilePath = "/data/test/demo1";
    std::shared_ptr<RestoreTask> task =
        std::make_shared<RestoreTask>("test_bundle", 0);
    auto pathInfo = std::make_shared<PathInfo>();
    task->info.paths[testFilePath] = pathInfo;
    pathInfo->target = testFilePath;
    // path not found, but fts_open returns ok
    EXPECT_EQ(task->RestoreTraversal(testFilePath), SELINUX_SUCC);
}

/**
 * @tc.name: RestoreTask004
 * @tc.desc: test stopping RestoreTask
 * @tc.type: FUNC
 * @tc.require: 4622
 */
HWTEST_F(HapFileTest, RestoreTask004, TestSize.Level0)
{
    std::string testFilePath = "/data/test/demo1";
    std::shared_ptr<RestoreTask> task =
        std::make_shared<RestoreTask>("test_bundle", 0);
    EXPECT_TRUE(task->TryToStop(UPDATE, true));
    auto pathInfo = std::make_shared<PathInfo>();
    task->info.paths[testFilePath] = pathInfo;
    pathInfo->target = testFilePath;
    EXPECT_EQ(task->RestoreTraversal(testFilePath),
        -SELINUX_RESTORECON_TASK_STOPPED);
    EXPECT_TRUE(task->IsInterrupted());
    EXPECT_FALSE(pathInfo->done);
}

/**
 * @tc.name: RestoreTask005
 * @tc.desc: test RestoreTask of stop
 * @tc.type: FUNC
 * @tc.require: 4622
 */
HWTEST_F(HapFileTest, RestoreTask005, TestSize.Level1)
{
    std::shared_ptr<RestoreTask> task =
        std::make_shared<RestoreTask>("test_bundle", 0);
    EXPECT_EQ(task->info.bundleName, "test_bundle");
    EXPECT_EQ(task->info.uid, 0);
    EXPECT_TRUE(task->TryToStop(UPDATE, true));
    EXPECT_TRUE(task->IsStopping());
    EXPECT_EQ(task->GetShouldSave(), true);
    EXPECT_EQ(task->GetStopReason(), UPDATE);

    EXPECT_TRUE(task->TryToStop(DELETE, false));
    EXPECT_EQ(task->GetShouldSave(), false);
    EXPECT_EQ(task->GetStopReason(), DELETE);

    // cannot change to busy
    EXPECT_FALSE(task->TryToStop(BUSY, true));
    EXPECT_EQ(task->GetShouldSave(), false);
    EXPECT_EQ(task->GetStopReason(), DELETE);
}

/**
 * @tc.name: HapFileRestoreContextTest001
 * @tc.desc: test HapFileRestoreContext
 * @tc.type: FUNC
 * @tc.require: 4622
 */
HWTEST_F(HapFileTest, HapFileRestoreContextTest001, TestSize.Level0)
{
    std::string myTestPath = "/data/test/selinux_unittest_001/";
    RemoveDirectory(myTestPath);

    HapFileInfo hapFileInfo = {
        .pathNameOrig = {},
        .apl = SYSTEM_CORE_APL,
        .packageName = TEST_HAP_BUNDLE_NAME,
        .flags = 0,
        .hapFlags = 1,
        .uid = 100
    };

    HapFileRestoreContext::GetInstance().StopSetFileCon(hapFileInfo, DELETE);

    ResultInfo info;
    EXPECT_EQ(HapFileRestoreContext::GetInstance().SetFileConForce(hapFileInfo, info),
        SELINUX_SUCC);

    hapFileInfo.apl = NORMAL_APL;
    hapFileInfo.packageName = "";
    EXPECT_EQ(HapFileRestoreContext::GetInstance().SetFileConForce(hapFileInfo, info),
        -SELINUX_ARG_INVALID);

    hapFileInfo.packageName = TEST_HAP_BUNDLE_NAME;
    EXPECT_EQ(HapFileRestoreContext::GetInstance().SetFileConForce(hapFileInfo, info),
        -SELINUX_ARG_INVALID);

    // // path not found
    hapFileInfo.pathNameOrig.push_back(myTestPath + "not_exist");
    EXPECT_EQ(HapFileRestoreContext::GetInstance().SetFileConForce(hapFileInfo, info),
        -SELINUX_RESTORECON_TASK_INVALID_PATHS);

    EXPECT_TRUE(CreateDirectory(myTestPath));
    hapFileInfo.pathNameOrig.clear();
    hapFileInfo.pathNameOrig.push_back(myTestPath);
    
    EXPECT_EQ(HapFileRestoreContext::GetInstance().SetFileConForce(hapFileInfo, info),
        SELINUX_SUCC);
    EXPECT_EQ(info.currentCount, 1);
    EXPECT_EQ(info.totalCount, 1);
    
    RemoveDirectory(myTestPath);
    HapFileRestoreContext::GetInstance().StopSetFileCon(hapFileInfo, DELETE);
}

/**
 * @tc.name: HapFileRestoreContextTest002
 * @tc.desc: test HapFileRestoreContext of StopSetFileCon
 * @tc.type: FUNC
 * @tc.require: 4622
 */
HWTEST_F(HapFileTest, HapFileRestoreContextTest002, TestSize.Level0)
{
    HapFileInfo hapFileInfo = {
        .pathNameOrig = {},
        .apl = NORMAL_APL,
        .packageName = TEST_HAP_BUNDLE_NAME,
        .flags = 0,
        .hapFlags = 1,
    };
    // no task, app is appdat, noting to do
    EXPECT_EQ(HapFileRestoreContext::GetInstance().StopSetFileCon(hapFileInfo, UPDATE),
        SELINUX_SUCC);

    // task is runng, app is appdat, to stop
    std::shared_ptr<RestoreTask> task =
        std::make_shared<RestoreTask>(TEST_HAP_BUNDLE_NAME, 0);
    HapFileRestoreContext::GetInstance().restoreTask_ = task;
    EXPECT_EQ(HapFileRestoreContext::GetInstance().StopSetFileCon(hapFileInfo, UPDATE),
        SELINUX_SUCC);
    EXPECT_TRUE(task->IsStopping());
    EXPECT_TRUE(task->GetShouldSave());
    EXPECT_EQ(task->GetStopReason(), UPDATE);
    HapFileRestoreContext::GetInstance().restoreTask_ = nullptr;

    task = std::make_shared<RestoreTask>(TEST_HAP_BUNDLE_NAME, 0);
    HapFileRestoreContext::GetInstance().restoreTask_ = task;
    EXPECT_EQ(HapFileRestoreContext::GetInstance().StopSetFileCon(hapFileInfo, BUSY),
        SELINUX_SUCC);
    EXPECT_TRUE(task->IsStopping());
    EXPECT_TRUE(task->GetShouldSave());
    EXPECT_EQ(task->GetStopReason(), BUSY);
    HapFileRestoreContext::GetInstance().restoreTask_ = nullptr;

    task = std::make_shared<RestoreTask>(TEST_HAP_BUNDLE_NAME, 0);
    HapFileRestoreContext::GetInstance().restoreTask_ = task;
    EXPECT_EQ(HapFileRestoreContext::GetInstance().StopSetFileCon(hapFileInfo, DELETE),
        SELINUX_SUCC);
    EXPECT_TRUE(task->IsStopping());
    EXPECT_FALSE(task->GetShouldSave());
    EXPECT_EQ(task->GetStopReason(), DELETE);
    HapFileRestoreContext::GetInstance().restoreTask_ = nullptr;

    // context is change, to delete
    hapFileInfo.apl = SYSTEM_CORE_APL;
        task = std::make_shared<RestoreTask>(TEST_HAP_BUNDLE_NAME, 0);
    HapFileRestoreContext::GetInstance().restoreTask_ = task;
    EXPECT_EQ(HapFileRestoreContext::GetInstance().StopSetFileCon(hapFileInfo, UPDATE),
        SELINUX_SUCC);
    EXPECT_TRUE(task->IsStopping());
    EXPECT_FALSE(task->GetShouldSave());
    EXPECT_EQ(task->GetStopReason(), UPDATE);
    HapFileRestoreContext::GetInstance().restoreTask_ = nullptr;
    hapFileInfo.apl = NORMAL_APL;

    // busy and then delete, reason is change
    task = std::make_shared<RestoreTask>(TEST_HAP_BUNDLE_NAME, 0);
    HapFileRestoreContext::GetInstance().restoreTask_ = task;
    EXPECT_EQ(HapFileRestoreContext::GetInstance().StopSetFileCon(hapFileInfo, BUSY),
        SELINUX_SUCC);
    EXPECT_TRUE(task->IsStopping());
    EXPECT_TRUE(task->GetShouldSave());
    EXPECT_EQ(task->GetStopReason(), BUSY);
    EXPECT_EQ(HapFileRestoreContext::GetInstance().StopSetFileCon(hapFileInfo, DELETE),
        SELINUX_SUCC);
    EXPECT_TRUE(task->IsStopping());
    EXPECT_FALSE(task->GetShouldSave());
    EXPECT_EQ(task->GetStopReason(), DELETE);
    HapFileRestoreContext::GetInstance().restoreTask_ = nullptr;

    // delete and then busy, reason is not change
    task = std::make_shared<RestoreTask>(TEST_HAP_BUNDLE_NAME, 0);
    HapFileRestoreContext::GetInstance().restoreTask_ = task;
    EXPECT_EQ(HapFileRestoreContext::GetInstance().StopSetFileCon(hapFileInfo, DELETE),
        SELINUX_SUCC);
    EXPECT_TRUE(task->IsStopping());
    EXPECT_FALSE(task->GetShouldSave());
    EXPECT_EQ(task->GetStopReason(), DELETE);
    EXPECT_EQ(HapFileRestoreContext::GetInstance().StopSetFileCon(hapFileInfo, BUSY),
        SELINUX_SUCC);
    EXPECT_TRUE(task->IsStopping());
    EXPECT_FALSE(task->GetShouldSave());
    EXPECT_EQ(task->GetStopReason(), DELETE);
    HapFileRestoreContext::GetInstance().restoreTask_ = nullptr;
}

/**
 * @tc.name: HapFileRestoreContextTest003
 * @tc.desc: StopSetFileCon with no or unmatched task
 * @tc.type: FUNC
 * @tc.require: 4622
 */
HWTEST_F(HapFileTest, HapFileRestoreContextTest003, TestSize.Level0)
{
    HapFileInfo hapFileInfo = {
        .pathNameOrig = {},
        .apl = NORMAL_APL,
        .packageName = TEST_HAP_BUNDLE_NAME,
        .flags = 0,
        .hapFlags = 1,
    };
    // no task, try to delete
    EXPECT_EQ(HapFileRestoreContext::GetInstance().StopSetFileCon(hapFileInfo, DELETE),
        SELINUX_SUCC);

    // no task, noting todo
    EXPECT_EQ(HapFileRestoreContext::GetInstance().StopSetFileCon(hapFileInfo, BUSY),
        SELINUX_SUCC);
    EXPECT_EQ(HapFileRestoreContext::GetInstance().StopSetFileCon(hapFileInfo, UPDATE),
        SELINUX_SUCC);

    // delete and then busy, reason is not change
    auto task = std::make_shared<RestoreTask>(TEST_HAP_BUNDLE_NAME, 0);
    HapFileRestoreContext::GetInstance().restoreTask_ = task;
    // task unmatch, nothing to do
    HapFileInfo hapFileInfo2 = {
        .pathNameOrig = {},
        .apl = NORMAL_APL,
        .packageName = TEST_HAP_BUNDLE_NAME_2,
        .flags = 0,
        .hapFlags = 1,
    };
    EXPECT_EQ(HapFileRestoreContext::GetInstance().StopSetFileCon(hapFileInfo2, DELETE),
        SELINUX_SUCC);
    EXPECT_FALSE(task->IsStopping());
    EXPECT_TRUE(task->GetShouldSave());
    EXPECT_EQ(task->GetStopReason(), NONE);

    EXPECT_EQ(HapFileRestoreContext::GetInstance().StopSetFileCon(hapFileInfo2, UPDATE),
        SELINUX_SUCC);
    EXPECT_FALSE(task->IsStopping());
    EXPECT_TRUE(task->GetShouldSave());
    EXPECT_EQ(task->GetStopReason(), NONE);

    EXPECT_EQ(HapFileRestoreContext::GetInstance().StopSetFileCon(hapFileInfo2, BUSY),
        SELINUX_SUCC);
    EXPECT_FALSE(task->IsStopping());
    EXPECT_TRUE(task->GetShouldSave());
    EXPECT_EQ(task->GetStopReason(), NONE);
}

/**
 * @tc.name: HapFileRestoreContextTest004
 * @tc.desc: StopSetFileCon with no or unmatched task
 * @tc.type: FUNC
 * @tc.require: 4622
 */
HWTEST_F(HapFileTest, HapFileRestoreContextTest004, TestSize.Level0)
{
    HapFileInfo hapFileInfo = {
        .pathNameOrig = {TEST_HAP_PATH},
        .apl = NORMAL_APL,
        .packageName = TEST_HAP_BUNDLE_NAME,
        .flags = 0,
        .hapFlags = 1,
        .uid = 200001
    };
    auto task1 = std::make_shared<RestoreTask>(TEST_HAP_BUNDLE_NAME, hapFileInfo.uid);
    HapFileRestoreContext::GetInstance().restoreTask_ = task1;

    // cannot start again
    ResultInfo info;
    EXPECT_EQ(HapFileRestoreContext::GetInstance().SetFileConForce(hapFileInfo, info),
        -SELINUX_RESTORECON_TASK_ALREADY_RUNNING);

    EXPECT_TRUE(CreateDirectory(TEST_HAP_PATH));
    char realPath[PATH_MAX + 1];
    EXPECT_NE(realpath(TEST_HAP_PATH.c_str(), realPath), nullptr);
    std::string targetPath(realPath);

    // process a stopping task
    auto pathInfo = std::make_shared<PathInfo>();
    task1->info.paths[targetPath] = pathInfo;
    pathInfo->target = targetPath;

    EXPECT_EQ(HapFileRestoreContext::GetInstance().StopSetFileCon(hapFileInfo, UPDATE),
        SELINUX_SUCC);
    EXPECT_EQ(HapFileRestoreContext::GetInstance().ProcessRestorePath(task1,
        TEST_HAP_PATH, hapFileInfo), -SELINUX_RESTORECON_TASK_STOPPED);
    EXPECT_EQ(task1->IsInterrupted(), true);
    pathInfo->finished = targetPath;
    // to write file
    HapFileRestoreContext::GetInstance().FinishRestoreTask(hapFileInfo, info);
    RefreshInfo loadedInfo1;
    loadedInfo1.bundleName = hapFileInfo.packageName;
    loadedInfo1.uid = hapFileInfo.uid;
    std::vector<std::string> paths1 = hapFileInfo.pathNameOrig;
    EXPECT_EQ(ReadRefreshInfo(loadedInfo1, paths1), 0);
    EXPECT_EQ(loadedInfo1.paths.empty(), false);
    EXPECT_EQ(loadedInfo1.paths[targetPath]->done, false);
    // becanse of last path is targetPath, finished is ""
    EXPECT_EQ(loadedInfo1.paths[targetPath]->finished, "");

    auto task2 = std::make_shared<RestoreTask>(TEST_HAP_BUNDLE_NAME, hapFileInfo.uid);
    task2->info.paths[targetPath] = std::make_shared<PathInfo>();
    task2->info.paths[targetPath]->target = targetPath;
    HapFileRestoreContext::GetInstance().restoreTask_ = task2;
    EXPECT_EQ(HapFileRestoreContext::GetInstance().ProcessRestorePath(task2, TEST_HAP_PATH, hapFileInfo), SELINUX_SUCC);
    EXPECT_EQ(task2->IsInterrupted(), false);
    HapFileRestoreContext::GetInstance().FinishRestoreTask(hapFileInfo, info);
    RefreshInfo loadedInfo2;
    loadedInfo2.bundleName = hapFileInfo.packageName;
    loadedInfo2.uid = hapFileInfo.uid;
    std::vector<std::string> paths2 = hapFileInfo.pathNameOrig;
    ReadRefreshInfo(loadedInfo2, paths2);
    EXPECT_EQ(loadedInfo2.paths[targetPath]->finished.empty(), true);
    EXPECT_EQ(loadedInfo2.paths[targetPath]->done, false);

    auto task3 = std::make_shared<RestoreTask>(TEST_HAP_BUNDLE_NAME, hapFileInfo.uid);
    task3->info.paths[targetPath] = std::make_shared<PathInfo>();
    task3->info.paths[targetPath]->target = targetPath;
    HapFileRestoreContext::GetInstance().restoreTask_ = task3;
    EXPECT_EQ(HapFileRestoreContext::GetInstance().StopSetFileCon(hapFileInfo, DELETE), SELINUX_SUCC);
    EXPECT_EQ(HapFileRestoreContext::GetInstance().ProcessRestorePath(task3,
        TEST_HAP_PATH, hapFileInfo), -SELINUX_RESTORECON_TASK_STOPPED);
    EXPECT_EQ(task3->IsInterrupted(), true);
    HapFileRestoreContext::GetInstance().FinishRestoreTask(hapFileInfo, info);
    RefreshInfo loadedInfo3;
    loadedInfo3.bundleName = hapFileInfo.packageName;
    loadedInfo3.uid = hapFileInfo.uid;
    std::vector<std::string> paths3 = hapFileInfo.pathNameOrig;
    ReadRefreshInfo(loadedInfo3, paths3);
    EXPECT_EQ(loadedInfo3.paths[targetPath]->finished.empty(), true);
    EXPECT_EQ(loadedInfo3.paths[targetPath]->done, false);

    RemoveDirectory(TEST_HAP_PATH);
}

void GenerateHapFiles(const std::string& basepath)
{
    const int32_t count = 100;
    for (int32_t i = 0; i < count; ++i) {
        std::string dirname = basepath + "/dir_" + std::to_string(i);
        EXPECT_TRUE(CreateDirectory(dirname));
        for (int32_t j = 0; j < count; ++j) {
            std::string subdir = dirname + "/file_" + std::to_string(j);
            EXPECT_TRUE(CreateDirectory(subdir));
        }
    }
}

void LoopStartRestoreTask()
{
    HapFileInfo hapFileInfo = {
        .pathNameOrig = {TEST_HAP_PATH},
        .apl = NORMAL_APL,
        .packageName = TEST_HAP_BUNDLE_NAME,
        .flags = 0,
        .hapFlags = 1,
        .uid = 200001
    };
    ResultInfo info;
    const int32_t count = 100;
    g_runningTasks = true;
    for (int32_t i = 0; i < count; ++i) {
        HapFileRestoreContext::GetInstance().SetFileConForce(hapFileInfo, info);
        EXPECT_EQ(HapFileRestoreContext::GetInstance().restoreTask_, nullptr);
    }
    g_runningTasks = false;
}

void LoopStopRestoreTask()
{
    HapFileInfo hapFileInfo = {
        .pathNameOrig = {TEST_HAP_PATH},
        .apl = NORMAL_APL,
        .packageName = TEST_HAP_BUNDLE_NAME,
        .flags = 0,
        .hapFlags = 1,
        .uid = 200001
    };
    for (int32_t i = 0; i < LOOP_COUNT; ++i) {
        StopReason reason = static_cast<StopReason>(i % 3 + 1);
        EXPECT_EQ(HapFileRestoreContext::GetInstance().StopSetFileCon(hapFileInfo, reason),
            SELINUX_SUCC);
        usleep(SLEEP_DURATION_1_3MS);
        if (!g_runningTasks) {
            break;
        }
    }
}

void LoopStopRestoreUnRelatedTask()
{
    HapFileInfo hapFileInfo = {
        .pathNameOrig = {TEST_HAP_PATH},
        .apl = NORMAL_APL,
        .packageName = TEST_HAP_BUNDLE_NAME,
        .flags = 0,
        .hapFlags = 1,
        .uid = 200001
    };
    for (int32_t i = 0; i < LOOP_COUNT; ++i) {
        StopReason reason = static_cast<StopReason>(i % 3 + 1);
        hapFileInfo.uid = i;
        EXPECT_EQ(HapFileRestoreContext::GetInstance().StopSetFileCon(hapFileInfo, reason),
            SELINUX_SUCC);
        usleep(SLEEP_DURATION_1MS);
        if (!g_runningTasks) {
            break;
        }
    }
}

/**
 * @tc.name: HapFileRestoreContextTest005
 * @tc.desc: HapFileRestoreContextTest in parallel
 * @tc.type: FUNC
 * @tc.require: 4622
 */
HWTEST_F(HapFileTest, HapFileRestoreContextTest005, TestSize.Level2)
{
    GenerateHapFiles(TEST_HAP_PATH);
    std::thread t1(LoopStartRestoreTask);
    std::thread t2(LoopStopRestoreTask);
    std::thread t3(LoopStopRestoreUnRelatedTask);

    t1.join();
    t2.join();
    t3.join();
    RemoveDirectory(TEST_HAP_PATH);
}
} // namespace SelinuxUnitTest
} // namespace Security
} // namespace OHOS
