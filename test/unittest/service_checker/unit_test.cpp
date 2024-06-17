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
#include "selinux_error.h"
#include "service_checker.h"
#include "hdf_service_checker.h"
#include "test_common.h"

namespace OHOS {
namespace Security {
namespace SelinuxUnitTest {
using namespace testing::ext;
using namespace Selinux;
const static std::string TEST_SERVICE_NAME = "test_service";
const static std::string DEFAULT_SERVICE = "default_service";
const static std::string DEFAULT_HDF_SERVICE = "default_hdf_service";

void SelinuxUnitTest::SetUpTestCase()
{
    // make test case clean
}

void SelinuxUnitTest::TearDownTestCase() {}

void SelinuxUnitTest::SetUp() {}

void SelinuxUnitTest::TearDown() {}

void SelinuxUnitTest::CreateDataFile() const {}

/**
 * @tc.name: HdfListServiceCheck001
 * @tc.desc: HdfListServiceCheck test.
 * @tc.type: FUNC
 * @tc.require:AR000GJSDS
 */
HWTEST_F(SelinuxUnitTest, HdfListServiceCheck001, TestSize.Level1)
{
    ASSERT_EQ(-SELINUX_GET_CONTEXT_ERROR, HdfListServiceCheck(-1));
    ASSERT_EQ(SELINUX_SUCC, HdfListServiceCheck(getpid()));
    std::string cmd = "hilog -T Selinux -x | grep 'avc:  denied  { list } for service=hdf_devmgr_class pid=" +
                      std::to_string(getpid()) + "' | grep 'tclass=hdf_devmgr_class'";
    std::string cmdRes = RunCommand(cmd);
    ASSERT_TRUE(cmdRes.find("hdf_devmgr_class") != std::string::npos);
}

/**
 * @tc.name: HdfGetServiceCheck001
 * @tc.desc: HdfGetServiceCheck test.
 * @tc.type: FUNC
 * @tc.require:AR000GJSDS
 */
HWTEST_F(SelinuxUnitTest, HdfGetServiceCheck001, TestSize.Level1)
{
    ASSERT_EQ(-SELINUX_GET_CONTEXT_ERROR, HdfGetServiceCheck(-1, TEST_SERVICE_NAME.c_str()));
    ASSERT_EQ(-SELINUX_PTR_NULL, HdfGetServiceCheck(getpid(), nullptr));
    ASSERT_EQ(SELINUX_SUCC, HdfGetServiceCheck(getpid(), TEST_SERVICE_NAME.c_str()));
    std::string cmd = "hilog -T Selinux -x | grep 'avc:  denied  { get } for service=" + TEST_SERVICE_NAME +
                      " pid=" + std::to_string(getpid()) + "' | grep 'tclass=hdf_devmgr_class'";
    std::string cmdRes = RunCommand(cmd);
    ASSERT_TRUE(cmdRes.find(TEST_SERVICE_NAME) != std::string::npos);
}

/**
 * @tc.name: HdfAddServiceCheck001
 * @tc.desc: HdfAddServiceCheck test.
 * @tc.type: FUNC
 * @tc.require:AR000GJSDS
 */
HWTEST_F(SelinuxUnitTest, HdfAddServiceCheck001, TestSize.Level1)
{
    ASSERT_EQ(-SELINUX_GET_CONTEXT_ERROR, HdfAddServiceCheck(-1, TEST_SERVICE_NAME.c_str()));
    ASSERT_EQ(-SELINUX_PTR_NULL, HdfAddServiceCheck(getpid(), nullptr));
    ASSERT_EQ(SELINUX_SUCC, HdfAddServiceCheck(getpid(), TEST_SERVICE_NAME.c_str()));
    std::string cmd = "hilog -T Selinux -x | grep 'avc:  denied  { add } for service=" + TEST_SERVICE_NAME +
                      " pid=" + std::to_string(getpid()) + "' | grep 'tclass=hdf_devmgr_class'";
    std::string cmdRes = RunCommand(cmd);
    ASSERT_TRUE(cmdRes.find(TEST_SERVICE_NAME) != std::string::npos);
}

/**
 * @tc.name: ListServiceCheck001
 * @tc.desc: ListServiceCheck test.
 * @tc.type: FUNC
 * @tc.require:AR000GJSDS
 */
HWTEST_F(SelinuxUnitTest, ListServiceCheck001, TestSize.Level1)
{
    ServiceChecker service(false);
    ASSERT_EQ(-SELINUX_GET_CONTEXT_ERROR, service.ListServiceCheck(-1));
    ASSERT_EQ(SELINUX_SUCC, service.ListServiceCheck(getpid()));
    std::string cmd =
        "hilog -T Selinux -x | grep 'avc:  denied  { list } for service=samgr_class pid=" + std::to_string(getpid()) +
        "' | grep 'tclass=samgr_class'";
    std::string cmdRes = RunCommand(cmd);
    ASSERT_TRUE(cmdRes.find("samgr_class") != std::string::npos);
}

/**
 * @tc.name: GetServiceCheck001
 * @tc.desc: GetServiceCheck test.
 * @tc.type: FUNC
 * @tc.require:AR000GJSDS
 */
HWTEST_F(SelinuxUnitTest, GetServiceCheck001, TestSize.Level1)
{
    ServiceChecker service(false);
    ASSERT_EQ(-SELINUX_GET_CONTEXT_ERROR, service.GetServiceCheck(-1, TEST_SERVICE_NAME));
    ASSERT_EQ(-SELINUX_ARG_INVALID, service.GetServiceCheck(getpid(), ""));
    ASSERT_EQ(SELINUX_SUCC, service.GetServiceCheck(getpid(), TEST_SERVICE_NAME));
    std::string cmd = "hilog -T Selinux -x | grep 'avc:  denied  { get } for service=" + TEST_SERVICE_NAME +
                      " pid=" + std::to_string(getpid()) + "' | grep 'tclass=samgr_class'";
    std::string cmdRes = RunCommand(cmd);
    ASSERT_TRUE(cmdRes.find(TEST_SERVICE_NAME) != std::string::npos);
}

/**
 * @tc.name: GetRemoteServiceCheck001
 * @tc.desc: GetRemoteServiceCheck test.
 * @tc.type: FUNC
 * @tc.require:AR000GJSDS
 */
HWTEST_F(SelinuxUnitTest, GetRemoteServiceCheck001, TestSize.Level1)
{
    ServiceChecker service(false);
    ASSERT_EQ(-SELINUX_GET_CONTEXT_ERROR, service.GetRemoteServiceCheck(-1, TEST_SERVICE_NAME));
    ASSERT_EQ(-SELINUX_ARG_INVALID, service.GetRemoteServiceCheck(getpid(), ""));
    ASSERT_EQ(SELINUX_SUCC, service.GetRemoteServiceCheck(getpid(), TEST_SERVICE_NAME));
    std::string cmd = "hilog -T Selinux -x | grep 'avc:  denied  { get_remote } for service=" + TEST_SERVICE_NAME +
                      " pid=" + std::to_string(getpid()) + "' | grep 'tclass=samgr_class'";
    std::string cmdRes = RunCommand(cmd);
    ASSERT_TRUE(cmdRes.find(TEST_SERVICE_NAME) != std::string::npos);
}

/**
 * @tc.name: AddServiceCheck001
 * @tc.desc: AddServiceCheck test.
 * @tc.type: FUNC
 * @tc.require:AR000GJSDS
 */
HWTEST_F(SelinuxUnitTest, AddServiceCheck001, TestSize.Level1)
{
    ServiceChecker service(false);
    ASSERT_EQ(-SELINUX_GET_CONTEXT_ERROR, service.AddServiceCheck(-1, TEST_SERVICE_NAME));
    ASSERT_EQ(-SELINUX_ARG_INVALID, service.AddServiceCheck(getpid(), ""));
    ASSERT_EQ(SELINUX_SUCC, service.AddServiceCheck(getpid(), TEST_SERVICE_NAME));
    std::string cmd = "hilog -T Selinux -x | grep 'avc:  denied  { add } for service=" + TEST_SERVICE_NAME +
                      " pid=" + std::to_string(getpid()) + "' | grep 'tclass=samgr_class'";
    std::string cmdRes = RunCommand(cmd);
    ASSERT_TRUE(cmdRes.find(TEST_SERVICE_NAME) != std::string::npos);
}
} // namespace SelinuxUnitTest
} // namespace Security
} // namespace OHOS
