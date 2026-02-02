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

#ifndef HAP_RESTORECON_HAPFILE_TEST_H
#define HAP_RESTORECON_HAPFILE_TEST_H

#include <gtest/gtest.h>
#define protected public
#include "hap_restorecon.h"
#undef protected

namespace OHOS {
namespace Security {
namespace SelinuxUnitTest {
class HapFileTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp();

    void TearDown();

    void CreateDataFile() const;

    HapContext test;
};
} // namespace Selinux
} // namespace Security
} // namespace OHOS
#endif // HAP_RESTORECON_SELINUX_UNIT_TEST_H
