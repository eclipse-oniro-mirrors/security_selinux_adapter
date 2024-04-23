/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "selinux_log.h"
#include "securec.h"
#include "hilog/log.h"


#undef LOG_DOMAIN
#undef LOG_TAG
static const unsigned int LOG_DOMAIN = 0xD005A03;
static const char* LOG_TAG = "Selinux";

#define MAX_LOG_BUFF_LEN 1024

static int g_logLevel = SELINUX_HILOG_ERROR;

void SetSelinuxHilogLevel(int logLevel)
{
    g_logLevel = logLevel;
}

int SelinuxHilog(int logLevel, const char *fmt, ...)
{
    if (logLevel != SELINUX_HILOG_AVC && logLevel > g_logLevel) {
        return -1;
    }

    char *buf = (char *)malloc(MAX_LOG_BUFF_LEN);
    if (buf == NULL) {
        HILOG_ERROR(LOG_CORE, "selinux log malloc fail");
        return -1;
    }
    (void)memset_s(buf, MAX_LOG_BUFF_LEN, 0, MAX_LOG_BUFF_LEN);

    va_list ap;
    va_start(ap, fmt);
    if (vsnprintf_s(buf, MAX_LOG_BUFF_LEN, MAX_LOG_BUFF_LEN - 1, fmt, ap) < 0) {
        HILOG_ERROR(LOG_CORE, "selinux log concatenate error.");
        free(buf);
        buf = NULL;
        va_end(ap);
        return -1;
    }
    va_end(ap);

    switch (logLevel) {
        case SELINUX_HILOG_INFO:
            HILOG_INFO(LOG_CORE, "%{public}s\n", buf);
            break;
        case SELINUX_HILOG_WARN:
            HILOG_WARN(LOG_CORE, "%{public}s\n", buf);
            break;
        case SELINUX_HILOG_ERROR:
        case SELINUX_HILOG_AVC:
            HILOG_ERROR(LOG_CORE, "%{public}s\n", buf);
            break;
        default:
            free(buf);
            buf = NULL;
            return -1;
    }

    free(buf);
    buf = NULL;
    return 0;
}
