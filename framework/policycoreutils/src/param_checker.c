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

#include "param_checker.h"
#include <fcntl.h>
#include <unistd.h>
#include "errno.h"
#include "securec.h"
#include "selinux_error.h"
#include "selinux_klog.h"
#include "src/callbacks.h"

static pthread_once_t g_setLogOnce = PTHREAD_ONCE_INIT;
#define BUF_SIZE 512

typedef struct AuditMsg {
    const struct ucred *ucred;
    const char *name;
} AuditMsg;

static int SelinuxAuditCallback(void *data, security_class_t cls, char *buf, size_t len)
{
    if (data == NULL || buf == NULL || len == 0) {
        return -1;
    }
    AuditMsg *msg = (AuditMsg *)data;
    if (!msg->name || !msg->ucred) {
        selinux_log(SELINUX_ERROR, "Selinux audit msg invalid argument\n");
        return -1;
    }
    if (snprintf_s(buf, len, len - 1, "parameter=%s pid=%d uid=%u gid=%u", msg->name, msg->ucred->pid, msg->ucred->uid,
                   msg->ucred->gid) <= 0) {
        return -1;
    }
    return 0;
}

static void SelinuxSetCallback(void)
{
    SetSelinuxKmsgLevel(SELINUX_KWARN);
    union selinux_callback cb;
    cb.func_log = SelinuxKmsg;
    selinux_set_callback(SELINUX_CB_LOG, cb);
    cb.func_audit = SelinuxAuditCallback;
    selinux_set_callback(SELINUX_CB_AUDIT, cb);
}

static int CheckPerm(const char *paraName, const char *srcContext, const char *destContext, const struct ucred *uc)
{
    if (srcContext == NULL || uc == NULL) {
        selinux_log(SELINUX_ERROR, "args empty!\n");
        return -SELINUX_PTR_NULL;
    }
    selinux_log(SELINUX_INFO, "srcContext[%s] is setting param[%s] destContext[%s]\n", srcContext, paraName,
                destContext);
    AuditMsg msg;
    msg.name = paraName;
    msg.ucred = uc;
    int res = selinux_check_access(srcContext, destContext, "parameter_service", "set", &msg);
    return res == 0 ? SELINUX_SUCC : -SELINUX_PERMISSION_DENY;
}

void SetInitSelinuxLog(void)
{
    if (getpid() == 1) {
        __selinux_once(g_setLogOnce, SelinuxSetCallback);
    }
}

int SetParamCheck(const char *paraName, const char *destContext, const SrcInfo *info)
{
    if (paraName == NULL || destContext == NULL || info == NULL) {
        selinux_log(SELINUX_ERROR, "input param is null!\n");
        return -SELINUX_PTR_NULL;
    }

    char *srcContext = NULL;
    int rc = getpeercon(info->sockFd, &srcContext);
    if (rc < 0) {
        selinux_log(SELINUX_ERROR, "getpeercon failed: %s\n", strerror(errno));
        return -SELINUX_GET_CONTEXT_ERROR;
    }

    int res = CheckPerm(paraName, srcContext, destContext, &(info->uc));
    freecon(srcContext);
    return res;
}
