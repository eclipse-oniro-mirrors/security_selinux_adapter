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

#include "selinux_parameter.h"
#include <fcntl.h>
#include <pthread.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <unistd.h>
#include "errno.h"
#include "selinux_error.h"
#include "contexts_trie.h"

static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;
static const char DEFAULT_CONTEXT[] = "u:object_r:default_param:s0";
static const int INVALID_INDEX = -1;
static ParamContextsTrie *g_contextsTrie = NULL;
static ParamContextsList *g_contextsList = NULL;

static int ParameterContextsLoad(int isInit)
{
    if (isInit) { // process init will load parameter_contexts to shared memory
        int res = LoadParameterContextsToSharedMem();
        if (res != 0) {
            return res;
        }
    }
    if (!ReadParamFromSharedMem(&g_contextsTrie, &g_contextsList)) { // other process load parameters from shared memory
        return -SELINUX_CONTEXTS_FILE_LOAD_ERROR;
    }
    return 0;
}

int InitParamSelinux(int isInit)
{
    pthread_mutex_lock(&g_mutex);
    if (g_contextsTrie != NULL) {
        pthread_mutex_unlock(&g_mutex);
        return 0;
    }
    int res = ParameterContextsLoad(isInit);
    pthread_mutex_unlock(&g_mutex);
    return res;
}

void DestroyParamList(ParamContextsList **list)
{
    if (list == NULL) {
        return;
    }
    ParamContextsList *tmpNode;
    ParamContextsList *listHead = *list;
    while (listHead != NULL) {
        tmpNode = listHead->next;
        free(listHead);
        listHead = tmpNode;
    }
    *list = NULL;
    return;
}

ParamContextsList *GetParamList()
{
    if (g_contextsList == NULL) {
        return NULL;
    }
    return g_contextsList;
}

const char *GetParamLabel(const char *paraName)
{
    if (paraName == NULL || g_contextsTrie == NULL) {
        return DEFAULT_CONTEXT;
    }
    return SearchFromParamTrie(g_contextsTrie, paraName);
}

int GetParamLabelIndex(const char *paraName)
{
    if ((paraName == NULL) || (g_contextsTrie == NULL)) {
        return INVALID_INDEX;
    }
    return GetLabelIndex(g_contextsTrie, paraName);
}
