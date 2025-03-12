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
#include "selinux_share_mem.h"
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <unistd.h>
#include <stdio.h>

void *InitSharedMem(const char *fileName, uint32_t spaceSize, bool readOnly)
{
    if (fileName == NULL || spaceSize == 0) {
        return NULL;
    }
    int mode = readOnly ? O_RDONLY : O_CREAT | O_RDWR | O_TRUNC;
    int fd = open(fileName, mode, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (fd < 0) {
        return NULL;
    }

    int prot = PROT_READ;
    if (!readOnly) {
        prot = PROT_READ | PROT_WRITE;
        ftruncate(fd, spaceSize);
    }
    void *sharedMem = (void *)mmap(NULL, spaceSize, prot, MAP_SHARED, fd, 0);
    if (sharedMem == MAP_FAILED) {
        close(fd);
        return NULL;
    }
    close(fd);
    return sharedMem;
}

void UnmapSharedMem(char *sharedMem, uint32_t dataSize)
{
    if (sharedMem == NULL || dataSize == 0) {
        return;
    }
    munmap(sharedMem, dataSize);
}

void WriteSharedMem(char *sharedMem, const char *data, uint32_t length)
{
    if (sharedMem == NULL || data == NULL || length == 0) {
        return;
    }
    memcpy(sharedMem, data, length);
    msync(sharedMem, length, MS_SYNC);
}

char *ReadSharedMem(char *sharedMem, uint32_t length)
{
    if (sharedMem == NULL) {
        return NULL;
    }
    if (strlen(sharedMem) != length) {
        return NULL;
    }
    return sharedMem;
}
