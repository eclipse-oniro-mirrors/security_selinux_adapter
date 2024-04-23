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

#include "test_common.h"
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>

namespace OHOS {
namespace Security {
namespace SelinuxUnitTest {
bool CreateDirectory(const std::string &path)
{
    std::string::size_type index = 0;
    do {
        std::string subPath;
        index = path.find('/', index + 1);
        if (index == std::string::npos) {
            subPath = path;
        } else {
            subPath = path.substr(0, index);
        }

        if (access(subPath.c_str(), F_OK) != 0) {
            if (mkdir(subPath.c_str(), S_IRWXU) != 0) {
                return false;
            }
        }
    } while (index != std::string::npos);

    return access(path.c_str(), F_OK) == 0;
}

bool RemoveDirectory(const std::string &path)
{
    std::string curDir = ".";
    std::string upDir = "..";
    DIR *dirp;
    struct dirent *dp;
    struct stat dirStat;

    if (access(path.c_str(), F_OK) != 0) {
        return true;
    }
    int statRet = stat(path.c_str(), &dirStat);
    if (statRet < 0) {
        return false;
    }

    if (S_ISREG(dirStat.st_mode)) {
        remove(path.c_str());
    } else if (S_ISDIR(dirStat.st_mode)) {
        dirp = opendir(path.c_str());
        while ((dp = readdir(dirp)) != nullptr) {
            if ((curDir == std::string(dp->d_name)) || (upDir == std::string(dp->d_name))) {
                continue;
            }
            std::string dirName = path + "/" + std::string(dp->d_name);
            RemoveDirectory(dirName.c_str());
        }
        closedir(dirp);
        rmdir(path.c_str());
    } else {
        return false;
    }
    return true;
}

std::string GetDirectory(const std::string &path)
{
    std::string dir = "";
    size_t index = path.rfind('/');
    if (index != std::string::npos) {
        dir = path.substr(0, index);
    }
    return dir;
}

bool CreateFile(const std::string &path)
{
    std::string dir = GetDirectory(path);
    if (dir != "") {
        if (!CreateDirectory(dir)) {
            return false;
        }
    }

    if (access(path.c_str(), F_OK) != 0) {
        FILE *fp = fopen(path.c_str(), "w");
        if (fp == nullptr) {
            return false;
        }
        fclose(fp);
    }

    return access(path.c_str(), F_OK) == 0;
}

bool CopyFile(const std::string &src, const std::string &des)
{
    std::ifstream fin(src, std::ifstream::in || std::ifstream::binary);
    if (!fin) {
        return false;
    }
    std::ofstream fout(des, std::ofstream::out || std::ofstream::binary);
    if (!fout) {
        fin.close();
        return false;
    }
    fout << fin.rdbuf();
    if (!fout) {
        fin.close();
        fout.close();
        return false;
    }
    fin.close();
    fout.close();
    return true;
}

bool WriteFile(const std::string &file, const std::vector<std::string> &info)
{
    std::ofstream fout(file, std::ofstream::out || std::ofstream::app);
    if (!fout) {
        return false;
    }
    for (auto i : info) {
        fout << i << std::endl;
    }
    if (!fout) {
        fout.close();
        return false;
    }
    fout.close();
    return true;
}

int RenameFile(const std::string &src, const std::string &des)
{
    return rename(src.c_str(), des.c_str());
}

std::string RunCommand(const std::string &command)
{
    std::string result = "";
    FILE *file = popen(command.c_str(), "r");

    if (file != nullptr) {
        char commandResult[1024] = {0};
        while ((fgets(commandResult, sizeof(commandResult), file)) != nullptr) {
            result.append(commandResult);
        }
        pclose(file);
        file = nullptr;
    }
    return result;
}
} // namespace SelinuxUnitTest
} // namespace Security
} // namespace OHOS
