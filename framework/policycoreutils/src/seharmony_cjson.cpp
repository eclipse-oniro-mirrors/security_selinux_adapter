/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "seharmony_cjson.h"

#include <cstdint>
#include <fcntl.h>
#include <fstream>
#include <memory>
#include <string>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>

#include "seharmony_hisysevent_adapter.h"
#include "selinux_error.h"
#include "selinux_log.h"
#include "selinux/selinux.h"
#include "src/callbacks.h"

using namespace Selinux;

namespace  {
#define RECURSE_FLAG_TRUE 1
#define PRINT_FORMAT_LEVEL_MAX 500
#define CHECK_BOOL_RETURN(func, res) \
    if ((func) == false) {           \
        return (res);                \
    }
#define CHECK_NULL_RETURN(func, res) \
    if ((func) == nullptr) {         \
        return (res);                \
    }

#ifdef SELINUX_CJSON_TEST
static const std::string RESTORECON_HAP_DATA_BASE = "/data/seharmony_cjson_test/";
#else
static const std::string RESTORECON_HAP_DATA_BASE = "/data/service/el2/";
#endif
static const std::string HAP_JSON_FILE = "restorecon_hap_data.json";
static const std::string JSON_FILE_SUB_DIR = "/bms/bundle_manager_service";
static const std::string JSON_FILE_SUB_INFO = "/bms/bundle_manager_service/restorecon_hap_data.json";
static const std::string BUNDLE_KEY_NAME = "bundlename";
static const std::string UID_KEY_NAME = "uid";
static const std::string PATHS_KEY_NAME = "paths";
static const std::string TARGET_KEY_NAME = "target";
static const std::string FINISHED_KEY_NAME = "finished";
static const std::string COUNT_KEY_NAME = "count";
static const std::string DONE_KEY_NAME = "done";
static constexpr uint32_t BASE_USER_RANGE = 200000;
static std::mutex g_accessJsonLock;
static constexpr unsigned int SECURITY_SELINUX_ADAPTER = 0xC05A03;
}

CJsonUnique CreateJsonFromString(const std::string& jsonStr)
{
    if (jsonStr.empty()) {
        return nullptr;
    }
    CJsonUnique aPtr(cJSON_Parse(jsonStr.c_str()), FreeJson);
    return aPtr;
}

CJsonUnique CreateJson(void)
{
    CJsonUnique aPtr(cJSON_CreateObject(), FreeJson);
    return aPtr;
}

CJsonUnique CreateJsonArray(void)
{
    CJsonUnique aPtr(cJSON_CreateArray(), FreeJson);
    return aPtr;
}

void FreeJson(CJson* jsonObj)
{
    cJSON_Delete(jsonObj);
    jsonObj = nullptr;
}

std::string PackJsonToString(const CJson* jsonObj)
{
    char* ptr = cJSON_PrintUnformatted(jsonObj);
    if (ptr == nullptr) {
        return std::string();
    }
    std::string ret = std::string(ptr);
    FreeJsonString(ptr);
    return ret;
}

std::string PackJsonToString(const CJsonUnique& jsonObj)
{
    return PackJsonToString(jsonObj.get());
}

void FreeJsonString(char* jsonStr)
{
    if (jsonStr != nullptr) {
        cJSON_free(jsonStr);
    }
}

CJson* GetArrayFromJson(const CJson* jsonObj, const std::string& key)
{
    if ((jsonObj == nullptr) || key.empty()) {
        return nullptr;
    }

    CJson* objValue = cJSON_GetObjectItemCaseSensitive(jsonObj, key.c_str());
    if (objValue != nullptr && cJSON_IsArray(objValue)) {
        return objValue;
    }
    return nullptr;
}

CJson* GetArrayFromJson(CJsonUnique& jsonObj, const std::string& key)
{
    return GetArrayFromJson(jsonObj.get(), key);
}

bool GetStringFromJson(const CJson* jsonObj, const std::string& key, std::string& out)
{
    if (jsonObj == nullptr) {
        return false;
    }

    cJSON* jsonObjTmp = cJSON_GetObjectItemCaseSensitive(jsonObj, key.c_str());
    if (jsonObjTmp != nullptr && cJSON_IsString(jsonObjTmp)) {
        out = cJSON_GetStringValue(jsonObjTmp);
        return true;
    }
    return false;
}

bool GetUnsignedIntFromJson(const CJson* jsonObj, const std::string& key, uint32_t& value)
{
    if ((jsonObj == nullptr) || key.empty()) {
        return false;
    }

    CJson* jsonObjTmp = cJSON_GetObjectItemCaseSensitive(jsonObj, key.c_str());
    if (jsonObjTmp != nullptr && cJSON_IsNumber(jsonObjTmp)) {
        value = static_cast<uint32_t>(cJSON_GetNumberValue(jsonObjTmp));
        return true;
    }
    return false;
}

bool GetUnsignedIntFromJson(const CJsonUnique& jsonObj, const std::string& key, uint32_t& value)
{
    return GetUnsignedIntFromJson(jsonObj.get(), key, value);
}

bool GetBoolFromJson(const CJson* jsonObj, const std::string& key, bool& value)
{
    if ((jsonObj == nullptr) || key.empty()) {
        return false;
    }

    CJson* jsonObjTmp = cJSON_GetObjectItemCaseSensitive(jsonObj, key.c_str());
    if (jsonObjTmp != nullptr && cJSON_IsBool(jsonObjTmp)) {
        value = cJSON_IsTrue(jsonObjTmp) ? true : false;
        return true;
    }
    return false;
}

bool GetBoolFromJson(const CJsonUnique& jsonObj, const std::string& key, bool& value)
{
    return GetBoolFromJson(jsonObj.get(), key, value);
}

bool AddObjToJson(CJson* jsonObj, const std::string& key, const CJson* childObj)
{
    if ((jsonObj == nullptr) || key.empty() || (childObj == nullptr)) {
        return false;
    }

    CJson* tmpObj = cJSON_Duplicate(childObj, RECURSE_FLAG_TRUE);
    if (tmpObj == nullptr) {
        return false;
    }

    CJson* objInJson = cJSON_GetObjectItemCaseSensitive(jsonObj, key.c_str());
    if (objInJson == nullptr) {
        if (!cJSON_AddItemToObject(jsonObj, key.c_str(), tmpObj)) {
            cJSON_Delete(tmpObj);
            return false;
        }
    } else {
        if (!cJSON_ReplaceItemInObjectCaseSensitive(jsonObj, key.c_str(), tmpObj)) {
            cJSON_Delete(tmpObj);
            return false;
        }
    }
    return true;
}

bool AddObjToJson(CJsonUnique& jsonObj, const std::string& key, CJsonUnique& childObj)
{
    return AddObjToJson(jsonObj.get(), key, childObj.get());
}

bool AddObjToArray(CJson* jsonArr, CJson* item)
{
    if ((jsonArr == nullptr) || (item == nullptr)) {
        return false;
    }

    if (!cJSON_IsArray(jsonArr)) {
        return false;
    }

    CJson* tmpObj = cJSON_Duplicate(item, RECURSE_FLAG_TRUE);
    if (tmpObj == nullptr) {
        return false;
    }
    return cJSON_AddItemToArray(jsonArr, tmpObj);
}

bool AddObjToArray(CJsonUnique& jsonArr, CJsonUnique& item)
{
    return AddObjToArray(jsonArr.get(), item.get());
}

bool AddStringToJson(CJson* jsonObj, const std::string& key, const std::string& value)
{
    if ((jsonObj == nullptr) || key.empty()) {
        return false;
    }

    CJson* objInJson = cJSON_GetObjectItemCaseSensitive(jsonObj, key.c_str());
    if (objInJson == nullptr) {
        if (cJSON_AddStringToObject(jsonObj, key.c_str(), value.c_str()) == nullptr) {
            return false;
        }
    } else {
        CJson* tmp = cJSON_CreateString(value.c_str());
        if (tmp == nullptr) {
            return false;
        }
        if (!cJSON_ReplaceItemInObjectCaseSensitive(jsonObj, key.c_str(), tmp)) {
            cJSON_Delete(tmp);
            return false;
        }
    }

    return true;
}

bool AddStringToJson(CJsonUnique& jsonObj, const std::string& key, const std::string& value)
{
    return AddStringToJson(jsonObj.get(), key, value);
}

bool AddBoolToJson(CJson* jsonObj, const std::string& key, bool value)
{
    if ((jsonObj == nullptr) || key.empty()) {
        return false;
    }

    CJson* objInJson = cJSON_GetObjectItemCaseSensitive(jsonObj, key.c_str());
    if (objInJson == nullptr) {
        if (cJSON_AddBoolToObject(jsonObj, key.c_str(), value) == nullptr) {
            return false;
        }
    } else {
        CJson* tmp = cJSON_CreateBool(value);
        if (tmp == nullptr) {
            return false;
        }
        if (!cJSON_ReplaceItemInObjectCaseSensitive(jsonObj, key.c_str(), tmp)) {
            cJSON_Delete(tmp);
            return false;
        }
    }

    return true;
}

bool AddBoolToJson(CJsonUnique& jsonObj, const std::string& key, bool value)
{
    return AddBoolToJson(jsonObj.get(), key, value);
}

bool AddUnsignedIntToJson(CJson* jsonObj, const std::string& key, const uint32_t value)
{
    if ((jsonObj == nullptr) || key.empty()) {
        return false;
    }

    CJson* objInJson = cJSON_GetObjectItemCaseSensitive(jsonObj, key.c_str());
    double tmpValue = static_cast<double>(value);
    if (objInJson == nullptr) {
        if (cJSON_AddNumberToObject(jsonObj, key.c_str(), tmpValue) == nullptr) {
            return false;
        }
    } else {
        CJson* tmp = cJSON_CreateNumber(tmpValue);
        if (tmp == nullptr) {
            return false;
        }
        if (!cJSON_ReplaceItemInObjectCaseSensitive(jsonObj, key.c_str(), tmp)) {
            cJSON_Delete(tmp);
            return false;
        }
    }
    return true;
}

bool AddUnsignedIntToJson(CJsonUnique& jsonObj, const std::string& key, uint32_t value)
{
    return AddUnsignedIntToJson(jsonObj.get(), key, value);
}

static bool IsCfgDirExist(uint32_t userId, std::string& cjsonDir)
{
    struct stat fstat = {};
    if (stat(cjsonDir.c_str(), &fstat) != 0) {
        selinux_log(SELINUX_ERROR, "Path: %s is invalid, errorNo: %d.", cjsonDir.c_str(), errno);
        return false;
    }

    if (!S_ISDIR(fstat.st_mode)) {
        selinux_log(SELINUX_ERROR, "Path: %s is not a directory.", cjsonDir.c_str());
        return false;
    }
    return true;
}

static bool IsCfgFileExist(uint32_t userId)
{
    std::string fileName = RESTORECON_HAP_DATA_BASE + std::to_string(userId) + JSON_FILE_SUB_INFO;
    struct stat fstat = {};
    int32_t res = stat(fileName.c_str(), &fstat);
    if (res != 0) {
        selinux_log(SELINUX_INFO, "File: %s is invalid, errorNo: %d.", fileName.c_str(), errno);
        return false;
    }
    return true;
}

static bool CreateDirectory(const std::string& path)
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
            if (mkdir(subPath.c_str(), S_IRUSR | S_IWUSR) != 0) {
                return false;
            }
        }
    } while (index != std::string::npos);

    return access(path.c_str(), F_OK) == 0;
}

static bool IsUserDirExist(uint32_t userId)
{
    std::string userDir = RESTORECON_HAP_DATA_BASE + std::to_string(userId);
    if (!IsCfgDirExist(userId, userDir)) {
        return false;
    }
    return true;
}

static int32_t CreateCfgFile(uint32_t userId)
{
    std::string cjsonDir = RESTORECON_HAP_DATA_BASE + std::to_string(userId) + JSON_FILE_SUB_DIR;
    if (!IsCfgDirExist(userId, cjsonDir)) {
        if (!CreateDirectory(cjsonDir)) {
            selinux_log(SELINUX_INFO, "Create path: %s failed, errorNo: %d.", cjsonDir.c_str(), errno);
            return -SELINUX_CREATE_PATH_ERROR;
        }
    }

    std::string fileName = cjsonDir + "/" + HAP_JSON_FILE;
    int32_t fd = creat(fileName.c_str(), S_IRUSR | S_IWUSR);
    if (fd < 0) {
        selinux_log(SELINUX_ERROR, "Create file: %s failed, errorNo: %d.", fileName.c_str(), errno);
        return -SELINUX_CREATE_FILE_ERROR;
    }
    fdsan_exchange_owner_tag(fd, 0, SECURITY_SELINUX_ADAPTER);
    fdsan_close_with_tag(fd, SECURITY_SELINUX_ADAPTER);
    return SELINUX_SUCC;
}

static void RemoveCfgFile(uint32_t userId)
{
    std::string fileName = RESTORECON_HAP_DATA_BASE + std::to_string(userId) + JSON_FILE_SUB_INFO;
    int32_t res = unlink(fileName.c_str());
    selinux_log(SELINUX_INFO, "Remove %s, res: %d.", fileName.c_str(), res);
}

static int32_t ReadJsonFileContent(uint32_t userId, std::string& content)
{
    std::string fileName = RESTORECON_HAP_DATA_BASE + std::to_string(userId) + JSON_FILE_SUB_INFO;
    char* jsonPath = realpath(fileName.c_str(), nullptr);
    if (jsonPath == nullptr) {
        selinux_log(SELINUX_ERROR, "Can not find %s, errorNo: %d.", fileName.c_str(), errno);
        return -SELINUX_PATH_INVALID;
    }
    std::ifstream jsonFile(jsonPath);
    if (!jsonFile.is_open()) {
        selinux_log(SELINUX_ERROR, "Can not open %s, errorNo: %d.", fileName.c_str(), errno);
        free(jsonPath);
        return -SELINUX_PATH_INVALID;
    }
    std::stringstream buffer;
    buffer << jsonFile.rdbuf();
    content = buffer.str();
    jsonFile.close();
    free(jsonPath);
    return SELINUX_SUCC;
}

static int32_t WriteJsonFileContent(uint32_t userId, const std::string& content)
{
    std::string fileName = RESTORECON_HAP_DATA_BASE + std::to_string(userId) + JSON_FILE_SUB_INFO;
    char* jsonPath = realpath(fileName.c_str(), nullptr);
    if (jsonPath == nullptr) {
        selinux_log(SELINUX_ERROR, "Can not find %s, errorNo: %d.", fileName.c_str(), errno);
        return -SELINUX_PATH_INVALID;
    }
    std::ofstream jsonFile(jsonPath);
    if (!jsonFile.is_open()) {
        selinux_log(SELINUX_ERROR, "Can not open %s, errorNo: %d.", fileName.c_str(), errno);
        free(jsonPath);
        return -SELINUX_PATH_INVALID;
    }
    jsonFile << content;
    jsonFile.close();
    free(jsonPath);
    return SELINUX_SUCC;
}

static int32_t InitRefreshInfo(RefreshInfo& refreshInfo, std::vector<std::string>& pathNameOrig)
{
    if (refreshInfo.bundleName.empty()) {
        selinux_log(SELINUX_ERROR, "Bundle name is invalid.");
        return -SELINUX_PATH_INVALID;
    }
    if (pathNameOrig.empty()) {
        selinux_log(SELINUX_ERROR, "Path list is empty.");
        return -SELINUX_PATH_INVALID;
    }
    for (auto& pathName : pathNameOrig) {
        if (pathName.empty()) {
            continue;
        }
        char* realPath = realpath(pathName.c_str(), nullptr);
        if (realPath == nullptr) {
            continue;
        }
        // Hash collision, we do not handle it.
        auto pathInfo = std::make_shared<PathInfo>();
        pathInfo->target = realPath;
        refreshInfo.paths[realPath] = pathInfo;
        free(realPath);
    }
    if (refreshInfo.paths.empty()) {
        selinux_log(SELINUX_ERROR, "None of paths are realpath.");
        Selinux::ReportSeharmonyRestoreErr(refreshInfo.bundleName,
            refreshInfo.uid, -SELINUX_PATH_INVALID,
            "InitRefreshInfo: no found path.");
        return -SELINUX_NO_FOUND_PATHS;
    }
    return SELINUX_SUCC;
}

static int32_t UpdateRefreshInfo(cJSON* root, RefreshInfo& refreshInfo)
{
    std::string bundleName;
    uint32_t uid;
    cJSON* item = nullptr;
    cJSON_ArrayForEach(item, root) {
        CHECK_BOOL_RETURN(cJSON_IsObject(item), -SELINUX_JSON_INFO_INVALID);
        CHECK_BOOL_RETURN(GetStringFromJson(item, BUNDLE_KEY_NAME, bundleName), -SELINUX_JSON_INFO_INVALID);
        CHECK_BOOL_RETURN(GetUnsignedIntFromJson(item, UID_KEY_NAME, uid), -SELINUX_JSON_INFO_INVALID);
        if ((bundleName != refreshInfo.bundleName) || (uid != refreshInfo.uid)) {
            continue;
        }
        cJSON* paths = GetArrayFromJson(item, PATHS_KEY_NAME);
        CHECK_NULL_RETURN(paths, -SELINUX_JSON_INFO_INVALID);
        cJSON* element = nullptr;
        cJSON_ArrayForEach(element, paths) {
            CHECK_BOOL_RETURN(cJSON_IsObject(element), -SELINUX_JSON_INFO_INVALID);
            std::string target;
            CHECK_BOOL_RETURN(GetStringFromJson(element, TARGET_KEY_NAME, target), -SELINUX_JSON_INFO_INVALID);
            auto iter = refreshInfo.paths.find(target);
            if (iter == refreshInfo.paths.end()) {
                continue;
            }
            CHECK_NULL_RETURN(refreshInfo.paths[target], -SELINUX_PTR_NULL);
            CHECK_BOOL_RETURN(GetStringFromJson(element, FINISHED_KEY_NAME, refreshInfo.paths[target]->finished),
                -SELINUX_JSON_INFO_INVALID);
            CHECK_BOOL_RETURN(GetUnsignedIntFromJson(element, COUNT_KEY_NAME, refreshInfo.paths[target]->count),
                -SELINUX_JSON_INFO_INVALID);
            CHECK_BOOL_RETURN(GetBoolFromJson(element, DONE_KEY_NAME, refreshInfo.paths[target]->done),
                -SELINUX_JSON_INFO_INVALID);
        }
    }
    return SELINUX_SUCC;
}

int32_t ReadRefreshInfo(RefreshInfo& refreshInfo, std::vector<std::string>& pathNameOrig)
{
    int32_t res = InitRefreshInfo(refreshInfo, pathNameOrig);
    if (res != SELINUX_SUCC) {
        return res;
    }

    auto userId = refreshInfo.uid / BASE_USER_RANGE;
    if (userId == 0) {
        return SELINUX_SUCC;
    }
    std::lock_guard<std::mutex> lock(g_accessJsonLock);
    if (!IsCfgFileExist(userId)) {
        return SELINUX_SUCC;
    }

    std::string jsonStr;
    res = ReadJsonFileContent(userId, jsonStr);
    if (res != SELINUX_SUCC) {
        return res;
    }
    if (jsonStr.empty()) {
        selinux_log(SELINUX_INFO, "The content of json file is empty.");
        return SELINUX_SUCC;
    }
    CJsonUnique root = CreateJsonFromString(jsonStr);
    if (root == nullptr) {
        RemoveCfgFile(userId);
        selinux_log(SELINUX_ERROR, "CreateJsonFromString failed");
        Selinux::ReportSeharmonyRestoreErr(refreshInfo.bundleName,
            refreshInfo.uid, -SELINUX_JSON_INFO_INVALID,
            "ReadRefreshInfo: Load json failed.");
        return SELINUX_SUCC;
    }
    RefreshInfo tmp = refreshInfo;
    res = UpdateRefreshInfo(root.get(), refreshInfo);
    if (res != SELINUX_SUCC) {
        refreshInfo = tmp;
        RemoveCfgFile(userId);
        Selinux::ReportSeharmonyRestoreErr(refreshInfo.bundleName,
            refreshInfo.uid, res, "ReadRefreshInfo: Parse info from json failed.");
    }
    return SELINUX_SUCC;
}

static int32_t AddRefreshInfo(CJsonUnique& root, RefreshInfo& refreshInfo)
{
    CJsonUnique jsonInfo = CreateJson();
    CHECK_NULL_RETURN(jsonInfo, -SELINUX_PTR_NULL);
    CHECK_BOOL_RETURN(AddStringToJson(jsonInfo, BUNDLE_KEY_NAME, refreshInfo.bundleName), -SELINUX_JSON_ADD_INFO_ERROR);
    CHECK_BOOL_RETURN(AddUnsignedIntToJson(jsonInfo, UID_KEY_NAME, refreshInfo.uid), -SELINUX_JSON_ADD_INFO_ERROR);
    CJsonUnique paths = CreateJsonArray();
    CHECK_NULL_RETURN(paths, -SELINUX_PTR_NULL);
    for (auto& path : refreshInfo.paths) {
        CJsonUnique pathInfo = CreateJson();
        CHECK_NULL_RETURN(pathInfo, -SELINUX_PTR_NULL);
        CHECK_NULL_RETURN(path.second, -SELINUX_PTR_NULL);
        CHECK_BOOL_RETURN(AddStringToJson(pathInfo, TARGET_KEY_NAME, path.second->target),
            -SELINUX_JSON_ADD_INFO_ERROR);
        CHECK_BOOL_RETURN(AddStringToJson(pathInfo, FINISHED_KEY_NAME, path.second->finished),
            -SELINUX_JSON_ADD_INFO_ERROR);
        CHECK_BOOL_RETURN(AddUnsignedIntToJson(pathInfo, COUNT_KEY_NAME, path.second->count),
            -SELINUX_JSON_ADD_INFO_ERROR);
        CHECK_BOOL_RETURN(AddBoolToJson(pathInfo, DONE_KEY_NAME, path.second->done), -SELINUX_JSON_ADD_INFO_ERROR);
        CHECK_BOOL_RETURN(AddObjToArray(paths, pathInfo), -SELINUX_JSON_ADD_INFO_ERROR);
    }
    CHECK_BOOL_RETURN(AddObjToJson(jsonInfo, PATHS_KEY_NAME, paths), -SELINUX_JSON_ADD_INFO_ERROR);
    CHECK_BOOL_RETURN(AddObjToArray(root, jsonInfo), -SELINUX_JSON_ADD_INFO_ERROR);
    return SELINUX_SUCC;
}

static int32_t DeleteRefreshNode(cJSON* root, const std::string& packageName, uint32_t packageUid)
{
    std::string bundleName;
    uint32_t uid;
    cJSON* item = nullptr;
    int32_t index = 0;
    cJSON_ArrayForEach(item, root) {
        CHECK_BOOL_RETURN(cJSON_IsObject(item), -SELINUX_JSON_INFO_INVALID);
        CHECK_BOOL_RETURN(GetStringFromJson(item, BUNDLE_KEY_NAME, bundleName), -SELINUX_JSON_INFO_INVALID);
        CHECK_BOOL_RETURN(GetUnsignedIntFromJson(item, UID_KEY_NAME, uid), -SELINUX_JSON_INFO_INVALID);
        if ((bundleName != packageName) || (uid != packageUid)) {
            ++index;
            continue;
        }
        cJSON_Delete(cJSON_DetachItemFromArray(root, index));
        return SELINUX_SUCC;
    }

    return SELINUX_SUCC;
}

static bool CheckRefreshInfo(RefreshInfo& refreshInfo)
{
    if (refreshInfo.bundleName.empty()) {
        return false;
    }
    if (refreshInfo.paths.empty()) {
        return false;
    }
    for (auto& path : refreshInfo.paths) {
        if (path.second == nullptr) {
            return false;
        }
        if (path.second->target.empty()) {
            return false;
        }
    }
    return true;
}

static bool RefreshInfoAllDone(RefreshInfo& refreshInfo)
{
    for (auto& path : refreshInfo.paths) {
        if (path.second == nullptr) {
            return false;
        }
        if (path.second->done == false) {
            return false;
        }
    }
    return true;
}

static CJsonUnique GetJsonRoot(std::string& jsonStr, uint32_t userId, RefreshInfo& refreshInfo)
{
    if (jsonStr.empty()) {
        return CreateJsonArray();
    }
    CJsonUnique root = CreateJsonFromString(jsonStr);
    if (root == nullptr) {
        RemoveCfgFile(userId);
        selinux_log(SELINUX_ERROR, "CreateJsonFromString failed.");
        Selinux::ReportSeharmonyRestoreErr(refreshInfo.bundleName,
            refreshInfo.uid, -SELINUX_JSON_INFO_INVALID,
            "GetJsonRoot: Load json failed.");
        return nullptr;
    }
    int32_t res = DeleteRefreshNode(root.get(), refreshInfo.bundleName, refreshInfo.uid);
    if (res != SELINUX_SUCC) {
        RemoveCfgFile(userId);
        selinux_log(SELINUX_ERROR, "Delete refresh info failed.");
        Selinux::ReportSeharmonyRestoreErr(refreshInfo.bundleName, refreshInfo.uid,
                res, "GetJsonRoot: DeleteRefreshNode failed.");
        return nullptr;
    }
    return root;
}

int32_t WriteRefreshInfo(RefreshInfo& refreshInfo)
{
    if (!CheckRefreshInfo(refreshInfo)) {
        return -SELINUX_ARG_INVALID;
    }
    auto userId = refreshInfo.uid / BASE_USER_RANGE;
    if (userId == 0) {
        return SELINUX_SUCC;
    }
    std::lock_guard<std::mutex> lock(g_accessJsonLock);
    if (!IsUserDirExist(userId)) {
        return SELINUX_SUCC;
    }
    int32_t res = SELINUX_SUCC;
    if (!IsCfgFileExist(userId)) {
        res = CreateCfgFile(userId);
        if (res != SELINUX_SUCC) {
            Selinux::ReportSeharmonyRestoreErr(refreshInfo.bundleName, refreshInfo.uid,
                res, "CreateCfgFile failed.");
            return res;
        }
    }
    std::string jsonStr;
    res = ReadJsonFileContent(userId, jsonStr);
    if (res != SELINUX_SUCC) {
        return res;
    }
    CJsonUnique root = GetJsonRoot(jsonStr, userId, refreshInfo);
    if (root == nullptr) {
        selinux_log(SELINUX_ERROR, "Root is null.");
        return -SELINUX_PTR_NULL;
    }
    if (!RefreshInfoAllDone(refreshInfo)) {
        res = AddRefreshInfo(root, refreshInfo);
        if (res != SELINUX_SUCC) {
            RemoveCfgFile(userId);
            selinux_log(SELINUX_ERROR, "Add refresh info failed.");
            Selinux::ReportSeharmonyRestoreErr(refreshInfo.bundleName, refreshInfo.uid,
                res, "WriteRefreshInfo: AddRefreshInfo failed.");
            return res;
        }
    }

    std::string content = PackJsonToString(root);
    res = WriteJsonFileContent(userId, content);
    if (res != SELINUX_SUCC) {
        Selinux::ReportSeharmonyRestoreErr(refreshInfo.bundleName, refreshInfo.uid,
                res, "WriteRefreshInfo: WriteJsonFileContent failed.");
        return res;
    }
    return SELINUX_SUCC;
}

int32_t DeleteRefreshInfo(const std::string& bundleName, uint32_t uid)
{
    if (bundleName.empty()) {
        selinux_log(SELINUX_ERROR, "Bundle name is invalid.");
        return -SELINUX_ARG_INVALID;
    }
    auto userId = uid / BASE_USER_RANGE;
    if (userId == 0) {
        return SELINUX_SUCC;
    }
    std::lock_guard<std::mutex> lock(g_accessJsonLock);
    if (!IsCfgFileExist(userId)) {
        return SELINUX_SUCC;
    }
    std::string jsonStr;
    int32_t res = ReadJsonFileContent(userId, jsonStr);
    if (res != SELINUX_SUCC) {
        return res;
    }
    if (jsonStr.empty()) {
        selinux_log(SELINUX_INFO, "The content of json file is empty.");
        return SELINUX_SUCC;
    }
    CJsonUnique root = CreateJsonFromString(jsonStr);
    if (root == nullptr) {
        RemoveCfgFile(userId);
        selinux_log(SELINUX_ERROR, "Create json from string failed.");
        Selinux::ReportSeharmonyRestoreErr(bundleName,
            uid, -SELINUX_JSON_INFO_INVALID,
            "DeleteRefreshInfo: Load json failed.");
        return -SELINUX_PTR_NULL;
    }
    res = DeleteRefreshNode(root.get(), bundleName, uid);
    if (res != SELINUX_SUCC) {
        RemoveCfgFile(userId);
        selinux_log(SELINUX_ERROR, "Delete refresh info failed.");
        Selinux::ReportSeharmonyRestoreErr(bundleName, uid,
                res, "DeleteRefreshInfo: DeleteRefreshNode failed.");
        return res;
    }
    std::string content = PackJsonToString(root);
    res = WriteJsonFileContent(userId, content);
    if (res != SELINUX_SUCC) {
        Selinux::ReportSeharmonyRestoreErr(bundleName, uid,
                res, "DeleteRefreshInfo: WriteJsonFileContent failed.");
        return res;
    }
    return SELINUX_SUCC;
}
