/* Copyright (c) 2021 北京万里红科技有限公司
 *
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

#ifndef __POLICYCOREUTILS_H__
#define __POLICYCOREUTILS_H__

int LoadPolicy(void);
int Restorecon(const char *path);
int RestoreconRecurse(const char *path);
#endif                          // __POLICYCOREUTILS_H__
