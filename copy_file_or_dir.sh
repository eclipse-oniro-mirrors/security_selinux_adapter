#!/bin/bash
# Copyright (c) 2025 Huawei Device Co., Ltd.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# Description: This script is used to convert the operation of copying hard links into direct copying.

set -e

# Check if exactly two arguments are provided
if [ "$#" -ne 2 ]; then
  echo "Usage:$0 <source> <target>"
  exit 1
fi

SOURCE="$1"
TARGET="$2"

# Check if the source exists
if [ ! -e "$SOURCE" ]; then
  echo "Error: Source $SOURCE does not exist"
  exit 1
fi

# If the target exists, remove it
if [ -e "$TARGET" ]; then
  if [ -d "$TARGET" ]; then
    rm -rf "$TARGET"
    REMOVE_RESULT=$?
  else
    rm -f "$TARGET"
    REMOVE_RESULT=$?
  fi

  # Check if the remove operation was successful
  if [ $REMOVE_RESULT -ne 0 ]; then
    echo "Error: Failed to remove $TARGET"
    exit 1
  fi
fi

# If the source is a directory, create the target directory
if [ -d "$SOURCE" ]; then
  mkdir -p "$TARGET"
  CREATE_DIR_RESULT=$?

  # Check if the directory was created successfully
  if [ $CREATE_DIR_RESULT -ne 0 ]; then
    echo "Error: Failed to create target directory $TARGET"
    exit 1
  fi

  # Copy all contents including hidden files
  touch /tmp/copy_file_or_dir.lock
  flock /tmp/copy_file_or_dir.lock cp -af "$SOURCE"/. "$TARGET"/
  COPY_RESULT=$?
else
  # If the source is a file, copy it directly.
  touch /tmp/copy_file_or_dir.lock
  if [ -d "$TARGET" ]; then
    flock /tmp/copy_file_or_dir.lock cp -af "$SOURCE" "$TARGET"/
  else
    flock /tmp/copy_file_or_dir.lock cp -af "$SOURCE" "$TARGET"
  fi
  COPY_RESULT=$?
fi

# Check if the copy was successful
if [ "$COPY_RESULT" -eq "0" ]; then
  echo "Copy successful:$SOURCE -> $TARGET"
else
  echo "Error: Failed to copy $SOURCE to $TARGET"
  exit 1
fi
