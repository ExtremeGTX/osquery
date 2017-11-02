/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <Windows.h>
#include <winternl.h>

#include "osquery/core/windows/wmi.h"
#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#pragma comment(lib, "ntdll.lib")

#include <iostream>

NTSTATUS(NTAPI* NtDuplicateObject)
(HANDLE SourceProcessHandle,
 HANDLE SourceHandle,
 HANDLE TargetProcessHandle,
 PHANDLE TargetHandle,
 ACCESS_MASK DesiredAccess,
 ULONG Attributes,
 ULONG Options);

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
  ULONG ProcessId;
  BYTE ObjectTypeNumber;
  BYTE Flags;
  USHORT Handle;
  PVOID Object;
  ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION {
  ULONG HandleCount;
  SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef enum _POOL_TYPE {
  NonPagedPool,
  PagedPool,
  NonPagedPoolMustSucceed,
  DontUseThisType,
  NonPagedPoolCacheAligned,
  PagedPoolCacheAligned,
  NonPagedPoolCacheAlignedMustS
} POOL_TYPE,
    *PPOOL_TYPE;

typedef struct _OBJECT_TYPE_INFORMATION {
  UNICODE_STRING Name;
  ULONG TotalNumberOfObjects;
  ULONG TotalNumberOfHandles;
  ULONG TotalPagedPoolUsage;
  ULONG TotalNonPagedPoolUsage;
  ULONG TotalNamePoolUsage;
  ULONG TotalHandleTableUsage;
  ULONG HighWaterNumberOfObjects;
  ULONG HighWaterNumberOfHandles;
  ULONG HighWaterPagedPoolUsage;
  ULONG HighWaterNonPagedPoolUsage;
  ULONG HighWaterNamePoolUsage;
  ULONG HighWaterHandleTableUsage;
  ULONG InvalidAttributes;
  GENERIC_MAPPING GenericMapping;
  ULONG ValidAccess;
  BOOLEAN SecurityRequired;
  BOOLEAN MaintainHandleCount;
  USHORT MaintainTypeList;
  POOL_TYPE PoolType;
  ULONG PagedPoolUsage;
  ULONG NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

#define SystemHandleInformation (SYSTEM_INFORMATION_CLASS)16
#define ObjectBasicInformation (OBJECT_INFORMATION_CLASS)0
#define ObjectNameInformation (OBJECT_INFORMATION_CLASS)1
#define ObjectTypeInformation (OBJECT_INFORMATION_CLASS)2

namespace osquery {
namespace tables {
#if 0
    const std::string kHandleTypes[] = {
        "device",
        "driver",
        "section",
        "port",
        "symlink",
        "key",
        "event",
        "job",
        "mutant",
        "keyedevent",
        "type",
        "directory",
        "winstation",
        "callback",
        "semaphore",
        "waitableport",
        "timer",
        "session",
        "controller",
        "profile",
        "eventpair",
        "desktop",
        "file",
        "wmiguid",
        "debugobject",
        "iocompletion",
        "process",
        "adapter",
        "token",
        "etwregistration",
        "thread",
        "tmtx",
        "tmtm",
        "tmrm",
        "tmen",
        "pcwobject",
        "fltconn_port",
        "fltcomm_port",
        "power_request",
        "etwconsumer",
        "tpworkerfactory",
        "composition",
        "irtimer",
        "dxgksharedres",
        "dxgksharedswapchain",
        "dxgksharedsync",
        "dxgkcurdxgprocessobject",
        "memorypartition",
    };
#endif

Row getHandleInfo(SYSTEM_HANDLE_TABLE_ENTRY_INFO& handle) {
  Row r;
  NTSTATUS status;
  ULONG returnLength = 0;
  HANDLE processHandle = 0;
  HANDLE duplicateHandle = 0;

  r["Name"] =
      SQL_TEXT("(UNNAMED)"); /* will be updated if NtQueryObject succeeded  */
  r["Type"] =
      SQL_TEXT("(UNKNOWN)"); /* will be updated if NtQueryObject succeeded  */
  r["PID"] = INTEGER(handle.ProcessId);
  r["UID"] = INTEGER(handle.Handle);
#if 0    
    /* i was looking for using a lookup table and save a call to NtQueryObject 
     * but this list will not alwayes be consistent with Windows (MSFT always change id of the types) 
     * Please check the code here: https://forum.powerbasic.com/forum/user-to-user-discussions/source-code/25843-ntquerysysteminformation-with-systemhandleinformation
     * also here: https://github.com/hfiref0x/WinObjEx64/blob/master/Source/WinObjEx64/objects.c
     * Also there is a change from windows 7 to 10 (even newer builds of win10)
     * This list is useful in only one case:
     *  if call to OpenProcess fail, you still can get at least (handle type) by using ObjectTypeNumber as index with
     *  this list.
     */
    if (handle.ObjectTypeNumber < 50) /* Protection if there is a new type introduced and not in the list */
    {
        r["Type"] = SQL_TEXT(kHandleTypes[handle.ObjectTypeNumber]);
    }
    else
    {
        r["Type"] = SQL_TEXT(INTEGER(handle.ObjectTypeNumber));
    }
#endif

  if (!(processHandle =
            OpenProcess(PROCESS_DUP_HANDLE, FALSE, handle.ProcessId))) {
    TLOG << "OpenProcess fail to open pid:" << handle.ProcessId;
    return r;
  }

  /* PCW Object can't be queried */
  if (handle.ObjectTypeNumber == 35) {
    TLOG << "PCW Object Skipped uid:" << handle.Handle;
    CloseHandle(processHandle);
    return r;
  }

  /* Duplicate the handle so we can query it. */
  status = NtDuplicateObject(processHandle,
                             (HANDLE)handle.Handle,
                             GetCurrentProcess(),
                             &duplicateHandle,
                             0,
                             0,
                             0);
  if (!NT_SUCCESS(status)) {
    TLOG << "NtDuplicateObject failed status:" << status
         << " uid:" << handle.Handle;
    CloseHandle(processHandle);
    return r;
  }

  /* Query the object type. */
  auto objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(4096);
  status = NtQueryObject(
      duplicateHandle, ObjectTypeInformation, objectTypeInfo, 4096, nullptr);
  if (!NT_SUCCESS(status)) {
    TLOG << "NtQueryObject failed status:" << status
         << " uid:" << handle.Handle;
    free(objectTypeInfo);
    CloseHandle(duplicateHandle);
    CloseHandle(processHandle);
    return r;
  }

  r["Type"] = wstringToString(objectTypeInfo->Name.Buffer);

  /* Query the object Name. */
  auto objectNameInfo = malloc(4096);
  status = NtQueryObject(duplicateHandle,
                         ObjectNameInformation,
                         objectNameInfo,
                         4096,
                         &returnLength);
  objectNameInfo = realloc(objectNameInfo, returnLength);
  status = NtQueryObject(duplicateHandle,
                         ObjectNameInformation,
                         objectNameInfo,
                         returnLength,
                         nullptr);
  if (!NT_SUCCESS(status)) {
    TLOG << "NtQueryObject failed status:" << status
         << " uid:" << handle.Handle;
    free(objectTypeInfo);
    free(objectNameInfo);
    CloseHandle(duplicateHandle);
    CloseHandle(processHandle);
    return r;
  }

  auto objectName = *(PUNICODE_STRING)objectNameInfo;
  if (objectName.Length) {
    r["Name"] = wstringToString(objectName.Buffer);
  }

  free(objectTypeInfo);
  free(objectNameInfo);
  CloseHandle(duplicateHandle);
  CloseHandle(processHandle);
  return r;
}

void queryHandles(QueryData& results) {
  NTSTATUS status;
  PSYSTEM_HANDLE_INFORMATION handleInfo = NULL;
  ULONG handleInfoSize = USHRT_MAX;
  ULONG i = 0;
  Row r;

  /* Use NtQuerySystemInformation to get list of all handles */
  handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);
  status = NtQuerySystemInformation(
      SystemHandleInformation, handleInfo, handleInfoSize, &handleInfoSize);
  handleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize);
  status = NtQuerySystemInformation(
      SystemHandleInformation, handleInfo, handleInfoSize, NULL);
  if (!NT_SUCCESS(status)) {
    TLOG << "NtQuerySystemInformation failed!";
    return;
  }

  for (i = 0; i < handleInfo->HandleCount; i++) {
    results.push_back(getHandleInfo(handleInfo->Handles[i]));
  }
  free(handleInfo);
}

QueryData genHandles(QueryContext& context) {
  QueryData results;
  HMODULE hNtDll = ::GetModuleHandle("ntdll.dll");
  *(FARPROC*)&NtDuplicateObject = ::GetProcAddress(hNtDll, "NtDuplicateObject");
  queryHandles(results);
  return results;
}
} // namespace tables
} // namespace osquery
