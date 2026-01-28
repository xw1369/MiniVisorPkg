/** @file
  Hypervisor DXE Driver Header File
  
  This file contains definitions and declarations for the hypervisor.
  
  Copyright (c) 2024, Hypervisor Project. All rights reserved.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef __HYPERVISOR_DXE_H__
#define __HYPERVISOR_DXE_H__

#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DebugLib.h>
#include <Library/PrintLib.h>
#include <Library/IoLib.h>
#include <Library/PcdLib.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/DevicePath.h>

#include "VmxDefs.h"
#include "VmxStructs.h"
#include "../../Include/MiniVisorAuth.h"
#include "../MiniVisorSvmDxe/MiniVisorSvmDxe.h"

// External declarations for global variables

//
// Hypervisor Version Information
//
#define HYPERVISOR_MAJOR_VERSION    2
#define HYPERVISOR_MINOR_VERSION    0
#define HYPERVISOR_BUILD_VERSION    0

//
// Hypervisor Status Flags
//
#define HYPERVISOR_STATUS_INITIALIZED       BIT0
#define HYPERVISOR_STATUS_VMX_ENABLED       BIT1
#define HYPERVISOR_STATUS_VMCS_LOADED       BIT2
#define HYPERVISOR_STATUS_GUEST_RUNNING     BIT3
#define HYPERVISOR_STATUS_AUTH_VERIFIED     BIT4
#define HYPERVISOR_STATUS_UNIFIED_AUTH      BIT5
#define HYPERVISOR_STATUS_ERROR             BIT31

//
// Performance Monitoring Structures
//
typedef struct {
  UINT64    VmExitCount;
  UINT64    VmEntryCount;
  UINT64    LastVmExitReason;
  UINT64    TotalVmExitTime;
  UINT64    AverageVmExitTime;
  UINT64    MaxVmExitTime;
  UINT64    MinVmExitTime;
} HYPERVISOR_PERFORMANCE_DATA;

//
// Lightweight memory tracking for diagnosis
//
typedef struct {
  UINT64  TotalPagesAllocated;
  UINT64  TotalPagesFreed;
  UINT64  OutstandingPages;
} HYPERVISOR_MEMORY_TRACKING;

//
// Hypervisor Global State Structure
//
typedef struct {
  UINT32                        Signature;
  UINT32                        Version;
  UINT32                        Status;
  UINT32                        CpuCount;
  VOID                          *VmxonRegion;
  VOID                          *VmcsRegion;
  HYPERVISOR_PERFORMANCE_DATA   PerfData;
  HYPERVISOR_MEMORY_TRACKING    MemTrack;
  EFI_PHYSICAL_ADDRESS          GuestPhysicalBase;
  UINTN                         GuestPhysicalSize;
  //
  // Unified Authorization System
  //
  MINI_VISOR_AUTH_CONTEXT       AuthContext;
  MINI_VISOR_AUTHORIZATION      *CurrentAuthorization;
  UINT32                        CompatibilityScore;
  BOOLEAN                       UnifiedAuthEnabled;
} HYPERVISOR_GLOBAL_DATA;

//
// Function Prototypes
//

/**
  Initialize hypervisor.
  
  @param[in] ImageHandle    The image handle of the driver.
  @param[in] SystemTable    The system table.
  
  @retval EFI_SUCCESS       Initialization successful.
  @retval Others            Initialization failed.
**/
EFI_STATUS
EFIAPI
HypervisorInitialize (
  IN EFI_HANDLE         ImageHandle,
  IN EFI_SYSTEM_TABLE   *SystemTable
  );

/**
  Get hypervisor status information.
  
  @param[out] StatusInfo    Pointer to receive status information.
  
  @retval EFI_SUCCESS       Status retrieved successfully.
  @retval EFI_INVALID_PARAMETER  StatusInfo is NULL.
**/
EFI_STATUS
EFIAPI
HypervisorGetStatus (
  OUT HYPERVISOR_GLOBAL_DATA  *StatusInfo
  );

/**
  Get hypervisor performance data.
  
  @param[out] PerfData      Pointer to receive performance data.
  
  @retval EFI_SUCCESS       Performance data retrieved successfully.
  @retval EFI_INVALID_PARAMETER  PerfData is NULL.
**/
EFI_STATUS
EFIAPI
HypervisorGetPerformanceData (
  OUT HYPERVISOR_PERFORMANCE_DATA  *PerfData
  );

/**
  Reset hypervisor performance counters.
  
  @retval EFI_SUCCESS       Performance counters reset successfully.
**/
EFI_STATUS
EFIAPI
HypervisorResetPerformanceCounters (
  VOID
  );

//
// Memory tracking helpers (wrappers around gBS->AllocatePages/FreePages)
//
EFI_STATUS
EFIAPI
HypervisorAllocateTrackedPages (
  IN EFI_ALLOCATE_TYPE     Type,
  IN EFI_MEMORY_TYPE       MemoryType,
  IN UINTN                 Pages,
  IN OUT EFI_PHYSICAL_ADDRESS *Memory
  );

EFI_STATUS
EFIAPI
HypervisorFreeTrackedPages (
  IN EFI_PHYSICAL_ADDRESS  Memory,
  IN UINTN                 Pages
  );

/**
  Enable or disable hypervisor debug output.
  
  @param[in] Enable         TRUE to enable debug output, FALSE to disable.
  
  @retval EFI_SUCCESS       Debug mode updated successfully.
**/
EFI_STATUS
EFIAPI
HypervisorSetDebugMode (
  IN BOOLEAN  Enable
  );

/**
  Verify authorization using unified authorization system.
  
  @param[in] AuthData       Pointer to authorization data.
  @param[in] AuthSize       Size of authorization data.
  
  @retval EFI_SUCCESS       Authorization verified successfully.
  @retval EFI_ACCESS_DENIED Authorization verification failed.
  @retval Others            Other errors occurred.
**/
EFI_STATUS
EFIAPI
VtdAuthVerifyUnified (
  IN UINT8   *AuthData,
  IN UINTN   AuthSize
  );

/**
  Get current authorization status and compatibility score.
  
  @param[out] AuthStatus    Current authorization status.
  @param[out] CompatScore   Compatibility score (0-1000).
  
  @retval EFI_SUCCESS       Status retrieved successfully.
**/
EFI_STATUS
EFIAPI
VtdAuthGetStatus (
  OUT MINI_VISOR_AUTH_STATUS  *AuthStatus,
  OUT UINT32                  *CompatScore
  );

/**
  Print VT-d authorization diagnostics.
**/
EFI_STATUS
EFIAPI
VtdAuthPrintDiagnostics (
  VOID
  );

/**
  Generate Intel VT-d upgrade recommendations.
**/
EFI_STATUS
EFIAPI
VtdAuthGenerateUpgradeRecommendations (
  VOID
  );

//
// Global Variables
//
extern MINI_VISOR_GLOBAL_DATA  gMiniVisorGlobalData;
extern BOOLEAN                 gHypervisorDebugMode;
extern MINI_VISOR_AUTHORIZATION *gVtdCurrentAuth;
extern MINI_VISOR_AUTH_CONTEXT gHypervisorAuthContext;

//
// Constants (using BIT macros instead of direct values)
//

//
// Utility Macros
//
#define HYPERVISOR_SIGNATURE  SIGNATURE_32('H','Y','P','R')

#define IS_HYPERVISOR_INITIALIZED() \
  ((gHypervisorGlobalData.Status & HYPERVISOR_STATUS_INITIALIZED) != 0)

#define IS_VMX_ENABLED() \
  ((gHypervisorGlobalData.Status & HYPERVISOR_STATUS_VMX_ENABLED) != 0)

#define HYPERVISOR_DEBUG(Expression) \
  do { \
    if (gHypervisorDebugMode) { \
      DEBUG(Expression); \
    } \
  } while (FALSE)

#endif // __HYPERVISOR_DXE_H__
