/** @file
  Hypervisor SVM DXE Driver Header File
  
  This file contains definitions and declarations for the hypervisor 
  using AMD SVM (Secure Virtual Machine) technology.
  
  Copyright (c) 2024, Hypervisor Project. All rights reserved.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef __HYPERVISOR_SVM_DXE_H__
#define __HYPERVISOR_SVM_DXE_H__

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

#include "SvmDefs.h"
#include "SvmStructs.h"
#include "../../Include/MiniVisorAuth.h"
#include "../../Include/UnifiedAuth.h"

//
// Static function macro for internal functions
//
#define STATIC static

//
// Hypervisor SVM Version Information
//
#define HYPERVISOR_SVM_MAJOR_VERSION    1
#define HYPERVISOR_SVM_MINOR_VERSION    0
#define HYPERVISOR_SVM_BUILD_VERSION    0

//
// MiniVisor SVM Version Information (alias for compatibility)
//
#define MINI_VISOR_SVM_MAJOR_VERSION    HYPERVISOR_SVM_MAJOR_VERSION
#define MINI_VISOR_SVM_MINOR_VERSION    HYPERVISOR_SVM_MINOR_VERSION
#define MINI_VISOR_SVM_BUILD_VERSION    HYPERVISOR_SVM_BUILD_VERSION

//
// MiniVisor Version Information (alias for compatibility)
//
#define MINI_VISOR_MAJOR_VERSION        HYPERVISOR_SVM_MAJOR_VERSION
#define MINI_VISOR_MINOR_VERSION        HYPERVISOR_SVM_MINOR_VERSION
#define MINI_VISOR_BUILD_VERSION        HYPERVISOR_SVM_BUILD_VERSION

//
// Hypervisor SVM Status Flags
//
#define HYPERVISOR_SVM_STATUS_INITIALIZED    BIT0
#define HYPERVISOR_SVM_STATUS_SVM_ENABLED    BIT1
#define HYPERVISOR_SVM_STATUS_VMCB_LOADED    BIT2
#define HYPERVISOR_SVM_STATUS_GUEST_RUNNING  BIT3
#define HYPERVISOR_SVM_STATUS_NPT_ENABLED    BIT4
#define HYPERVISOR_SVM_STATUS_AVIC_ENABLED   BIT5
#define HYPERVISOR_SVM_STATUS_ERROR          BIT31

//
// MiniVisor SVM Status Flags (alias for compatibility)
//
#define MINI_VISOR_SVM_STATUS_INITIALIZED    HYPERVISOR_SVM_STATUS_INITIALIZED
#define MINI_VISOR_SVM_STATUS_SVM_ENABLED    HYPERVISOR_SVM_STATUS_SVM_ENABLED
#define MINI_VISOR_SVM_STATUS_VMCB_LOADED    HYPERVISOR_SVM_STATUS_VMCB_LOADED
#define MINI_VISOR_SVM_STATUS_GUEST_RUNNING  HYPERVISOR_SVM_STATUS_GUEST_RUNNING
#define MINI_VISOR_SVM_STATUS_NPT_ENABLED    HYPERVISOR_SVM_STATUS_NPT_ENABLED
#define MINI_VISOR_SVM_STATUS_AVIC_ENABLED   HYPERVISOR_SVM_STATUS_AVIC_ENABLED
#define MINI_VISOR_SVM_STATUS_ERROR          HYPERVISOR_SVM_STATUS_ERROR

//
// MiniVisor Status Flags (for compatibility)
//
#define MINI_VISOR_STATUS_AUTH_VERIFIED      BIT16
#define MINI_VISOR_STATUS_UNIFIED_AUTH       BIT17
#define MINI_VISOR_STATUS_INITIALIZED        BIT0

// Types `SVM_EXIT_INFO` and `NESTED_SVM_CONTEXT` are defined in `SvmStructs.h`

//
// Advanced SVM Feature Control
//
typedef struct {
  BOOLEAN  NestedSvmEnabled;
  BOOLEAN  AvicEnabled;
  BOOLEAN  VmcbCleanEnabled;
  BOOLEAN  PauseFilterEnabled;
  BOOLEAN  TscScalingEnabled;
  BOOLEAN  VirtualGifEnabled;
  UINT32   MaxAsidCount;
  UINT32   CurrentAsid;
  UINT64   TscMultiplier;
  UINT64   PauseFilterThreshold;
} ADVANCED_SVM_FEATURES;

//
// Nested SVM Management
//
typedef struct {
  UINT64  L1VmcbPhysicalAddress;
  UINT64  L2VmcbPhysicalAddress;
  UINT32  NestingLevel;
  UINT32  L1Asid;
  UINT32  L2Asid;
  BOOLEAN InNestedMode;
  UINT64  NestedNptBase;
  UINT64  HostSaveArea;
} NESTED_SVM_STATE;

//
// AVIC (Advanced Virtual Interrupt Controller) Management
//
typedef struct {
  UINT64  AvicLogicalTable;
  UINT64  AvicPhysicalTable;
  UINT64  AvicBackingPage;
  UINT32  AvicLogicalId;
  UINT32  AvicPhysicalId;
  BOOLEAN AvicInUse;
  UINT32  PendingInterrupts[8]; // 256 bits for pending interrupts
} AVIC_MANAGEMENT;

//
// VMCB Clean Bits Management
//
typedef struct {
  UINT32  CleanBits;
  BOOLEAN InterceptVectorDirty;
  BOOLEAN IopmDirty;
  BOOLEAN AsidDirty;
  BOOLEAN TprDirty;
  BOOLEAN NestedPageDirty;
  BOOLEAN ControlDirty;
  BOOLEAN DrDirty;
  BOOLEAN DtDirty;
  BOOLEAN SegmentDirty;
  BOOLEAN Cr2Dirty;
  BOOLEAN LbrDirty;
  BOOLEAN AvicDirty;
} VMCB_CLEAN_STATE;

//
// Performance Monitoring Structures for SVM
//
typedef struct {
  UINT64    VmrunCount;
  UINT64    VmExitCount;
  UINT64    LastVmExitReason;
  UINT64    TotalVmExitTime;
  UINT64    AverageVmExitTime;
  UINT64    MaxVmExitTime;
  UINT64    MinVmExitTime;
  UINT64    NptViolationCount;
  UINT64    MsrInterceptCount;
  UINT64    IoInterceptCount;
  UINT64    CpuidInterceptCount;
} HYPERVISOR_SVM_PERFORMANCE_DATA;

// Lightweight memory tracking for diagnosis (SVM)
typedef struct {
  UINT64  TotalPagesAllocated;
  UINT64  TotalPagesFreed;
  UINT64  OutstandingPages;
} HYPERVISOR_SVM_MEMORY_TRACKING;

//
// MiniVisor SVM Performance Data (alias for compatibility)
//
typedef HYPERVISOR_SVM_PERFORMANCE_DATA MINI_VISOR_SVM_PERFORMANCE_DATA;

//
// Hypervisor SVM Global State Structure
//
typedef struct {
  UINT32                              Signature;
  UINT32                              Version;
  UINT32                              Status;
  UINT32                              CpuCount;
  VOID                                *VmcbRegion;
  VOID                                *HostSaveArea;
  HYPERVISOR_SVM_PERFORMANCE_DATA     PerfData;
  HYPERVISOR_SVM_MEMORY_TRACKING      MemTrack;
  EFI_PHYSICAL_ADDRESS                GuestPhysicalBase;
  
  //
  // Advanced SVM features
  //
  ADVANCED_SVM_FEATURES               AdvancedFeatures;
  
  //
  // Nested SVM state
  //
  NESTED_SVM_STATE                    NestedState;
  
  //
  // AVIC management
  //
  AVIC_MANAGEMENT                     AvicState;
  
  //
  // VMCB clean state
  //
  VMCB_CLEAN_STATE                    CleanState;
  UINTN                               GuestPhysicalSize;
  SVM_CAPABILITIES                    SvmCapabilities;
  UINT32                              CurrentAsid;
  UINT32                              MaxAsid;
  BOOLEAN                             NptEnabled;
  BOOLEAN                             AvicEnabled;
  BOOLEAN                             LbrVirtEnabled;
  BOOLEAN                             UnifiedAuthEnabled;
  UINT32                              CompatibilityScore;
  EFI_PHYSICAL_ADDRESS                NptPml4Base;
  EFI_PHYSICAL_ADDRESS                MsrBitmapBase;
  EFI_PHYSICAL_ADDRESS                IoBitmapBase;
} HYPERVISOR_SVM_GLOBAL_DATA;

//
// MiniVisor SVM Global Data (alias for compatibility)
//
typedef HYPERVISOR_SVM_GLOBAL_DATA MINI_VISOR_SVM_GLOBAL_DATA;

//
// Comprehensive IOMMU Manager Structure
//
typedef struct {
  EFI_PHYSICAL_ADDRESS  MmioBase;
  EFI_PHYSICAL_ADDRESS  RegisterBaseAddress;
  UINT32                NumSegments;
  EFI_PHYSICAL_ADDRESS  SegmentMmioBases[16];
  UINT16                SegmentIds[16];
  UINT32                Control[16];
  UINT32                Status[16];
  UINT32                DtbHi[16];
  UINT32                DtbLo[16];
  UINT32                CmbHi[16];
  UINT32                CmbLo[16];
  UINT32                ElbHi[16];
  UINT32                ElbLo[16];
  UINT32                ExtFeatures[16];
  UINT32                PerfCounters[16][4];
  UINT64                ShadowMmio[16][256];
  UINT32                IvrsTableKey;
  UINT32                ExistingIvrsTableKey;
  BOOLEAN               CompatibilityMode;
  UINT64                AccessCount;
  UINT64                ControlEnableCount;
  UINT64                IotlbFlushCount;
  UINT64                CmbDoorbellCount;
  UINT64                StatusReadCount;
  UINT32                TimingSeed;
  UINT32                StateVector;
  UINT64                RandomizationSeed;
  UINT32                AntiDetectionMode;
  BOOLEAN               NptTrapsEnabled;
  EFI_PHYSICAL_ADDRESS  TrapRegionBase;
  UINT64                TrapRegionSize;
  UINT64                *TrapPageTable;
  UINT64                FakeDeviceTable[256];
  UINT64                FakeCommandBuffer[128];
  UINT64                FakeEventLog[64];
  UINT32                HypervisorSignature[4];
  UINT32                VirtualizationLevel;
  UINT64                HypervisorFeatures;
  UINT64                LastAccessTime;
  UINT64                AccessPattern[16];
  UINT32                BehaviorMode;
  UINT32                PerformanceProfile;
  UINT32                IntelCompatMode;
  UINT32                HyperVCompatMode;
  UINT32                VMwareCompatMode;
  UINT32                XenCompatMode;
  UINT8                 SpoofBus;
  UINT8                 SpoofDevice;
  UINT8                 SpoofFunction;
  BOOLEAN               SpoofLocked;
} COMPREHENSIVE_IOMMU_MANAGER;

//
// MiniVisor Global Data (alias for compatibility)
//
typedef HYPERVISOR_SVM_GLOBAL_DATA MINI_VISOR_GLOBAL_DATA;

//
// Function Prototypes
//

/**
  Allocate tracked pages for memory management.
  
  @param[in]  AllocateType     The type of allocation to perform.
  @param[in]  MemoryType       The type of memory to allocate.
  @param[in]  Pages            The number of pages to allocate.
  @param[out] Memory           Pointer to the allocated memory.
  
  @retval EFI_SUCCESS          Pages allocated successfully.
  @retval Others               Allocation failed.
**/
EFI_STATUS
MiniVisorAllocateTrackedPages (
  IN EFI_ALLOCATE_TYPE  AllocateType,
  IN EFI_MEMORY_TYPE    MemoryType,
  IN UINTN              Pages,
  OUT EFI_PHYSICAL_ADDRESS *Memory
  );

/**
  Free tracked pages for memory management.
  
  @param[in]  Memory           Pointer to the memory to free.
  @param[in]  Pages            The number of pages to free.
  
  @retval EFI_SUCCESS          Pages freed successfully.
  @retval Others               Free operation failed.
**/
EFI_STATUS
MiniVisorFreeTrackedPages (
  IN EFI_PHYSICAL_ADDRESS Memory,
  IN UINTN                Pages
  );

/**
  Initialize Hypervisor SVM hypervisor.
  
  @param[in] ImageHandle    The image handle of the driver.
  @param[in] SystemTable    The system table.
  
  @retval EFI_SUCCESS       Initialization successful.
  @retval Others            Initialization failed.
**/
EFI_STATUS
EFIAPI
HypervisorSvmInitialize (
  IN EFI_HANDLE         ImageHandle,
  IN EFI_SYSTEM_TABLE   *SystemTable
  );

/**
  Check if SVM is supported by the processor.
  
  @retval TRUE              SVM is supported.
  @retval FALSE             SVM is not supported.
**/
BOOLEAN
EFIAPI
IsSvmSupported (
  VOID
  );

/**
  Enable SVM on the current processor.
  
  @retval EFI_SUCCESS       SVM enabled successfully.
  @retval Others            Failed to enable SVM.
**/
EFI_STATUS
EFIAPI
EnableSvm (
  VOID
  );

/**
  Disable SVM on the current processor.
  
  @retval EFI_SUCCESS       SVM disabled successfully.
  @retval Others            Failed to disable SVM.
**/
EFI_STATUS
EFIAPI
DisableSvm (
  VOID
  );

/**
  Initialize VMCB (Virtual Machine Control Block).
  
  @param[in] VmcbPhysicalAddress    Physical address of VMCB.
  
  @retval EFI_SUCCESS               VMCB initialized successfully.
  @retval Others                    Failed to initialize VMCB.
**/
EFI_STATUS
EFIAPI
InitializeVmcb (
  IN EFI_PHYSICAL_ADDRESS VmcbPhysicalAddress
  );

/**
  Setup Nested Page Tables (NPT).
  
  @retval EFI_SUCCESS       NPT setup successfully.
  @retval Others            Failed to setup NPT.
**/
EFI_STATUS
EFIAPI
SetupNestedPageTables (
  VOID
  );

/**
  Initialize all advanced SVM features during driver startup.
  
  @retval EFI_SUCCESS       All features initialized successfully.
**/
EFI_STATUS
EFIAPI
InitializeAdvancedSvmFeatures (
  VOID
  );

/**
  Handle VM exit with fast path optimization.
  
  @param[in] ExitInfo       Pointer to exit information.
  @param[in] Context        Pointer to guest context.
  
  @retval EFI_SUCCESS       VM exit handled successfully.
**/
EFI_STATUS
EFIAPI
HandleVmExit (
  IN SVM_EXIT_INFO *ExitInfo,
  IN OUT NESTED_SVM_CONTEXT *Context
  );

/**
  Perform SVM security and integrity checks.
  
  @retval EFI_SUCCESS       Security checks passed.
  @retval Others            Security violation detected.
**/
EFI_STATUS
EFIAPI
PerformSvmSecurityChecks (
  VOID
  );

/**
  Update VMCB clean bits before VMRUN.
  
  @param[in] VmcbControl    Pointer to VMCB control area.
**/
VOID
EFIAPI
UpdateVmcbCleanBits (
  IN VMCB_CONTROL_AREA *VmcbControl
  );

/**
  Launch the guest using SVM.
  
  @retval EFI_SUCCESS       Guest launched successfully.
  @retval Others            Failed to launch guest.
**/
EFI_STATUS
EFIAPI
LaunchGuest (
  VOID
  );

/**
  Handle SVM VM Exit.
  
  @param[in] ExitCode       The SVM exit code.
  @param[in] ExitInfo       Pointer to exit information.
  @param[in] Context        Pointer to guest context.
  
  @retval EFI_SUCCESS       Exit handled successfully.
  @retval Others            Failed to handle exit.
**/
EFI_STATUS
EFIAPI
HandleSvmExit (
  IN UINT64 ExitCode,
  IN SVM_EXIT_INFO *ExitInfo,
  IN OUT NESTED_SVM_CONTEXT *Context
  );

/**
  Get Hypervisor SVM status information.
  
  @param[out] StatusInfo    Pointer to receive status information.
  
  @retval EFI_SUCCESS       Status retrieved successfully.
  @retval EFI_INVALID_PARAMETER  StatusInfo is NULL.
**/
EFI_STATUS
EFIAPI
HypervisorSvmGetStatus (
  OUT HYPERVISOR_SVM_GLOBAL_DATA  *StatusInfo
  );

/**
  Get Hypervisor SVM performance data.
  
  @param[out] PerfData      Pointer to receive performance data.
  
  @retval EFI_SUCCESS       Performance data retrieved successfully.
  @retval EFI_INVALID_PARAMETER  PerfData is NULL.
**/
EFI_STATUS
EFIAPI
HypervisorSvmGetPerformanceData (
  OUT HYPERVISOR_SVM_PERFORMANCE_DATA  *PerfData
  );

/**
  Reset Hypervisor SVM performance counters.
  
  @retval EFI_SUCCESS       Performance counters reset successfully.
**/
EFI_STATUS
EFIAPI
HypervisorSvmResetPerformanceCounters (
  VOID
  );

// Memory tracking helpers (wrappers around gBS->AllocatePages/FreePages)
EFI_STATUS
EFIAPI
SvmAllocateTrackedPages (
  IN EFI_ALLOCATE_TYPE     Type,
  IN EFI_MEMORY_TYPE       MemoryType,
  IN UINTN                 Pages,
  IN OUT EFI_PHYSICAL_ADDRESS *Memory
  );

EFI_STATUS
EFIAPI
SvmFreeTrackedPages (
  IN EFI_PHYSICAL_ADDRESS  Memory,
  IN UINTN                 Pages
  );

/**
  Enable or disable Hypervisor SVM debug output.
  
  @param[in] Enable         TRUE to enable debug output, FALSE to disable.
  
  @retval EFI_SUCCESS       Debug mode updated successfully.
**/
EFI_STATUS
EFIAPI
HypervisorSvmSetDebugMode (
  IN BOOLEAN  Enable
  );

/**
  Check SVM capabilities.
  
  @param[out] Capabilities  Pointer to receive SVM capabilities.
  
  @retval EFI_SUCCESS       Capabilities retrieved successfully.
  @retval EFI_INVALID_PARAMETER  Capabilities is NULL.
**/
EFI_STATUS
EFIAPI
GetSvmCapabilities (
  OUT SVM_CAPABILITIES *Capabilities
  );

/**
  Allocate ASID (Address Space Identifier).
  
  @param[out] Asid          Pointer to receive allocated ASID.
  
  @retval EFI_SUCCESS       ASID allocated successfully.
  @retval EFI_OUT_OF_RESOURCES  No ASID available.
**/
EFI_STATUS
EFIAPI
AllocateAsid (
  OUT UINT32 *Asid
  );

/**
  Free ASID (Address Space Identifier).
  
  @param[in] Asid           ASID to free.
  
  @retval EFI_SUCCESS       ASID freed successfully.
  @retval EFI_INVALID_PARAMETER  Invalid ASID.
**/
EFI_STATUS
EFIAPI
FreeAsid (
  IN UINT32 Asid
  );

/**
  Setup MSR bitmap for SVM.
  
  @retval EFI_SUCCESS       MSR bitmap setup successfully.
  @retval Others            Failed to setup MSR bitmap.
**/
EFI_STATUS
EFIAPI
SetupMsrBitmap (
  VOID
  );

/**
  Setup I/O bitmap for SVM.
  
  @retval EFI_SUCCESS       I/O bitmap setup successfully.
  @retval Others            Failed to setup I/O bitmap.
**/
EFI_STATUS
EFIAPI
SetupIoBitmap (
  VOID
  );

/**
  Handle CPUID VM Exit.
  
  @param[in] Context        Pointer to guest context.
  
  @retval EFI_SUCCESS       CPUID handled successfully.
**/
EFI_STATUS
EFIAPI
HandleCpuidExit (
  IN OUT NESTED_SVM_CONTEXT *Context
  );

/**
  Handle MSR access VM Exit.
  
  @param[in] ExitInfo       Pointer to exit information.
  @param[in] Context        Pointer to guest context.
  
  @retval EFI_SUCCESS       MSR access handled successfully.
**/
EFI_STATUS
EFIAPI
HandleMsrExit (
  IN SVM_EXIT_INFO *ExitInfo,
  IN OUT NESTED_SVM_CONTEXT *Context
  );

/**
  Handle NPT violation VM Exit.
  
  @param[in] ExitInfo       Pointer to exit information.
  @param[in] Context        Pointer to guest context.
  
  @retval EFI_SUCCESS       NPT violation handled successfully.
**/
EFI_STATUS
EFIAPI
HandleNptViolation (
  IN SVM_EXIT_INFO *ExitInfo,
  IN OUT NESTED_SVM_CONTEXT *Context
  );

/**
  Handle I/O instruction VM Exit.
  
  @param[in] ExitInfo       Pointer to exit information.
  @param[in] Context        Pointer to guest context.
  
  @retval EFI_SUCCESS       I/O instruction handled successfully.
**/
EFI_STATUS
EFIAPI
HandleIoExit (
  IN SVM_EXIT_INFO *ExitInfo,
  IN OUT NESTED_SVM_CONTEXT *Context
  );

/**
  Handle I/O instruction VM exit (implementation name).
  This is the implementation used by the dispatcher.
**/
EFI_STATUS
EFIAPI
HandleIoInstruction (
  IN SVM_EXIT_INFO *ExitInfo,
  IN OUT NESTED_SVM_CONTEXT *Context
  );

// Internal helper forward declarations used across this compilation unit
EFI_STATUS EFIAPI SetupAmdViMmioTraps(VOID);
EFI_STATUS EFIAPI SplitNptPagesForMmioRange(IN EFI_PHYSICAL_ADDRESS MmioBase, IN UINT64 Size);
EFI_STATUS EFIAPI MarkNptRangeNonPresent(IN EFI_PHYSICAL_ADDRESS Base, IN UINT64 Size);
EFI_STATUS EFIAPI HandleIommuMmioWrite(IN UINTN SegmentIndex, IN UINT32 Offset, IN UINT32 Value, IN OUT NESTED_SVM_CONTEXT *Context);
EFI_STATUS EFIAPI HandleIommuMmioRead(IN UINTN SegmentIndex, IN UINT32 Offset, IN OUT NESTED_SVM_CONTEXT *Context);
EFI_STATUS EFIAPI HandlePciConfigAccess(IN OUT NESTED_SVM_CONTEXT *Context, IN BOOLEAN IsWrite, IN UINT16 Port, IN UINT8 Size);
BOOLEAN    EFIAPI IsAmdIommuDevice(IN UINT8 Bus, IN UINT8 Device, IN UINT8 Function);
EFI_STATUS EFIAPI HandleIommuPciConfigWrite(IN UINT8 Bus, IN UINT8 Device, IN UINT8 Function, IN UINT8 Register, IN UINT32 Value, IN UINT8 Size, IN OUT NESTED_SVM_CONTEXT *Context);
EFI_STATUS EFIAPI HandleIommuPciConfigRead(IN UINT8 Bus, IN UINT8 Device, IN UINT8 Function, IN UINT8 Register, IN UINT8 Size, IN OUT NESTED_SVM_CONTEXT *Context);

EFI_STATUS EFIAPI HandleNestedVmrun(IN SVM_EXIT_INFO *ExitInfo, IN OUT NESTED_SVM_CONTEXT *Context);
EFI_STATUS EFIAPI HandleVmmcallExit(IN SVM_EXIT_INFO *ExitInfo, IN OUT NESTED_SVM_CONTEXT *Context);
EFI_STATUS EFIAPI HandleSvmInstruction(IN SVM_EXIT_INFO *ExitInfo, IN OUT NESTED_SVM_CONTEXT *Context);
EFI_STATUS EFIAPI HandleAvicIncompleteIpi(IN SVM_EXIT_INFO *ExitInfo, IN OUT NESTED_SVM_CONTEXT *Context);
EFI_STATUS EFIAPI HandleAvicUnacceleratedAccess(IN SVM_EXIT_INFO *ExitInfo, IN OUT NESTED_SVM_CONTEXT *Context);
EFI_STATUS EFIAPI InjectException(IN OUT NESTED_SVM_CONTEXT *Context, IN UINT8 Vector, IN UINT32 ErrorCode);

/**
  Handle RDTSC instruction.
  
  @param[in] Context        Pointer to guest context.
  
  @retval EFI_SUCCESS       RDTSC handled successfully.
**/
EFI_STATUS
EFIAPI
HandleRdtscExit (
  IN OUT NESTED_SVM_CONTEXT *Context
  );

/**
  Handle RDTSCP instruction.
  
  @param[in] Context        Pointer to guest context.
  
  @retval EFI_SUCCESS       RDTSCP handled successfully.
**/
EFI_STATUS
EFIAPI
HandleRdtscpExit (
  IN OUT NESTED_SVM_CONTEXT *Context
  );

/**
  Handle RDPMC instruction.
  
  @param[in] Context        Pointer to guest context.
  
  @retval EFI_SUCCESS       RDPMC handled successfully.
**/
EFI_STATUS
EFIAPI
HandleRdpmcExit (
  IN OUT NESTED_SVM_CONTEXT *Context
  );

/**
  Handle VMMCALL instruction.
  
  @param[in] Context        Pointer to guest context.
  
  @retval EFI_SUCCESS       VMMCALL handled successfully.
**/
EFI_STATUS
EFIAPI
HandleVmmcall (
  IN OUT NESTED_SVM_CONTEXT *Context
  );

/**
  Initialize advanced IOMMU manager for enhanced compatibility.
  
  @retval EFI_SUCCESS       IOMMU manager initialized successfully.
  @retval Others            Failed to initialize IOMMU manager.
**/
EFI_STATUS
EFIAPI
InitializeAdvancedIommuManager (
  VOID
  );

//
// Assembly function prototypes
//

/**
  Enable SVM by setting EFER.SVME bit.
  
  @retval EFI_SUCCESS       SVM enabled successfully.
  @retval Others            Failed to enable SVM.
**/
EFI_STATUS
EFIAPI
AsmEnableSvm (
  VOID
  );

/**
  Disable SVM by clearing EFER.SVME bit.
  
  @retval EFI_SUCCESS       SVM disabled successfully.
  @retval Others            Failed to disable SVM.
**/
EFI_STATUS
EFIAPI
AsmDisableSvm (
  VOID
  );

/**
  Execute VMRUN instruction.
  
  @param[in] VmcbPhysicalAddress    Physical address of VMCB.
  
  @retval EFI_SUCCESS               VMRUN executed successfully.
  @retval Others                    VMRUN failed.
**/
EFI_STATUS
EFIAPI
AsmVmrun (
  IN EFI_PHYSICAL_ADDRESS VmcbPhysicalAddress
  );

/**
  Execute VMSAVE instruction.
  
  @param[in] VmcbPhysicalAddress    Physical address of VMCB.
  
  @retval EFI_SUCCESS               VMSAVE executed successfully.
  @retval Others                    VMSAVE failed.
**/
EFI_STATUS
EFIAPI
AsmVmsave (
  IN EFI_PHYSICAL_ADDRESS VmcbPhysicalAddress
  );

/**
  Execute VMLOAD instruction.
  
  @param[in] VmcbPhysicalAddress    Physical address of VMCB.
  
  @retval EFI_SUCCESS               VMLOAD executed successfully.
  @retval Others                    VMLOAD failed.
**/
EFI_STATUS
EFIAPI
AsmVmload (
  IN EFI_PHYSICAL_ADDRESS VmcbPhysicalAddress
  );

/**
  Execute VMMCALL instruction.
  
  @retval EFI_SUCCESS               VMMCALL executed successfully.
  @retval Others                    VMMCALL failed.
**/
EFI_STATUS
EFIAPI
AsmVmmcall (
  VOID
  );

/**
  Execute STGI instruction (Set Global Interrupt Flag).
  
  @retval EFI_SUCCESS               STGI executed successfully.
**/
EFI_STATUS
EFIAPI
AsmStgi (
  VOID
  );

/**
  Execute CLGI instruction (Clear Global Interrupt Flag).
  
  @retval EFI_SUCCESS               CLGI executed successfully.
**/
EFI_STATUS
EFIAPI
AsmClgi (
  VOID
  );

/**
  Get current processor number for SMP support.
  
  @return                   Current processor number.
**/
UINT32
EFIAPI
AsmGetCurrentProcessorNumber (
  VOID
  );

//
// Next-Generation Authorization System
//
extern MINI_VISOR_AUTH_CONTEXT gSvmAuthContext;

/**
  Initialize SVM authorization system with next-generation features.
  
  @retval EFI_SUCCESS          Authorization system initialized successfully.
  @retval Others               Initialization failed.
**/
EFI_STATUS
EFIAPI
SvmAuthInitializeNextGen (
  VOID
  );

/**
  Verify authorization using the unified Hypervisor system.
  
  @retval MINI_VISOR_AUTH_STATUS Authorization status.
**/
MINI_VISOR_AUTH_STATUS
EFIAPI
SvmAuthVerifyUnified (
  VOID
  );

/**
  Display comprehensive authorization status for SVM driver.
  
  @param[in] Verbose           TRUE for detailed output.
  
  @retval EFI_SUCCESS          Status displayed successfully.
**/
EFI_STATUS
EFIAPI
SvmAuthDisplayStatus (
  IN BOOLEAN Verbose
  );

/**
  Generate SVM hardware fingerprint.
  
  @param[out] Fingerprint      Pointer to receive hardware fingerprint.
  
  @retval EFI_SUCCESS          Fingerprint generated successfully.
  @retval EFI_INVALID_PARAMETER Fingerprint is NULL.
**/
EFI_STATUS
EFIAPI
SvmGenerateHardwareFingerprint (
  OUT SVM_HARDWARE_FINGERPRINT *Fingerprint
  );

/**
  Verify authorization using the unified library system.
  
  @retval EFI_SUCCESS          Authorization verified successfully.
  @retval Others               Authorization failed.
**/
EFI_STATUS
EFIAPI
SvmAuthVerifyUnifiedLibrary (
  VOID
  );

//
// Global Variables
//
extern HYPERVISOR_SVM_GLOBAL_DATA  gMiniVisorSvmGlobalData;
extern BOOLEAN                     gMiniVisorSvmDebugMode;
extern RING2_SVM_MANAGER           gSvmManager;
extern MINI_VISOR_UNIVERSAL_AUTHORIZATION gSvmAuthInfo;
extern MINI_VISOR_AUTH_CONTEXT gHypervisorAuthContext;
extern MINI_VISOR_AUTH_STATUS gSvmAuthStatus;

//
// IOMMU Manager
//
extern COMPREHENSIVE_IOMMU_MANAGER gIommuManager;

//
// Constants
//
#define SVM_AUTH_UNAUTHORIZED    0
#define SVM_AUTH_AUTHORIZED      1
#define SVM_AUTH_EXPIRED         2
#define SVM_AUTH_INVALID         3
#define SVM_AUTH_OVER_LIMIT      4

//
// SVM Authorization Constants
//
#define SVM_AUTH_SIGNATURE       0x4D56534D  // 'MVSM'
#define SVM_AUTH_VERSION         0x00010001  // Version 1.0.1

//
// Type definitions
//
typedef UINT32 SVM_AUTH_STATUS;

//
// Function declarations
//
EFI_STATUS
EFIAPI
SvmAuthVerifyLicense (
  IN UINT8 *LicenseData,
  IN UINTN LicenseSize
  );

UINT32
SvmSimpleHash (
  IN UINT8 *Data,
  IN UINTN DataSize
  );

EFI_STATUS
SvmRsaVerifySignature (
  IN UINT8 *Data,
  IN UINTN DataSize,
  IN UINT8 *Signature,
  IN UINT8 *PublicKey
  );

//
// Utility Macros
//
#define HYPERVISOR_SVM_SIGNATURE  SIGNATURE_32('H','Y','S','V')
#define MINI_VISOR_SVM_SIGNATURE  SIGNATURE_32('M','V','S','V')
#define MINI_VISOR_SIGNATURE      SIGNATURE_32('M','I','N','V')

#define IS_HYPERVISOR_SVM_INITIALIZED() \
  ((gMiniVisorSvmGlobalData.Status & HYPERVISOR_SVM_STATUS_INITIALIZED) != 0)

#define IS_SVM_ENABLED() \
  ((gMiniVisorSvmGlobalData.Status & HYPERVISOR_SVM_STATUS_SVM_ENABLED) != 0)

#define IS_NPT_ENABLED() \
  ((gMiniVisorSvmGlobalData.Status & HYPERVISOR_SVM_STATUS_NPT_ENABLED) != 0)

#define IS_MINI_VISOR_INITIALIZED() \
  ((gMiniVisorSvmGlobalData.Status & MINI_VISOR_STATUS_INITIALIZED) != 0)

#define HYPERVISOR_SVM_DEBUG(Expression) \
  do { \
    if (gMiniVisorSvmDebugMode) { \
      DEBUG(Expression); \
    } \
  } while (FALSE)

#define MINI_VISOR_SVM_DEBUG(Expression) \
  do { \
    if (gMiniVisorSvmDebugMode) { \
      DEBUG(Expression); \
    } \
  } while (FALSE)

#define MINI_VISOR_DEBUG(Expression) \
  do { \
    if (gMiniVisorSvmDebugMode) { \
      DEBUG(Expression); \
    } \
  } while (FALSE)

//
// Memory allocation alignment macros
//
#define VMCB_ALIGNMENT              4096
#define HOST_SAVE_AREA_ALIGNMENT    4096
#define NPT_ALIGNMENT               4096

#define ALIGN_UP(Address, Alignment) \
  (((Address) + (Alignment) - 1) & ~((Alignment) - 1))

#define ALIGN_DOWN(Address, Alignment) \
  ((Address) & ~((Alignment) - 1))

//
// AMD-Vi Status Bits
//
#define AMDVI_STATUS_READY                   BIT0
#define AMDVI_STATUS_CMD_DONE                BIT1

//
// SVM Error Codes
//
#define SVM_ERROR_SUCCESS                    0x00000000
#define SVM_ERROR_NOT_SUPPORTED              0x00000001
#define SVM_ERROR_ALREADY_ENABLED            0x00000002
#define SVM_ERROR_NOT_ENABLED                0x00000003
#define SVM_ERROR_INVALID_VMCB               0x00000004
#define SVM_ERROR_INVALID_PARAMETER          0x00000005
#define SVM_ERROR_OUT_OF_RESOURCES           0x00000006
#define SVM_ERROR_NPT_NOT_SUPPORTED          0x00000007
#define SVM_ERROR_ASID_EXHAUSTED             0x00000008
#define SVM_ERROR_VMRUN_FAILED               0x00000009
#define SVM_ERROR_UNEXPECTED_EXIT            0x0000000A

#endif // __HYPERVISOR_SVM_DXE_H__
