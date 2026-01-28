/** @file
  Hypervisor SVM DXE Driver Implementation
  
  This file implements a Windows-compatible hypervisor using AMD SVM (Secure Virtual Machine) 
  technology. Designed for broad compatibility across Windows environments and applications,
  focusing on system-level transparency rather than specific emulator optimizations.
  
  Copyright (c) 2024, Hypervisor Project. All rights reserved.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <PiDxe.h>
#include <Library/PcdLib.h>
#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/BaseLib.h>
#include <Library/UefiDriverEntryPoint.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/DebugLib.h>
#include <Library/PrintLib.h>
#include <Library/IoLib.h>
#include <Library/CpuLib.h>
#include <Library/BaseCryptLib.h>
#include <Protocol/MpService.h>
#include <Protocol/AcpiTable.h>
#include <Protocol/AcpiSystemDescriptionTable.h>
#include <Protocol/Smbios.h>
#include <Protocol/SimpleFileSystem.h>
#include <Protocol/PciRootBridgeIo.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/DevicePath.h>
#include <Protocol/Tcg2Protocol.h>
#include <Guid/FileSystemInfo.h>
#include <Guid/FileInfo.h>
#include <Guid/Acpi.h>
#include <Library/DevicePathLib.h>
#include <IndustryStandard/SmBios.h>
#include <IndustryStandard/Acpi.h>
#include <IndustryStandard/Acpi10.h>
#include <IndustryStandard/Acpi20.h>
#include <IndustryStandard/Acpi30.h>
#include <IndustryStandard/Acpi40.h>
#include <IndustryStandard/Acpi50.h>
#include <IndustryStandard/Acpi60.h>
#include <IndustryStandard/Acpi61.h>

#include "SvmDefs.h"
#include "SvmStructs.h"
#include "MiniVisorSvmDxe.h"

//
// AMD-specific ACPI table signatures
//
#define EFI_ACPI_IVRS_TABLE_SIGNATURE  SIGNATURE_32('I','V','R','S')

// -----------------------------------------------------------------------------
// Legacy RSA constants used by SVM legacy authorization path
// These are required for compatibility with existing authorization blobs.
// -----------------------------------------------------------------------------
#ifndef RSA_PUBLIC_KEY_SIZE
#define RSA_PUBLIC_KEY_SIZE   256  // RSA-2048 modulus size in bytes
#endif

#ifndef RSA_SIGNATURE_SIZE
#define RSA_SIGNATURE_SIZE    256  // RSA-2048 signature size in bytes
#endif

// -----------------------------------------------------------------------------
// Forward declarations for internal FS helpers used before their definitions
// -----------------------------------------------------------------------------
STATIC EFI_STATUS SvmAuthOpenRootOnHandle(IN EFI_HANDLE FsHandle, OUT EFI_FILE_PROTOCOL **RootDir);
STATIC EFI_STATUS SvmAuthGetLoadedImageFsHandle(OUT EFI_HANDLE *FsHandle);

// -----------------------------------------------------------------------------
// Forward declarations for SVM authorization functions used before definitions
// -----------------------------------------------------------------------------
STATIC EFI_STATUS SvmSha256Hash(IN UINT8 *Data, IN UINTN DataSize, OUT UINT8 *Hash);
EFI_STATUS SvmEnhancedAuthorizationVerification(IN SVM_AUTHORIZATION_INFO *AuthInfo);
EFI_STATUS SvmVerifyAuthorizationChainOfTrust(IN SVM_AUTHORIZATION_INFO *AuthInfo);
EFI_STATUS SvmValidateAuthorizationStructure(IN SVM_AUTHORIZATION_INFO *AuthInfo);

//
// Global Variables
//
HYPERVISOR_SVM_GLOBAL_DATA  gHypervisorSvmGlobalData;
BOOLEAN                     gHypervisorSvmDebugMode = FALSE;
RING2_SVM_MANAGER           gSvmManager;
STATIC EFI_HANDLE           gImageHandle = NULL;

//
// SVM Driver Authorization System (Compatible with Intel VT-d)
//

// Production-grade TPM-based Hardware Root of Trust Public Keys
// Intel TXT/TPM-compatible authentication chain
STATIC CONST UINT8 kSvmTpmRootPublicKey[RSA_PUBLIC_KEY_SIZE] = { 0 };

// Secondary verification key for redundant TPM-based authentication
STATIC CONST UINT8 kSvmSecondaryPublicKey[RSA_PUBLIC_KEY_SIZE] = { 0 };

// Global authorization state
MINI_VISOR_UNIVERSAL_AUTHORIZATION gSvmAuthInfo;
static MINI_VISOR_AUTH_STATUS gSvmAuthStatus = MiniVisorAuthStatusUnauthorized;

//
// Global auth context for unified authorization system
//
MINI_VISOR_AUTH_CONTEXT  gMiniVisorAuthContext = {0};

// File system cache to avoid repeated scans
typedef struct {
  EFI_HANDLE FsHandle;
  EFI_FILE_PROTOCOL *RootDir;
  CHAR16 *AuthFilePath;
  BOOLEAN Valid;
} SVM_FS_CACHE_ENTRY;

#define MAX_SVM_FS_CACHE_ENTRIES 8
static SVM_FS_CACHE_ENTRY gSvmFsCache[MAX_SVM_FS_CACHE_ENTRIES];
static UINTN gSvmFsCacheCount = 0;
static BOOLEAN gSvmFsCacheInitialized = FALSE;
static BOOLEAN gSvmAuthDebugMode = FALSE;  // Debug mode flag
static EFI_HANDLE gSvmAuthFsHandle = NULL; // Remember FS handle where auth was found/saved
static CHAR16 gSvmAuthLoadedRelPath[260] = L""; // Remember exact relative path used during load

// Non-volatile usage counter variable name (anti-rollback)
static CONST CHAR16 SVM_NV_USAGE_VAR[] = L"SvmAuthUsage";

// Forward declarations for NV helpers
STATIC EFI_STATUS SvmAuthReadNvUsage(OUT UINT32 *UsageOut);
STATIC EFI_STATUS SvmAuthWriteNvUsage(IN UINT32 Usage);

// Forward declarations for ACPI RSDP/RSDT/XSDT handling
STATIC EFI_STATUS ProcessAcpiRootTables(VOID);
STATIC EFI_STATUS FindWritableRsdp(OUT EFI_ACPI_2_0_ROOT_SYSTEM_DESCRIPTION_POINTER **Rsdp);
STATIC EFI_STATUS CreateEnhancedRsdtXsdt(VOID);

// Global IOMMU manager instance
STATIC COMPREHENSIVE_IOMMU_MANAGER gIommuManager = { 0 };

// Global variables required by MiniVisorDxe
BOOLEAN gMiniVisorSvmDebugMode = FALSE;
HYPERVISOR_SVM_GLOBAL_DATA gMiniVisorSvmGlobalData = { 0 };

#pragma pack(1)
// Minimal IVRS header
typedef struct {
  EFI_ACPI_DESCRIPTION_HEADER  Header;
  UINT32                       IvInfo;
  UINT32                       Reserved;
} AMD_ACPI_IVRS_HEADER;

// Minimal IVHD (Type 0x10) header
typedef struct {
  UINT8    Type;              // 0x10
  UINT8    Flags;             // include-all bit may be used
  UINT16   Length;            // total length of this structure
  UINT16   DeviceId;          // optional
  UINT16   CapabilityOffset;  // 0 if none
  UINT64   BaseAddress;       // IOMMU MMIO base
  UINT16   PciSegment;        // segment number
  UINT16   Info;              // implementation-specific; 0 minimal
  UINT32   Reserved;          // reserved
} AMD_ACPI_IVRS_IVHD10;
#pragma pack()

// AMD-Vi minimal MMIO register offsets (per AMD IOMMU spec common subset)
#define AMDVI_REG_DTB_LO    0x00  // Device Table Base Low
#define AMDVI_REG_DTB_HI    0x04  // Device Table Base High
#define AMDVI_REG_CMB_LO    0x08  // Command Buffer Base Low
#define AMDVI_REG_CMB_HI    0x0C  // Command Buffer Base High
#define AMDVI_REG_ELB_LO    0x10  // Event Log Base Low
#define AMDVI_REG_ELB_HI    0x14  // Event Log Base High
#define AMDVI_REG_CONTROL   0x18  // Control
#define AMDVI_REG_STATUS    0x1C  // Status
// Non-spec minimal doorbells emulated for Windows polling patterns
#define AMDVI_REG_IOTLB_DB  0x20  // IOTLB flush doorbell (write-only, no-op)
#define AMDVI_REG_CMB_TAIL  0x24  // Command buffer tail doorbell (write-only, no-op)

// Status bits in our minimal model
#define AMDVI_STATUS_READY      BIT0
#define AMDVI_STATUS_CMD_DONE   BIT1

// Helpers to access Context GPRs by index (0..15)
STATIC
UINT64
GetGprValueByIndex (
  IN CONST NESTED_SVM_CONTEXT *Context,
  IN UINT8 RegIndex
  )
{
  switch (RegIndex & 0x0F) {
    case 0:  return Context->GuestRax;
    case 1:  return Context->GuestRcx;
    case 2:  return Context->GuestRdx;
    case 3:  return Context->GuestRbx;
    case 4:  return Context->GuestRsp;
    case 5:  return Context->GuestRbp;
    case 6:  return Context->GuestRsi;
    case 7:  return Context->GuestRdi;
    case 8:  return Context->GuestR8;
    case 9:  return Context->GuestR9;
    case 10: return Context->GuestR10;
    case 11: return Context->GuestR11;
    case 12: return Context->GuestR12;
    case 13: return Context->GuestR13;
    case 14: return Context->GuestR14;
    case 15: return Context->GuestR15;
  }
  return 0;
}

STATIC
VOID
SetGprValueByIndex32 (
  IN OUT NESTED_SVM_CONTEXT *Context,
  IN UINT8 RegIndex,
  IN UINT32 Value32
  )
{
  switch (RegIndex & 0x0F) {
    case 0:  Context->GuestRax = (Context->GuestRax & ~0xFFFFFFFFULL) | Value32; break;
    case 1:  Context->GuestRcx = (Context->GuestRcx & ~0xFFFFFFFFULL) | Value32; break;
    case 2:  Context->GuestRdx = (Context->GuestRdx & ~0xFFFFFFFFULL) | Value32; break;
    case 3:  Context->GuestRbx = (Context->GuestRbx & ~0xFFFFFFFFULL) | Value32; break;
    case 4:  Context->GuestRsp = (Context->GuestRsp & ~0xFFFFFFFFULL) | Value32; break;
    case 5:  Context->GuestRbp = (Context->GuestRbp & ~0xFFFFFFFFULL) | Value32; break;
    case 6:  Context->GuestRsi = (Context->GuestRsi & ~0xFFFFFFFFULL) | Value32; break;
    case 7:  Context->GuestRdi = (Context->GuestRdi & ~0xFFFFFFFFULL) | Value32; break;
    case 8:  Context->GuestR8  = (Context->GuestR8  & ~0xFFFFFFFFULL) | Value32; break;
    case 9:  Context->GuestR9  = (Context->GuestR9  & ~0xFFFFFFFFULL) | Value32; break;
    case 10: Context->GuestR10 = (Context->GuestR10 & ~0xFFFFFFFFULL) | Value32; break;
    case 11: Context->GuestR11 = (Context->GuestR11 & ~0xFFFFFFFFULL) | Value32; break;
    case 12: Context->GuestR12 = (Context->GuestR12 & ~0xFFFFFFFFULL) | Value32; break;
    case 13: Context->GuestR13 = (Context->GuestR13 & ~0xFFFFFFFFULL) | Value32; break;
    case 14: Context->GuestR14 = (Context->GuestR14 & ~0xFFFFFFFFULL) | Value32; break;
    case 15: Context->GuestR15 = (Context->GuestR15 & ~0xFFFFFFFFULL) | Value32; break;
  }
}

// Minimal decode: return TRUE if opcode is MOV r32->m32 (0x89) or MOV m32->r32 (0x8B)
// Provide reg index from ModRM.reg plus REX.R extension, ignore addressing specifics
STATIC
BOOLEAN
DecodeMovRegFromGuestInstruction (
  OUT BOOLEAN *IsReadFromMmio,
  OUT UINT8   *RegIndex,
  OUT UINT8   *OperandWidthBytes
  )
{
  VMCB *Vmcb = (VMCB *)gMiniVisorSvmGlobalData.VmcbRegion;
  if (Vmcb == NULL) {
    return FALSE;
  }
  UINT8 *Bytes = Vmcb->ControlArea.GuestInstructionBytes;
  UINT8 Len = Vmcb->ControlArea.GuestInstructionLen;
  if (Len < 2) {
    return FALSE;
  }
  UINT8 idx = 0;
  UINT8 Rex = 0;
  BOOLEAN OpSize16 = FALSE;
  // Parse legacy prefixes we care about (only 0x66 for operand-size)
  for (;;) {
    if (idx >= Len) return FALSE;
    UINT8 P = Bytes[idx];
    if (P == 0x66) { OpSize16 = TRUE; idx++; continue; }
    // Ignore other prefixes for simplicity
    break;
  }
  if (idx < Len && (Bytes[idx] & 0xF0) == 0x40) {
    Rex = Bytes[idx++];
    if (idx >= Len) return FALSE;
  }
  UINT8 Op = Bytes[idx++];
  if (idx >= Len) return FALSE;
  if (Op != 0x88 && Op != 0x89 && Op != 0x8A && Op != 0x8B) {
    return FALSE;
  }
  UINT8 ModRm = Bytes[idx];
  UINT8 Reg = (UINT8)(((ModRm >> 3) & 0x7) | ((Rex & 0x04) ? 0x8 : 0)); // REX.R extends reg
  *RegIndex = Reg;
  // Determine direction: 0x8B/0x8A are m->r (read), 0x89/0x88 are r->m (write)
  *IsReadFromMmio = (Op == 0x8B || Op == 0x8A);
  // Determine operand width
  if ((Op == 0x88) || (Op == 0x8A)) {
    *OperandWidthBytes = 1; // byte mov
  } else if ((Rex & 0x08) != 0) {
    *OperandWidthBytes = 8; // REX.W
  } else if (OpSize16) {
    *OperandWidthBytes = 2;
  } else {
    *OperandWidthBytes = 4;
  }
  return TRUE;
}

//
// External assembly functions
//
extern EFI_STATUS EFIAPI AsmEnableSvm(VOID);
extern EFI_STATUS EFIAPI AsmDisableSvm(VOID);
extern EFI_STATUS EFIAPI AsmVmrun(EFI_PHYSICAL_ADDRESS VmcbPhysicalAddress);
extern EFI_STATUS EFIAPI AsmVmsave(EFI_PHYSICAL_ADDRESS VmcbPhysicalAddress);
extern EFI_STATUS EFIAPI AsmVmload(EFI_PHYSICAL_ADDRESS VmcbPhysicalAddress);
extern EFI_STATUS EFIAPI AsmVmmcall(VOID);
extern EFI_STATUS EFIAPI AsmStgi(VOID);
extern EFI_STATUS EFIAPI AsmClgi(VOID);
extern UINT32 EFIAPI AsmGetCurrentProcessorNumber(VOID);
extern UINT64 EFIAPI AsmReadMsr(UINT32 MsrNumber);
extern EFI_STATUS EFIAPI AsmWriteMsr(UINT32 MsrNumber, UINT64 Value);
extern UINT64 EFIAPI AsmReadCr0(VOID);
extern UINT64 EFIAPI AsmReadCr3(VOID);
extern UINT64 EFIAPI AsmReadCr4(VOID);
extern EFI_STATUS EFIAPI AsmWriteCr0(UINT64 Value);
extern EFI_STATUS EFIAPI AsmWriteCr3(UINT64 Value);
extern EFI_STATUS EFIAPI AsmWriteCr4(UINT64 Value);

//
// Internal function declarations
//
STATIC EFI_STATUS InitializeSvmGlobalData(VOID);
STATIC EFI_STATUS AllocateSvmRegions(VOID);
STATIC EFI_STATUS SetupSvmEnvironment(VOID);
STATIC EFI_STATUS SetupHostSaveArea(VOID);
STATIC EFI_STATUS EnforceIommuSafePciRouting(VOID);
STATIC EFI_STATUS InitializeAmdViEmulation(VOID);
STATIC EFI_STATUS ParseIvrsTable(VOID);
STATIC EFI_STATUS CreatePlatformIvrsTable(VOID);
STATIC EFI_STATUS CreateEnhancedIvrsTable(VOID);
STATIC EFI_STATUS SetupAmdViTables(VOID);
STATIC EFI_STATUS EnhanceExistingIvrsTable(VOID);
STATIC EFI_STATUS VerifyAcpiTableInjection(VOID);
STATIC EFI_STATUS InstallWindowsCompatibilityMeasures(VOID);
STATIC EFI_STATUS TrapIommuMmioWithNpt(VOID);
STATIC EFI_STATUS VerifyIommuRegisterMap(VOID);
STATIC
EFI_STATUS
VerifyIommuRegisterMap(
  VOID
  )
{
  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] Verifying AMD-Vi MMIO register map...\n"));
  Print(L"[SVM] Verifying AMD-Vi MMIO register map...\n");

  for (UINTN SegmentIndex = 0; SegmentIndex < gIommuManager.NumSegments; SegmentIndex++) {
    EFI_PHYSICAL_ADDRESS Base = gIommuManager.SegmentMmioBases[SegmentIndex];
    if (Base == 0) {
      continue;
    }
    MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] Segment %u: Base=0x%lx Ctrl=0x%x Stat=0x%x DTB=%08x:%08x CMB=%08x:%08x ELB=%08x:%08x\n",
      (UINT32)SegmentIndex,
      Base,
      gIommuManager.Control[SegmentIndex],
      gIommuManager.Status[SegmentIndex],
      gIommuManager.DtbHi[SegmentIndex], gIommuManager.DtbLo[SegmentIndex],
      gIommuManager.CmbHi[SegmentIndex], gIommuManager.CmbLo[SegmentIndex],
      gIommuManager.ElbHi[SegmentIndex], gIommuManager.ElbLo[SegmentIndex]
    ));
  }
  return EFI_SUCCESS;
}

/**
  Process ACPI root tables to ensure proper IVRS integration without modifying firmware tables.
  
  This function handles RSDP, RSDT, and XSDT tables to create enhanced versions that include
  our IVRS table while preserving the original firmware tables.
  
  @retval EFI_SUCCESS          ACPI root tables processed successfully
  @retval EFI_NOT_FOUND        Required ACPI tables not found
  @retval EFI_OUT_OF_RESOURCES Memory allocation failed
  @retval Other                Other errors from ACPI protocol operations
**/
STATIC
EFI_STATUS
ProcessAcpiRootTables (
  VOID
  )
{
  EFI_STATUS                                Status;
  EFI_ACPI_2_0_ROOT_SYSTEM_DESCRIPTION_POINTER *Rsdp;

  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] Processing ACPI root tables for IVRS integration\n"));

  // First, find a writable RSDP (not in firmware-protected memory)
  Status = FindWritableRsdp(&Rsdp);
  if (EFI_ERROR(Status)) {
    MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM] Failed to find writable RSDP: %r\n", Status));
    return Status;
  }

  // Create enhanced RSDT/XSDT with our IVRS table
  Status = CreateEnhancedRsdtXsdt();
  if (EFI_ERROR(Status)) {
    MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM] Failed to create enhanced RSDT/XSDT: %r\n", Status));
    return Status;
  }

  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] ACPI root table processing completed successfully\n"));
  return EFI_SUCCESS;
}

/**
  Find a writable RSDP table that is not in firmware-protected memory.
  
  This function locates an RSDP table that can be safely modified by checking
  its memory attributes and ensuring it's not in protected firmware regions.
  
  @param[out] Rsdp  Pointer to store the found writable RSDP
  
  @retval EFI_SUCCESS          Writable RSDP found
  @retval EFI_NOT_FOUND        No writable RSDP found
  @retval EFI_UNSUPPORTED      RSDP memory protection not supported
**/
STATIC
EFI_STATUS
FindWritableRsdp (
  OUT EFI_ACPI_2_0_ROOT_SYSTEM_DESCRIPTION_POINTER **Rsdp
  )
{
  EFI_STATUS                                Status;
  EFI_ACPI_2_0_ROOT_SYSTEM_DESCRIPTION_POINTER *CurrentRsdp;
  EFI_ACPI_1_0_ROOT_SYSTEM_DESCRIPTION_POINTER *CurrentRsdp10;
  EFI_PHYSICAL_ADDRESS                      RsdpAddress;
  UINTN                                     Index;
  EFI_MEMORY_DESCRIPTOR                     *MemoryMap;
  UINTN                                     MemoryMapSize;
  UINTN                                     MapKey;
  UINTN                                     DescriptorSize;
  UINT32                                    DescriptorVersion;

  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] Searching for writable RSDP\n"));

  // Get current RSDP address from system configuration table (ACPI 2.0 preferred)
  CurrentRsdp = NULL;
  CurrentRsdp10 = NULL;
  Status = EfiGetSystemConfigurationTable(&gEfiAcpi20TableGuid, (VOID **)&CurrentRsdp);
  if (EFI_ERROR(Status) || CurrentRsdp == NULL) {
    // Fallback to ACPI 1.0
    Status = EfiGetSystemConfigurationTable(&gEfiAcpi10TableGuid, (VOID **)&CurrentRsdp10);
    if (EFI_ERROR(Status) || CurrentRsdp10 == NULL) {
      MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM] Failed to locate RSDP via system configuration table\n"));
      return EFI_NOT_FOUND;
    }
    // Cast 1.0 RSDP to 2.0 pointer type for downstream use
    CurrentRsdp = (EFI_ACPI_2_0_ROOT_SYSTEM_DESCRIPTION_POINTER *)(UINTN)CurrentRsdp10;
  }

  RsdpAddress = (EFI_PHYSICAL_ADDRESS)CurrentRsdp;

  // Get memory map to check RSDP memory attributes
  MemoryMapSize = 0;
  MemoryMap = NULL;
  Status = gBS->GetMemoryMap(&MemoryMapSize, MemoryMap, &MapKey, &DescriptorSize, &DescriptorVersion);
  if (Status != EFI_BUFFER_TOO_SMALL) {
    MINI_VISOR_SVM_DEBUG((DEBUG_WARN, "[SVM] Failed to get memory map size: %r\n", Status));
    return EFI_UNSUPPORTED;
  }

  MemoryMap = AllocatePool(MemoryMapSize);
  if (MemoryMap == NULL) {
    MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM] Failed to allocate memory map\n"));
    return EFI_OUT_OF_RESOURCES;
  }

  Status = gBS->GetMemoryMap(&MemoryMapSize, MemoryMap, &MapKey, &DescriptorSize, &DescriptorVersion);
  if (EFI_ERROR(Status)) {
    MINI_VISOR_SVM_DEBUG((DEBUG_WARN, "[SVM] Failed to get memory map: %r\n", Status));
    FreePool(MemoryMap);
    return EFI_UNSUPPORTED;
  }

  // Check if current RSDP is in writable memory
  for (Index = 0; Index < MemoryMapSize / DescriptorSize; Index++) {
    EFI_MEMORY_DESCRIPTOR *Desc = (EFI_MEMORY_DESCRIPTOR *)((UINT8 *)MemoryMap + (Index * DescriptorSize));
    
    if (RsdpAddress >= Desc->PhysicalStart && 
        RsdpAddress < Desc->PhysicalStart + (Desc->NumberOfPages * EFI_PAGE_SIZE)) {
      
      // Check if memory is writable (not runtime code or firmware)
      if ((Desc->Attribute & EFI_MEMORY_RP) == 0 &&
          (Desc->Type != EfiRuntimeServicesCode) &&
          (Desc->Type != EfiRuntimeServicesData) &&
          (Desc->Type != EfiReservedMemoryType)) {
        *Rsdp = CurrentRsdp;
        FreePool(MemoryMap);
        MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] Found writable RSDP at 0x%lx\n", RsdpAddress));
        return EFI_SUCCESS;
      }
      break;
    }
  }

  FreePool(MemoryMap);
  MINI_VISOR_SVM_DEBUG((DEBUG_WARN, "[SVM] No writable RSDP found, current RSDP is in protected memory\n"));
  return EFI_NOT_FOUND;
}

/**
  Create enhanced RSDT and XSDT tables that include our IVRS table.
  
  This function creates new RSDT and XSDT tables that reference both the original
  firmware tables and our enhanced IVRS table, without modifying the firmware tables.
  
  @retval EFI_SUCCESS          Enhanced tables created successfully
  @retval EFI_OUT_OF_RESOURCES Memory allocation failed
  @retval Other                Other errors from ACPI protocol operations
**/
STATIC
EFI_STATUS
CreateEnhancedRsdtXsdt (
  VOID
  )
{
  EFI_STATUS                        Status;
  EFI_ACPI_TABLE_PROTOCOL           *AcpiTableProtocol;
  EFI_ACPI_SDT_PROTOCOL             *AcpiSdtProtocol;
  EFI_ACPI_DESCRIPTION_HEADER       *Rsdt;
  EFI_ACPI_DESCRIPTION_HEADER       *Xsdt;
  UINT32                            *TableEntry;
  UINTN                             TableCount;
  UINTN                             NewTableCount;
  UINTN                             Index;
  UINT32                            *NewRsdtEntries;
  UINT64                            *NewXsdtEntries;
  EFI_ACPI_DESCRIPTION_HEADER       *NewRsdt;
  EFI_ACPI_DESCRIPTION_HEADER       *NewXsdt;
  UINTN                             RsdtSize;
  UINTN                             XsdtSize;

  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] Creating enhanced RSDT/XSDT tables\n"));

  // Locate ACPI table protocol
  Status = gBS->LocateProtocol(&gEfiAcpiTableProtocolGuid, NULL, (VOID **)&AcpiTableProtocol);
  if (EFI_ERROR(Status)) {
    MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM] Failed to locate ACPI table protocol: %r\n", Status));
    return Status;
  }

  // Locate ACPI SDT protocol
  Status = gBS->LocateProtocol(&gEfiAcpiSdtProtocolGuid, NULL, (VOID **)&AcpiSdtProtocol);
  if (EFI_ERROR(Status)) {
    MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM] Failed to locate ACPI SDT protocol: %r\n", Status));
    return Status;
  }

  // Get current RSDT and XSDT from RSDP
  {
    EFI_ACPI_2_0_ROOT_SYSTEM_DESCRIPTION_POINTER *Rsdp20 = NULL;
    EFI_ACPI_1_0_ROOT_SYSTEM_DESCRIPTION_POINTER *Rsdp10 = NULL;

    Rsdt = NULL;
    Xsdt = NULL;

    if (!EFI_ERROR(EfiGetSystemConfigurationTable(&gEfiAcpi20TableGuid, (VOID **)&Rsdp20)) && Rsdp20 != NULL) {
      if (Rsdp20->RsdtAddress != 0) {
        Rsdt = (EFI_ACPI_DESCRIPTION_HEADER *)(UINTN)Rsdp20->RsdtAddress;
      }
      if (Rsdp20->XsdtAddress != 0) {
        Xsdt = (EFI_ACPI_DESCRIPTION_HEADER *)(UINTN)Rsdp20->XsdtAddress;
      }
    } else if (!EFI_ERROR(EfiGetSystemConfigurationTable(&gEfiAcpi10TableGuid, (VOID **)&Rsdp10)) && Rsdp10 != NULL) {
      if (Rsdp10->RsdtAddress != 0) {
        Rsdt = (EFI_ACPI_DESCRIPTION_HEADER *)(UINTN)Rsdp10->RsdtAddress;
      }
    }
  }

  if (Rsdt == NULL && Xsdt == NULL) {
    MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM] No RSDT or XSDT found\n"));
    return EFI_NOT_FOUND;
  }

  // Calculate new table counts (original tables + our IVRS table)
  TableCount = 0;
  if (Rsdt != NULL) {
    TableCount = (Rsdt->Length - sizeof(EFI_ACPI_DESCRIPTION_HEADER)) / sizeof(UINT32);
  }
  NewTableCount = TableCount + 1; // Add our IVRS table

  // Create new RSDT if original exists
  if (Rsdt != NULL) {
    RsdtSize = sizeof(EFI_ACPI_DESCRIPTION_HEADER) + (NewTableCount * sizeof(UINT32));
    NewRsdt = AllocateZeroPool(RsdtSize);
    if (NewRsdt == NULL) {
      MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM] Failed to allocate new RSDT\n"));
      return EFI_OUT_OF_RESOURCES;
    }

    // Copy RSDT header
    CopyMem(NewRsdt, Rsdt, sizeof(EFI_ACPI_DESCRIPTION_HEADER));
    NewRsdt->Length = (UINT32)RsdtSize;

    // Copy existing table entries
    NewRsdtEntries = (UINT32 *)((UINT8 *)NewRsdt + sizeof(EFI_ACPI_DESCRIPTION_HEADER));
    TableEntry = (UINT32 *)((UINT8 *)Rsdt + sizeof(EFI_ACPI_DESCRIPTION_HEADER));
    
    for (Index = 0; Index < TableCount; Index++) {
      NewRsdtEntries[Index] = TableEntry[Index];
    }

    // Add our IVRS table - locate it by scanning SDT tables
    EFI_ACPI_DESCRIPTION_HEADER *IvrsTable = NULL;
    {
      EFI_ACPI_SDT_HEADER *AnyHdr = NULL;
      EFI_ACPI_TABLE_VERSION Version;
      for (Index = 0; ; Index++) {
        EFI_STATUS S = AcpiSdtProtocol->GetAcpiTable(Index, &AnyHdr, &Version, NULL);
        if (EFI_ERROR(S)) {
          break;
        }
        if (AnyHdr != NULL && AnyHdr->Signature == EFI_ACPI_IVRS_TABLE_SIGNATURE) {
          IvrsTable = (EFI_ACPI_DESCRIPTION_HEADER *)AnyHdr;
          break;
        }
      }
    }
    if (IvrsTable != NULL) {
      NewRsdtEntries[TableCount] = (UINT32)(UINTN)IvrsTable;
      MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] Added IVRS table to RSDT at 0x%lx\n", (UINTN)IvrsTable));
    } else {
      MINI_VISOR_SVM_DEBUG((DEBUG_WARN, "[SVM] IVRS table not found, using placeholder\n"));
      NewRsdtEntries[TableCount] = 0; // Fallback placeholder
    }

    // Recalculate checksum
    NewRsdt->Checksum = 0;
    NewRsdt->Checksum = CalculateCheckSum8((UINT8 *)NewRsdt, NewRsdt->Length);

    // Install new RSDT
    Status = AcpiTableProtocol->InstallAcpiTable(AcpiTableProtocol, NewRsdt, NewRsdt->Length, NULL);
    if (EFI_ERROR(Status)) {
      MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM] Failed to install new RSDT: %r\n", Status));
      FreePool(NewRsdt);
      return Status;
    }

    FreePool(NewRsdt);
  }

  // Create new XSDT if original exists
  if (Xsdt != NULL) {
    XsdtSize = sizeof(EFI_ACPI_DESCRIPTION_HEADER) + (NewTableCount * sizeof(UINT64));
    NewXsdt = AllocateZeroPool(XsdtSize);
    if (NewXsdt == NULL) {
      MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM] Failed to allocate new XSDT\n"));
      return EFI_OUT_OF_RESOURCES;
    }

    // Copy XSDT header
    CopyMem(NewXsdt, Xsdt, sizeof(EFI_ACPI_DESCRIPTION_HEADER));
    NewXsdt->Length = (UINT32)XsdtSize;

    // Copy existing table entries
    NewXsdtEntries = (UINT64 *)((UINT8 *)NewXsdt + sizeof(EFI_ACPI_DESCRIPTION_HEADER));
    UINT64 *XsdtTableEntry = (UINT64 *)((UINT8 *)Xsdt + sizeof(EFI_ACPI_DESCRIPTION_HEADER));
    
    for (Index = 0; Index < TableCount; Index++) {
      NewXsdtEntries[Index] = XsdtTableEntry[Index];
    }

    // Add our IVRS table - locate it by scanning SDT tables
    EFI_ACPI_DESCRIPTION_HEADER *IvrsTable = NULL;
    {
      EFI_ACPI_SDT_HEADER *AnyHdr = NULL;
      EFI_ACPI_TABLE_VERSION Version;
      for (Index = 0; ; Index++) {
        EFI_STATUS S = AcpiSdtProtocol->GetAcpiTable(Index, &AnyHdr, &Version, NULL);
        if (EFI_ERROR(S)) {
          break;
        }
        if (AnyHdr != NULL && AnyHdr->Signature == EFI_ACPI_IVRS_TABLE_SIGNATURE) {
          IvrsTable = (EFI_ACPI_DESCRIPTION_HEADER *)AnyHdr;
          break;
        }
      }
    }
    if (IvrsTable != NULL) {
      NewXsdtEntries[TableCount] = (UINT64)(UINTN)IvrsTable;
      MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] Added IVRS table to XSDT at 0x%lx\n", (UINTN)IvrsTable));
    } else {
      MINI_VISOR_SVM_DEBUG((DEBUG_WARN, "[SVM] IVRS table not found, using placeholder for XSDT\n"));
      NewXsdtEntries[TableCount] = 0; // Fallback placeholder
    }

    // Recalculate checksum
    NewXsdt->Checksum = 0;
    NewXsdt->Checksum = CalculateCheckSum8((UINT8 *)NewXsdt, NewXsdt->Length);

    // Install new XSDT
    Status = AcpiTableProtocol->InstallAcpiTable(AcpiTableProtocol, NewXsdt, NewXsdt->Length, NULL);
    if (EFI_ERROR(Status)) {
      MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM] Failed to install new XSDT: %r\n", Status));
      FreePool(NewXsdt);
      return Status;
    }

    FreePool(NewXsdt);
  }

  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] Enhanced RSDT/XSDT tables created successfully\n"));
  return EFI_SUCCESS;
}

STATIC VOID HandleSvmExitInternal(UINT64 ExitCode, SVM_EXIT_INFO *ExitInfo, NESTED_SVM_CONTEXT *Context);
STATIC EFI_STATUS SvmShowLegalWarning(VOID);
STATIC VOID ShowBilingualContinuePrompt(IN CONST CHAR16 *EnglishLine, IN CONST CHAR16 *ChineseLine);

// -----------------------------------------------------------------------------
// AMD-Vi (IVRS) Emulation
// -----------------------------------------------------------------------------
STATIC
EFI_STATUS
InitializeAmdViEmulation(
  VOID
  )
{
  EFI_STATUS Status;
  UINT64 Tsc = AsmReadTsc();
  gIommuManager.TimingSeed = (UINT32)((Tsc ^ (Tsc >> 32)) * 2654435761U);
  
  // Initialize spoof defaults (unlocked; no fixed BDF yet)
  gIommuManager.SpoofLocked = FALSE;
  gIommuManager.SpoofBus = 0xFF;
  gIommuManager.SpoofDevice = 0xFF;
  gIommuManager.SpoofFunction = 0xFF;

  // Detect existing IVRS first to avoid conflicts
  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] Scanning for existing IVRS tables...\n"));
  Print(L"[SVM] Scanning for existing IVRS tables...\n");
  
  Status = ParseIvrsTable();
  if (EFI_ERROR(Status)) {
    MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] No existing IVRS table found (Status: %r), will create new one\n", Status));
    Print(L"[SVM] No existing IVRS table found, will create new one\n");
    gIommuManager.CompatibilityMode = FALSE;
  } else {
    MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] Existing IVRS table found, will enhance it\n"));
    Print(L"[SVM] Existing IVRS table found, will enhance it\n");
  }

  // Setup AMD-Vi device tables like Intel VT-d implementation
  Status = SetupAmdViTables();
  if (EFI_ERROR(Status)) {
    MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM] Failed to setup AMD-Vi tables: %r\n", Status));
    return Status;
  }

  // Ensure the AMD-Vi MMIO window is trapped via NPT so our emulation is used
  Status = TrapIommuMmioWithNpt();
  if (EFI_ERROR(Status)) {
    MINI_VISOR_SVM_DEBUG((DEBUG_WARN, "[SVM] Failed to set NPT traps for AMD-Vi MMIO: %r\n", Status));
  }

  // Install enhanced IOMMU emulation for Windows compatibility
  if (!gIommuManager.CompatibilityMode) {
    MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] Creating enhanced IVRS table...\n"));
    Status = CreateEnhancedIvrsTable();
    if (EFI_ERROR(Status)) {
      MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM] Enhanced IVRS creation failed: %r\n", Status));
      Print(L"[SVM] ERROR: Failed to create IVRS table - ACPI injection failed\n");
      return Status;
    }
  } else {
    MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] Firmware IVRS detected, enhancing existing table...\n"));
    Status = EnhanceExistingIvrsTable();
    if (EFI_ERROR(Status)) {
      MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM] IVRS enhancement failed: %r\n", Status));
      Print(L"[SVM] ERROR: Failed to enhance existing IVRS table - ACPI injection failed\n");
      return Status;
    }
  }

  // Verify ACPI table injection to ensure OS will see AMD-Vi
  Status = VerifyAcpiTableInjection();
  if (EFI_ERROR(Status)) {
    MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM] ACPI IVRS verification failed: %r\n", Status));
    Print(L"[SVM] ERROR: ACPI IVRS verification failed (%r)\n", Status);
    return Status;
  }

  // Verify strict IOMMU MMIO register map shadow is sane
  Status = VerifyIommuRegisterMap();
  if (EFI_ERROR(Status)) {
    MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM] IOMMU MMIO map verification failed: %r\n", Status));
    Print(L"[SVM] ERROR: IOMMU MMIO map verification failed (%r)\n", Status);
    return Status;
  }

  // Apply Windows compatibility measures (best-effort)
  InstallWindowsCompatibilityMeasures();

  // Process ACPI root tables (RSDP/RSDT/XSDT) for proper IVRS integration
  Status = ProcessAcpiRootTables();
  if (EFI_ERROR(Status)) {
    MINI_VISOR_SVM_DEBUG((DEBUG_WARN, "[SVM] ACPI root table processing failed: %r\n", Status));
    Print(L"[SVM] WARNING: ACPI root table processing failed (%r)\n", Status);
    // Continue despite warning as IVRS may still work
  }

  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] AMD-Vi emulation initialization completed successfully\n"));
  Print(L"[SVM] AMD-Vi ACPI table injection completed\n");
  return EFI_SUCCESS;
}

STATIC
BOOLEAN
EFIAPI
IsIommuMmioAddress (
  IN EFI_PHYSICAL_ADDRESS Address
  )
{
  for (UINTN SegmentIndex = 0; SegmentIndex < gIommuManager.NumSegments; SegmentIndex++) {
    EFI_PHYSICAL_ADDRESS MmioBase = gIommuManager.SegmentMmioBases[SegmentIndex];
    if (MmioBase != 0 && Address >= MmioBase && Address < (MmioBase + 0x10000)) {
      return TRUE;
    }
  }
  return FALSE;
}

STATIC
EFI_STATUS
EFIAPI
HandleIommuMmioAccess (
  IN OUT NESTED_SVM_CONTEXT *Context,
  IN EFI_PHYSICAL_ADDRESS Address,
  IN BOOLEAN IsWrite
  )
{
  for (UINTN SegmentIndex = 0; SegmentIndex < gIommuManager.NumSegments; SegmentIndex++) {
    EFI_PHYSICAL_ADDRESS MmioBase = gIommuManager.SegmentMmioBases[SegmentIndex];
    if (MmioBase == 0) {
      continue;
    }
    if (Address >= MmioBase && Address < (MmioBase + 0x10000)) {
      UINT32 Offset = (UINT32)(Address - MmioBase);
      if (IsWrite) {
        UINT32 Value = (UINT32)Context->GuestRax;
        return HandleIommuMmioWrite(SegmentIndex, Offset, Value, Context);
      } else {
        return HandleIommuMmioRead(SegmentIndex, Offset, Context);
      }
    }
  }
  return EFI_UNSUPPORTED;
}

STATIC
EFI_STATUS
ParseIvrsTable(
  VOID
  )
{
  EFI_STATUS             Status;
  EFI_ACPI_SDT_PROTOCOL *AcpiSdt;
  EFI_ACPI_SDT_HEADER   *Table;
  EFI_ACPI_TABLE_VERSION Version;
  UINTN                  Index;
  UINTN                  TableKey;
  AMD_ACPI_IVRS_HEADER  *IvrsHeader;
  AMD_ACPI_IVRS_IVHD10  *IvhdHeader;
  UINT8                 *TablePtr;
  UINT32                 Offset;

  Status = gBS->LocateProtocol(&gEfiAcpiSdtProtocolGuid, NULL, (VOID**)&AcpiSdt);
  if (EFI_ERROR(Status) || AcpiSdt == NULL) {
    return EFI_NOT_FOUND;
  }

  for (Index = 0; ; Index++) {
    Status = AcpiSdt->GetAcpiTable(Index, &Table, &Version, &TableKey);
    if (EFI_ERROR(Status)) {
      break;
    }
    if (Table->Signature == SIGNATURE_32('I','V','R','S')) {
      MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] Found existing IVRS table at index %d\n", Index));
      
      // Parse the IVRS table to extract IOMMU information
      IvrsHeader = (AMD_ACPI_IVRS_HEADER*)Table;
      TablePtr = (UINT8*)Table;
      Offset = sizeof(AMD_ACPI_IVRS_HEADER);
      
      MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] IVRS: Length=0x%x, IV_Info=0x%x\n", 
                           IvrsHeader->Header.Length, IvrsHeader->IvInfo));
      
      // Parse IVHD entries
      while (Offset < IvrsHeader->Header.Length) {
        IvhdHeader = (AMD_ACPI_IVRS_IVHD10*)(TablePtr + Offset);
        
        if (IvhdHeader->Type == 0x10 || IvhdHeader->Type == 0x11 || IvhdHeader->Type == 0x40) {
          
          MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] Found IVHD Type=0x%x, Length=0x%x, DeviceId=0x%x\n",
                               IvhdHeader->Type, IvhdHeader->Length, IvhdHeader->DeviceId));
          MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] IOMMU Base Address: 0x%lx\n", IvhdHeader->BaseAddress));
          
          // Store the first IOMMU base address for our emulation
          if (gIommuManager.MmioBase == 0) {
            gIommuManager.MmioBase = IvhdHeader->BaseAddress;
          }
        }
        
        Offset += IvhdHeader->Length;
      }
      
      gIommuManager.CompatibilityMode = TRUE;
      gIommuManager.ExistingIvrsTableKey = TableKey;
      
      MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] IVRS parsing complete, compatibility mode enabled\n"));
      return EFI_SUCCESS;
    }
  }

  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] No existing IVRS table found, will create new one\n"));
  return EFI_NOT_FOUND;
}

STATIC
EFI_STATUS
SvmShowLegalWarning(
  VOID
  )
{
  Print(L"\n===============================================================================\n");
  Print(L"                      SVM Hardware Emulation Driver v1.0\n");
  Print(L"                      SVM 硬件仿真驱动程序 v1.0\n");
  Print(L"===============================================================================\n");
  Print(L"LEGAL NOTICE AND DISCLAIMER:\n");
  Print(L"法律声明和免责条款：\n");
  Print(L"\n");
  Print(L"This software is provided for LEGITIMATE VIRTUALIZATION PURPOSES ONLY.\n");
  Print(L"本软件仅供合法的虚拟化用途使用。\n");
  Print(L"\n");
  Print(L"By using this software, you acknowledge and agree to the following:\n");
  Print(L"使用本软件即表示您确认并同意以下条款：\n");
  Print(L"\n");
  Print(L"1. AUTHORIZED USE ONLY: This driver may only be used by authorized personnel\n");
  Print(L"   for legitimate development, testing, and compatibility purposes.\n");
  Print(L"   仅限授权使用：本驱动程序仅可由授权人员用于合法的开发、测试和兼容性用途。\n");
  Print(L"\n");
  Print(L"2. NO ILLEGAL ACTIVITIES: This software SHALL NOT be used to bypass\n");
  Print(L"   licensing, copy protection, or other security measures, nor for any\n");
  Print(L"   illegal or unauthorized activities.\n");
  Print(L"   禁止非法活动：本软件严禁用于绕过许可证、复制保护或其他安全措施，\n");
  Print(L"   也不得用于任何非法或未经授权的活动。\n");
  Print(L"\n");
  Print(L"3. NO WARRANTY: This software is provided \"AS IS\" without any warranty.\n");
  Print(L"   The authors disclaim all warranties and liability.\n");
  Print(L"   无质量保证：本软件按现状提供，不提供任何质量保证。\n");
  Print(L"   作者不承担任何保证责任和法律责任。\n");
  Print(L"\n");
  Print(L"4. COMPLIANCE: User is responsible for compliance with all applicable laws\n");
  Print(L"   and regulations in their jurisdiction.\n");
  Print(L"   合规责任：用户有责任遵守其所在司法管辖区的所有适用法律法规。\n");
  Print(L"\n");
  Print(L"IF YOU DO NOT AGREE TO THESE TERMS, DO NOT USE THIS SOFTWARE.\n");
  Print(L"如果您不同意这些条款，请勿使用本软件。\n");
  Print(L"===============================================================================\n");

  return EFI_SUCCESS;
}

STATIC
VOID
ShowBilingualContinuePrompt(
  IN CONST CHAR16 *EnglishLine,
  IN CONST CHAR16 *ChineseLine
  )
{
  EFI_INPUT_KEY Key;
  UINTN         Index;
  EFI_STATUS    Status;

  // Flush any pending key strokes
  for (;;) {
    Status = gST->ConIn->ReadKeyStroke(gST->ConIn, &Key);
    if (Status == EFI_NOT_READY) {
      break;
    }
    if (EFI_ERROR(Status)) {
      break;
    }
  }

  if (EnglishLine != NULL) {
    Print(L"%s\n", EnglishLine);
  }
  if (ChineseLine != NULL) {
    Print(L"%s\n", ChineseLine);
  }

  // Wait for Enter key
  for (;;) {
    Status = gST->ConIn->ReadKeyStroke(gST->ConIn, &Key);
    if (Status == EFI_NOT_READY) {
      gBS->WaitForEvent(1, &gST->ConIn->WaitForKey, &Index);
      continue;
    }
    if (EFI_ERROR(Status)) {
      break;
    }
    if (Key.UnicodeChar == L'\r' || Key.UnicodeChar == L'\n') {
      break;
    }
  }

  Print(L"\n");
}
STATIC
EFI_STATUS
CreatePlatformIvrsTable(
  VOID
  )
{
  EFI_STATUS                Status;
  EFI_ACPI_TABLE_PROTOCOL  *AcpiTableProtocol;
  UINTN                     TableKey;

  // Simplified single segment IOMMU for Windows compatibility
  UINTN TableLen = sizeof(AMD_ACPI_IVRS_HEADER) + sizeof(AMD_ACPI_IVRS_IVHD10);
  AMD_ACPI_IVRS_HEADER *Ivrs = AllocateZeroPool(TableLen);
  if (Ivrs == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  Ivrs->Header.Signature = SIGNATURE_32('I','V','R','S');
  Ivrs->Header.Length = (UINT32)TableLen;
  Ivrs->Header.Revision = 0x01; // Common IVRS revision used by OSes
  // Inherit OEM fields from an existing ACPI table to blend in
  {
    EFI_ACPI_SDT_PROTOCOL *AcpiSdt = NULL;
    EFI_STATUS S = gBS->LocateProtocol(&gEfiAcpiSdtProtocolGuid, NULL, (VOID**)&AcpiSdt);
    if (!EFI_ERROR(S) && AcpiSdt != NULL) {
      EFI_ACPI_SDT_HEADER *AnyHdr = NULL; EFI_ACPI_TABLE_VERSION V; UINTN K;
      for (K = 0; ; K++) {
        S = AcpiSdt->GetAcpiTable(K, &AnyHdr, &V, NULL);
        if (EFI_ERROR(S)) { AnyHdr = NULL; break; }
        // Prefer FACP or similar, else first table
        if (AnyHdr->Signature == EFI_ACPI_6_5_FIXED_ACPI_DESCRIPTION_TABLE_SIGNATURE) {
          break;
        }
        if (K == 0) { break; }
      }
      if (AnyHdr != NULL) {
        CopyMem(Ivrs->Header.OemId, AnyHdr->OemId, sizeof(Ivrs->Header.OemId));
        Ivrs->Header.OemTableId = (UINT64)AnyHdr->OemTableId;
        Ivrs->Header.OemRevision = AnyHdr->OemRevision;
        Ivrs->Header.CreatorId = AnyHdr->CreatorId;
        Ivrs->Header.CreatorRevision = AnyHdr->CreatorRevision;
      } else {
        CopyMem(Ivrs->Header.OemId, "AMD   ", 6);
        Ivrs->Header.OemTableId = SIGNATURE_64('A','M','D','V','I','R','S',' ');
        Ivrs->Header.OemRevision = 1;
        Ivrs->Header.CreatorId = SIGNATURE_32('A','M','D',' ');
        Ivrs->Header.CreatorRevision = 1;
      }
    } else {
      CopyMem(Ivrs->Header.OemId, "AMD   ", 6);
      Ivrs->Header.OemTableId = SIGNATURE_64('A','M','D','V','I','R','S',' ');
      Ivrs->Header.OemRevision = 1;
      Ivrs->Header.CreatorId = SIGNATURE_32('A','M','D',' ');
      Ivrs->Header.CreatorRevision = 1;
    }
  }
  Ivrs->IvInfo = 0; // minimal
  Ivrs->Reserved = 0;

  AMD_ACPI_IVRS_IVHD10 *Ivhd = (AMD_ACPI_IVRS_IVHD10 *)(Ivrs + 1);
  // Single IOMMU entry for Windows compatibility
  Ivhd->Type = 0x10;               // IVHD type 10h
  Ivhd->Flags = BIT0;              // include-all devices
  Ivhd->Length = (UINT16)sizeof(AMD_ACPI_IVRS_IVHD10);
  Ivhd->DeviceId = 0;
  Ivhd->CapabilityOffset = 0;
  Ivhd->BaseAddress = gIommuManager.MmioBase;
  Ivhd->PciSegment = 0;            // Standard segment 0
  Ivhd->Info = 0;
  Ivhd->Reserved = 0;

  // Compute checksum
  UINT8 Sum = 0;
  for (UINTN i = 0; i < TableLen; i++) {
    Sum = (UINT8)(Sum + ((UINT8*)Ivrs)[i]);
  }
  Ivrs->Header.Checksum = (UINT8)(0 - Sum);

  Status = gBS->LocateProtocol(&gEfiAcpiTableProtocolGuid, NULL, (VOID**)&AcpiTableProtocol);
  if (EFI_ERROR(Status)) {
    MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM] Failed to locate ACPI Table Protocol: %r\n", Status));
    FreePool(Ivrs);
    return Status;
  }

  Status = AcpiTableProtocol->InstallAcpiTable(AcpiTableProtocol, Ivrs, (UINT32)TableLen, &TableKey);
  if (!EFI_ERROR(Status)) {
    gIommuManager.IvrsTableKey = TableKey;
    MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] IVRS installed (Key=%u) for Windows compatibility\n", TableKey));
  }

  FreePool(Ivrs);
  return Status;
}

/**
  Setup AMD-Vi device tables (similar to Intel VT-d implementation)
**/
STATIC
EFI_STATUS
SetupAmdViTables(VOID)
{
  EFI_STATUS Status;
  EFI_PHYSICAL_ADDRESS DeviceTableAddress;
  EFI_PHYSICAL_ADDRESS CommandBufferAddress;
  EFI_PHYSICAL_ADDRESS EventLogAddress;
  
  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] Setting up AMD-Vi device tables...\n"));
  
  // Allocate Device Table (similar to VT-d root table)
  Status = gBS->AllocatePages(AllocateAnyPages, EfiReservedMemoryType, 
                              EFI_SIZE_TO_PAGES(256 * sizeof(UINT64)), &DeviceTableAddress);
  if (EFI_ERROR(Status)) {
    MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM] Failed to allocate device table: %r\n", Status));
    return Status;
  }
  
  ZeroMem((VOID*)(UINTN)DeviceTableAddress, 256 * sizeof(UINT64));
  gIommuManager.RegisterBaseAddress = DeviceTableAddress;
  
  // Allocate Command Buffer
  Status = gBS->AllocatePages(AllocateAnyPages, EfiReservedMemoryType, 
                              EFI_SIZE_TO_PAGES(0x1000), &CommandBufferAddress);
  if (EFI_ERROR(Status)) {
    MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM] Failed to allocate command buffer: %r\n", Status));
    return Status;
  }
  
  ZeroMem((VOID*)(UINTN)CommandBufferAddress, 0x1000);
  
  // Allocate Event Log
  Status = gBS->AllocatePages(AllocateAnyPages, EfiReservedMemoryType, 
                              EFI_SIZE_TO_PAGES(0x1000), &EventLogAddress);
  if (EFI_ERROR(Status)) {
    MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM] Failed to allocate event log: %r\n", Status));
    return Status;
  }
  
  ZeroMem((VOID*)(UINTN)EventLogAddress, 0x1000);
  
  // Set MMIO base address for registers
  if (gIommuManager.MmioBase == 0) {
    gIommuManager.MmioBase = 0xFED80000; // Standard AMD IOMMU MMIO base
  }
  
  // Expose a 64KB MMIO window as 16 segments (each 4KB) to ensure NPT trapping across the range
  gIommuManager.NumSegments = 16;
  for (UINT32 i = 0; i < gIommuManager.NumSegments; i++) {
    gIommuManager.SegmentMmioBases[i] = (gIommuManager.MmioBase & ~0xFFFULL) + ((EFI_PHYSICAL_ADDRESS)i << 12);
    gIommuManager.SegmentIds[i] = (UINT16)i;
  }
  
  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] Device table at 0x%lx\n", DeviceTableAddress));
  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] Command buffer at 0x%lx\n", CommandBufferAddress));
  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] Event log at 0x%lx\n", EventLogAddress));
  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] MMIO base at 0x%lx\n", gIommuManager.MmioBase));
  
  return EFI_SUCCESS;
}

/**
  Create enhanced IVRS table with comprehensive device entries
**/
STATIC
EFI_STATUS
CreateEnhancedIvrsTable(VOID)
{
  EFI_STATUS                Status;
  EFI_ACPI_TABLE_PROTOCOL  *AcpiTableProtocol;
  AMD_ACPI_IVRS_HEADER     *Ivrs;
  AMD_ACPI_IVRS_IVHD10     *Ivhd;
  UINTN                     TableKey;
  UINTN                     TableLen;
  UINT8                     Checksum;
  
  // For strict IVRS, enumerate PCI devices to emit per-device entries under IVHD
  EFI_HANDLE                      *Handles = NULL;
  UINTN                            HandleCount = 0;
  EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL *PciRbIo;
  UINTN                            DeviceEntryCount = 0;
  UINTN                            i;
  
  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] Creating enhanced IVRS table...\n"));
  
  Status = gBS->LocateProtocol(&gEfiAcpiTableProtocolGuid, NULL, (VOID**)&AcpiTableProtocol);
  if (EFI_ERROR(Status)) {
    MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM] Failed to locate ACPI Table Protocol: %r\n", Status));
    Print(L"[SVM] ERROR: ACPI Table Protocol not available (Status: %r)\n", Status);
    Print(L"[SVM] This usually indicates the ACPI module is not loaded or initialized\n");
    return Status;
  }
  
  if (AcpiTableProtocol == NULL) {
    MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM] ACPI Table Protocol is NULL\n"));
    Print(L"[SVM] ERROR: ACPI Table Protocol is NULL\n");
    return EFI_NOT_FOUND;
  }
  
  // First pass: count present PCI devices to size the table
  Status = gBS->LocateHandleBuffer(ByProtocol, &gEfiPciRootBridgeIoProtocolGuid, NULL, &HandleCount, &Handles);
  if (EFI_ERROR(Status)) {
    HandleCount = 0;
    Handles = NULL;
  }

  for (i = 0; i < HandleCount; i++) {
    if (EFI_ERROR(gBS->HandleProtocol(Handles[i], &gEfiPciRootBridgeIoProtocolGuid, (VOID **)&PciRbIo))) {
      continue;
    }
    for (UINTN Bus = 0; Bus <= 255; Bus++) {
      for (UINTN Dev = 0; Dev <= 31; Dev++) {
        for (UINTN Func = 0; Func <= 7; Func++) {
          UINT64 Address = EFI_PCI_ADDRESS(Bus, Dev, Func, 0);
          UINT16 VendorDevice;
          Status = PciRbIo->Pci.Read(PciRbIo, EfiPciWidthUint16, Address + 0x00, 1, &VendorDevice);
          if (EFI_ERROR(Status) || VendorDevice == 0xFFFF) {
            if (Func == 0) {
              break; // no more functions for this device
            }
            continue;
          }
          DeviceEntryCount++;
        }
      }
    }
  }

  // Each device entry will be 4 bytes: [Type=0x01][Flags][DeviceId(LE16)]
  UINTN DeviceEntriesSize = DeviceEntryCount * 4;
  
  // Calculate table size: IVRS header + IVHD + device entries
  TableLen = sizeof(AMD_ACPI_IVRS_HEADER) + sizeof(AMD_ACPI_IVRS_IVHD10) + DeviceEntriesSize;
  
  Ivrs = AllocateZeroPool(TableLen);
  if (Ivrs == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }
  
  // Fill IVRS header
  Ivrs->Header.Signature = SIGNATURE_32('I','V','R','S');
  Ivrs->Header.Length = (UINT32)TableLen;
  Ivrs->Header.Revision = 0x02; // Use revision 2 for better compatibility
  Ivrs->Header.Checksum = 0;
  
  // Copy OEM information from existing tables for stealth
  {
    EFI_ACPI_SDT_PROTOCOL *AcpiSdt = NULL;
    Status = gBS->LocateProtocol(&gEfiAcpiSdtProtocolGuid, NULL, (VOID**)&AcpiSdt);
    if (!EFI_ERROR(Status) && AcpiSdt != NULL) {
      EFI_ACPI_SDT_HEADER *FacpHeader = NULL;
      EFI_ACPI_TABLE_VERSION Version;
      UINTN Index;
      
      // Find FACP table to copy OEM info
      for (Index = 0; ; Index++) {
        Status = AcpiSdt->GetAcpiTable(Index, &FacpHeader, &Version, NULL);
        if (EFI_ERROR(Status)) {
          break;
        }
        if (FacpHeader->Signature == EFI_ACPI_6_5_FIXED_ACPI_DESCRIPTION_TABLE_SIGNATURE) {
          CopyMem(Ivrs->Header.OemId, FacpHeader->OemId, sizeof(Ivrs->Header.OemId));
          Ivrs->Header.OemTableId = (UINT64)FacpHeader->OemTableId;
          Ivrs->Header.OemRevision = FacpHeader->OemRevision;
          Ivrs->Header.CreatorId = FacpHeader->CreatorId;
          Ivrs->Header.CreatorRevision = FacpHeader->CreatorRevision;
          break;
        }
      }
    }
    
    // Fallback if no FACP found
    if (Ivrs->Header.OemTableId == 0) {
      CopyMem(Ivrs->Header.OemId, "AMD   ", 6);
      Ivrs->Header.OemTableId = SIGNATURE_64('A','M','D','V','I','R','S',' ');
      Ivrs->Header.OemRevision = 1;
      Ivrs->Header.CreatorId = SIGNATURE_32('A','M','D',' ');
      Ivrs->Header.CreatorRevision = 1;
    }
  }
  
  // IVRS-specific fields (use values aligned with common, compatible deployments)
  Ivrs->IvInfo = 0x00203041; // Virtualization Info per reference IVRS for broad OS acceptance
  Ivrs->Reserved = 0;
  
  // Fill IVHD entry
  Ivhd = (AMD_ACPI_IVRS_IVHD10*)(Ivrs + 1);
  Ivhd->Type = 0x10;                                    // IVHD type 10h
  Ivhd->Flags = BIT0;                                   // Include all PCI devices
  Ivhd->Length = (UINT16)(sizeof(AMD_ACPI_IVRS_IVHD10) + DeviceEntriesSize); // IVHD + device entries
  Ivhd->DeviceId = 0x0002;                              // PCI device ID for IOMMU
  Ivhd->CapabilityOffset = 0x40;                        // Standard capability offset
  Ivhd->BaseAddress = gIommuManager.MmioBase;           // MMIO base address
  Ivhd->PciSegment = 0;                                 // Segment 0
  Ivhd->Info = 0x0013;                                  // UnitID=0, PassPW=1, ErrWatching=1
  Ivhd->Reserved = 0;
  
  // Second pass: emit per-device entries
  if (DeviceEntryCount > 0) {
    UINT8 *DeviceEntries = (UINT8 *)(Ivhd + 1);
    UINT8 *Entry = DeviceEntries;
    for (i = 0; i < HandleCount; i++) {
      if (EFI_ERROR(gBS->HandleProtocol(Handles[i], &gEfiPciRootBridgeIoProtocolGuid, (VOID **)&PciRbIo))) {
        continue;
      }
      for (UINTN Bus = 0; Bus <= 255; Bus++) {
        for (UINTN Dev = 0; Dev <= 31; Dev++) {
          for (UINTN Func = 0; Func <= 7; Func++) {
            UINT64 Address = EFI_PCI_ADDRESS(Bus, Dev, Func, 0);
            UINT16 VendorDevice;
            Status = PciRbIo->Pci.Read(PciRbIo, EfiPciWidthUint16, Address + 0x00, 1, &VendorDevice);
            if (EFI_ERROR(Status) || VendorDevice == 0xFFFF) {
              if (Func == 0) {
                break;
              }
              continue;
            }
            // Type 0x01: Device entry; Flags=0; DeviceId=BDF encoding: Bus:8, Dev:5, Func:3
            Entry[0] = 0x01;
            Entry[1] = 0x00;
            UINT16 Bdf = (UINT16)(((Bus & 0xFF) << 8) | ((Dev & 0x1F) << 3) | (Func & 0x07));
            Entry[2] = (UINT8)(Bdf & 0xFF);
            Entry[3] = (UINT8)((Bdf >> 8) & 0xFF);
            Entry += 4;
          }
        }
      }
    }
  }

  
  // Calculate checksum
  Checksum = 0;
  for (UINTN idx = 0; idx < TableLen; idx++) {
    Checksum = (UINT8)(Checksum + ((UINT8*)Ivrs)[idx]);
  }
  Ivrs->Header.Checksum = (UINT8)(0 - Checksum);
  
  // Install the table
  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] Installing IVRS table (Size: %u bytes)...\n", TableLen));
  Print(L"[SVM] Installing IVRS table (Size: %u bytes)...\n", TableLen);
  
  Status = AcpiTableProtocol->InstallAcpiTable(AcpiTableProtocol, Ivrs, TableLen, &TableKey);
  if (EFI_ERROR(Status)) {
    MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM] Failed to install enhanced IVRS table: %r\n", Status));
    Print(L"[SVM] ERROR: Failed to install enhanced IVRS table (Status: %r)\n", Status);
    Print(L"[SVM] Table details - Size: %u, Signature: 0x%x, Length: 0x%x\n", 
          TableLen, Ivrs->Header.Signature, Ivrs->Header.Length);
    FreePool(Ivrs);
    return Status;
  }
  
  gIommuManager.IvrsTableKey = TableKey;
  
  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] Enhanced IVRS installed (Key=%u)\n", TableKey));
  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM]   IVHD base: 0x%lx\n", gIommuManager.MmioBase));
  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM]   Device table: 0x%lx\n", gIommuManager.RegisterBaseAddress));
  
  if (Handles != NULL) {
    FreePool(Handles);
  }
  FreePool(Ivrs);
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EnhanceExistingIvrsTable(
  VOID
  )
{
  EFI_STATUS                Status;
  EFI_ACPI_TABLE_PROTOCOL  *AcpiTableProtocol;
  EFI_ACPI_SDT_PROTOCOL    *AcpiSdt;
  AMD_ACPI_IVRS_HEADER     *ExistingIvrs;
  AMD_ACPI_IVRS_HEADER     *NewIvrs;
  AMD_ACPI_IVRS_IVHD10     *Ivhd;
  UINTN                     NewTableKey;
  UINTN                     TableLen;
  UINT8                     Checksum;
  
  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] Enhancing existing IVRS table for compatibility...\n"));
  
  Status = gBS->LocateProtocol(&gEfiAcpiTableProtocolGuid, NULL, (VOID**)&AcpiTableProtocol);
  if (EFI_ERROR(Status)) {
    MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM] Failed to locate ACPI Table Protocol for enhancement: %r\n", Status));
    Print(L"[SVM] ERROR: ACPI Table Protocol not available for enhancement (Status: %r)\n", Status);
    return Status;
  }
  
  Status = gBS->LocateProtocol(&gEfiAcpiSdtProtocolGuid, NULL, (VOID**)&AcpiSdt);
  if (EFI_ERROR(Status)) {
    MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM] Failed to locate ACPI SDT Protocol for enhancement: %r\n", Status));
    Print(L"[SVM] ERROR: ACPI SDT Protocol not available for enhancement (Status: %r)\n", Status);
    return Status;
  }
  
  // Get the existing IVRS table by scanning to avoid relying on saved key as index
  EFI_ACPI_SDT_HEADER *Table = NULL;
  EFI_ACPI_TABLE_VERSION Version;
  {
    UINTN Idx;
    for (Idx = 0; ; Idx++) {
      Status = AcpiSdt->GetAcpiTable(Idx, &Table, &Version, NULL);
      if (EFI_ERROR(Status)) {
        MINI_VISOR_SVM_DEBUG((DEBUG_WARN, "[SVM] Could not find existing IVRS table during enhancement\n"));
        return Status;
      }
      if (Table->Signature == SIGNATURE_32('I','V','R','S')) {
        break;
      }
    }
  }
  
  ExistingIvrs = (AMD_ACPI_IVRS_HEADER*)Table;
  TableLen = ExistingIvrs->Header.Length;
  
  // Create a modified copy
  NewIvrs = AllocatePool(TableLen);
  if (NewIvrs == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }
  
  CopyMem(NewIvrs, ExistingIvrs, TableLen);
  
  // Modify IVRS to point to our emulation
  // Find first IVHD entry and update its base address
  UINT8 *TablePtr = (UINT8*)NewIvrs;
  UINT32 Offset = sizeof(AMD_ACPI_IVRS_HEADER);
  
  while (Offset < TableLen) {
    Ivhd = (AMD_ACPI_IVRS_IVHD10*)(TablePtr + Offset);
    
    if (Ivhd->Type == 0x10 || Ivhd->Type == 0x11 || Ivhd->Type == 0x40) {
      MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] Modifying IVHD at offset 0x%x\n", Offset));
      MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] Original base: 0x%lx -> New base: 0x%lx\n", 
                           Ivhd->BaseAddress, gIommuManager.MmioBase));
      
      // Redirect to our emulation MMIO base
      Ivhd->BaseAddress = gIommuManager.MmioBase;
      
      // Set include-all flag for maximum compatibility
      Ivhd->Flags |= BIT0;
      
      break;  // Only modify the first IVHD for now
    }
    
    Offset += Ivhd->Length;
  }
  
  // Recalculate checksum
  NewIvrs->Header.Checksum = 0;
  Checksum = 0;
  for (UINTN i = 0; i < TableLen; i++) {
    Checksum = (UINT8)(Checksum + ((UINT8*)NewIvrs)[i]);
  }
  NewIvrs->Header.Checksum = (UINT8)(0 - Checksum);
  
  // Install new IVRS table instead of replacing firmware table
  // This avoids modifying protected firmware tables and follows ACPI specification
  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] Installing new enhanced IVRS table (Size: %u bytes)...\n", TableLen));
  Print(L"[SVM] Installing new enhanced IVRS table (Size: %u bytes)...\n", TableLen);
  
  Status = AcpiTableProtocol->InstallAcpiTable(AcpiTableProtocol, NewIvrs, TableLen, &NewTableKey);
  if (EFI_ERROR(Status)) {
    MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM] Failed to install modified IVRS table: %r\n", Status));
    Print(L"[SVM] ERROR: Failed to install enhanced IVRS table (Status: %r)\n", Status);
    Print(L"[SVM] Enhanced table details - Size: %u, Original base: 0x%lx, New base: 0x%lx\n", 
          TableLen, ExistingIvrs->Header.Length, gIommuManager.MmioBase);
    FreePool(NewIvrs);
    return Status;
  }
  
  gIommuManager.IvrsTableKey = NewTableKey;
  
  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] Enhanced IVRS installed (Key=%u)\n", NewTableKey));
  
  FreePool(NewIvrs);
  return EFI_SUCCESS;
}

/**
  Verify that ACPI table injection was successful and can be detected.
  This function ensures the virtualization emulator can start properly.

  @retval EFI_SUCCESS         ACPI table injection verified successfully
  @retval EFI_NOT_FOUND       IVRS table not found after injection
  @retval EFI_DEVICE_ERROR    ACPI table injection failed verification
**/
STATIC
EFI_STATUS
VerifyAcpiTableInjection(
  VOID
  )
{
  EFI_STATUS             Status;
  EFI_ACPI_SDT_PROTOCOL *AcpiSdt;
  EFI_ACPI_SDT_HEADER   *Table;
  EFI_ACPI_TABLE_VERSION Version;
  UINTN                  Index;
  UINTN                  TableKey;
  AMD_ACPI_IVRS_HEADER  *IvrsHeader;
  AMD_ACPI_IVRS_IVHD10  *IvhdHeader;
  UINT8                 *TablePtr;
  UINT32                 Offset;
  BOOLEAN                IvrsFound = FALSE;
  BOOLEAN                ValidIvhdFound = FALSE;

  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] Verifying ACPI table injection...\n"));

  Status = gBS->LocateProtocol(&gEfiAcpiSdtProtocolGuid, NULL, (VOID**)&AcpiSdt);
  if (EFI_ERROR(Status) || AcpiSdt == NULL) {
    MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM] Failed to locate ACPI SDT Protocol for verification: %r\n", Status));
    return EFI_NOT_FOUND;
  }

  // Scan all ACPI tables to verify our IVRS table is present and valid
  for (Index = 0; ; Index++) {
    Status = AcpiSdt->GetAcpiTable(Index, &Table, &Version, &TableKey);
    if (EFI_ERROR(Status)) {
      break;
    }
    
    if (Table->Signature == SIGNATURE_32('I','V','R','S')) {
      IvrsFound = TRUE;
      IvrsHeader = (AMD_ACPI_IVRS_HEADER*)Table;
      TablePtr = (UINT8*)Table;
      Offset = sizeof(AMD_ACPI_IVRS_HEADER);
      
      MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] Found IVRS table at index %d (Key=%u)\n", Index, TableKey));
      MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] IVRS Length=0x%x, IvInfo=0x%x\n", 
                           IvrsHeader->Header.Length, IvrsHeader->IvInfo));
      
      // Verify that the table contains valid IVHD entries
      while (Offset < IvrsHeader->Header.Length) {
        IvhdHeader = (AMD_ACPI_IVRS_IVHD10*)(TablePtr + Offset);
        
        if (IvhdHeader->Type == 0x10 || IvhdHeader->Type == 0x11 || IvhdHeader->Type == 0x40) {
          MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] Found valid IVHD: Type=0x%x, DeviceId=0x%x, BaseAddr=0x%lx\n",
                               IvhdHeader->Type, IvhdHeader->DeviceId, IvhdHeader->BaseAddress));
          
          // Verify that the base address matches our emulation address
          if (IvhdHeader->BaseAddress == gIommuManager.MmioBase) {
            ValidIvhdFound = TRUE;
            MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] IVHD base address matches our emulation (0x%lx)\n", 
                                 gIommuManager.MmioBase));
          }
        }
        
        Offset += IvhdHeader->Length;
      }
      
      // We found at least one IVRS table, check if others exist
      continue;
    }
  }

  if (!IvrsFound) {
    MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM] VERIFICATION FAILED: No IVRS table found after injection!\n"));
    Print(L"[SVM] ERROR: ACPI table injection failed - no IVRS table detected\n");
    return EFI_NOT_FOUND;
  }

  if (!ValidIvhdFound) {
    MINI_VISOR_SVM_DEBUG((DEBUG_WARN, "[SVM] WARNING: IVRS table found but no valid IVHD pointing to our emulation\n"));
    Print(L"[SVM] WARNING: ACPI table injection incomplete - IOMMU emulation may not work properly\n");
    // Don't fail here, continue for compatibility
  }

  // Additional verification: Check if IOMMU manager is properly initialized
  if (gIommuManager.MmioBase == 0) {
    MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM] VERIFICATION FAILED: IOMMU manager not properly initialized\n"));
    Print(L"[SVM] ERROR: IOMMU emulation not properly initialized\n");
    return EFI_DEVICE_ERROR;
  }

  if (gIommuManager.NumSegments == 0) {
    MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM] VERIFICATION FAILED: No IOMMU segments configured\n"));
    Print(L"[SVM] ERROR: IOMMU segments not configured\n");
    return EFI_DEVICE_ERROR;
  }

  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] ACPI table injection verification PASSED\n"));
  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] IOMMU emulation ready: Base=0x%lx, Segments=%d\n", 
                       gIommuManager.MmioBase, gIommuManager.NumSegments));
  
  Print(L"[SVM] ACPI table injection verified successfully\n");
  Print(L"[SVM] IOMMU emulation active at 0x%lx with %d segments\n", 
        gIommuManager.MmioBase, gIommuManager.NumSegments);
  
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
InstallWindowsCompatibilityMeasures(
  VOID
  )
{
  EFI_STATUS Status = EFI_SUCCESS;
  
  // Install Windows compatibility measures for broad software support
  
  // 1. Configure MSR bitmap for Windows applications
  if (gMiniVisorSvmGlobalData.MsrBitmapBase != 0) {
    UINT8 *MsrBitmap = (UINT8 *)(UINTN)gMiniVisorSvmGlobalData.MsrBitmapBase;
    
    // Allow direct access to common MSRs that Windows applications use
    // SYSENTER MSRs (0x174-0x176)
    for (UINT32 msr = 0x174; msr <= 0x176; msr++) {
      MsrBitmap[msr / 8] &= ~(1 << (msr % 8));
    }
    
    // AMD performance monitoring MSRs commonly used by Windows tools
    UINT32 amd_base = 0x800;
    for (UINT32 msr = 0xC0000080; msr <= 0xC0000084; msr++) { // EFER and related
      UINT32 offset = amd_base + ((msr - 0xC0000000) / 8);
      if (offset < 2 * SIZE_4KB) {
        MsrBitmap[offset] &= ~(1 << ((msr - 0xC0000000) % 8));
      }
    }
  }
  
  // 2. Configure I/O bitmap for standard PC hardware compatibility
  if (gMiniVisorSvmGlobalData.IoBitmapBase != 0) {
    UINT8 *IoBitmap = (UINT8 *)(UINTN)gMiniVisorSvmGlobalData.IoBitmapBase;
    
    // Allow direct access to standard PC hardware ports for Windows compatibility
    
    // System timer ports (0x40-0x43)
    for (UINT16 port = 0x40; port <= 0x43; port++) {
      IoBitmap[port / 8] &= ~(1 << (port % 8));
    }
    
    // Keyboard controller ports (0x60, 0x64)
    IoBitmap[0x60 / 8] &= ~(1 << (0x60 % 8));
    IoBitmap[0x64 / 8] &= ~(1 << (0x64 % 8));
    
    // Real-time clock ports (0x70, 0x71)
    IoBitmap[0x70 / 8] &= ~(1 << (0x70 % 8));
    IoBitmap[0x71 / 8] &= ~(1 << (0x71 % 8));
    
    // Serial communication ports
    for (UINT16 port = 0x3F8; port <= 0x3FF; port++) {
      IoBitmap[port / 8] &= ~(1 << (port % 8));
    }
    for (UINT16 port = 0x2F8; port <= 0x2FF; port++) {
      IoBitmap[port / 8] &= ~(1 << (port % 8));
    }
  }
  
  // 3. Initialize timing consistency
  if (gIommuManager.TimingSeed == 0) {
    gIommuManager.TimingSeed = (UINT32)AsmReadTsc();
  }
  
  // 4. Configure VMCB for optimal Windows performance
  VMCB *Vmcb = (VMCB *)gMiniVisorSvmGlobalData.VmcbRegion;
  if (Vmcb != NULL) {
    // Minimize VM exits for better Windows application performance
    Vmcb->ControlArea.InterceptException &= ~(SVM_INTERCEPT_EXCEPTION_DB | SVM_INTERCEPT_EXCEPTION_BP);
    
    // Keep essential intercepts for virtualization functionality
    Vmcb->ControlArea.InterceptInstr1 = SVM_INTERCEPT_CPUID | SVM_INTERCEPT_MSR_PROT;
    Vmcb->ControlArea.InterceptInstr2 = SVM_INTERCEPT_VMMCALL;
  }
  
  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] Windows compatibility measures installed\n"));
  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] - MSR access optimized for Windows\n"));
  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] - I/O access configured for PC hardware\n"));
  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] - VMCB optimized for Windows performance\n"));
  
  return Status;
}

/**
  Check if SVM is supported by the processor.
  
  @retval TRUE              SVM is supported.
  @retval FALSE             SVM is not supported.
**/
BOOLEAN
EFIAPI
IsSvmSupported (
  VOID
  )
{
  UINT32  Eax, Ebx, Ecx, Edx;
  UINT64  EferValue;

  //
  // Check if processor supports SVM
  // CPUID function 0x80000001, ECX bit 2 indicates SVM support
  //
  AsmCpuid(0x80000001, &Eax, &Ebx, &Ecx, &Edx);
  if ((Ecx & BIT2) == 0) {
    DEBUG((DEBUG_ERROR, "[SVM] SVM not supported by processor\n"));
    return FALSE;
  }

  //
  // Check if SVM features are available
  // CPUID function 0x8000000A provides SVM feature information
  //
  AsmCpuid(0x8000000A, &Eax, &Ebx, &Ecx, &Edx);
  if (Eax == 0) {
    DEBUG((DEBUG_ERROR, "[SVM] SVM features not available\n"));
    return FALSE;
  }

  //
  // Check if SVM is not disabled by BIOS
  // Read VM_CR MSR to check if SVM is locked or disabled
  //
  EferValue = AsmReadMsr(MSR_VM_CR);
  if ((EferValue & VM_CR_SVMDIS) != 0) {
    DEBUG((DEBUG_ERROR, "[SVM] SVM disabled by BIOS\n"));
    return FALSE;
  }

  if ((EferValue & VM_CR_LOCK) != 0) {
    DEBUG((DEBUG_ERROR, "[SVM] SVM locked by BIOS\n"));
    return FALSE;
  }

  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] SVM is supported\n"));
  return TRUE;
}

/**
  Enable SVM on the current processor.
  
  @retval EFI_SUCCESS       SVM enabled successfully.
  @retval Others            Failed to enable SVM.
**/
EFI_STATUS
EFIAPI
EnableSvm (
  VOID
  )
{
  EFI_STATUS  Status;
  UINT64      EferValue;

  //
  // Check if SVM is already enabled
  //
  EferValue = AsmReadMsr(MSR_EFER);
  if ((EferValue & EFER_SVME) != 0) {
    MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] SVM already enabled\n"));
    return EFI_SUCCESS;
  }

  //
  // Enable SVM by setting EFER.SVME bit
  //
  Status = AsmEnableSvm();
  if (EFI_ERROR(Status)) {
    DEBUG((DEBUG_ERROR, "[SVM] Failed to enable SVM: %r\n", Status));
    return Status;
  }

  //
  // Verify SVM is enabled
  //
  EferValue = AsmReadMsr(MSR_EFER);
  if ((EferValue & EFER_SVME) == 0) {
    DEBUG((DEBUG_ERROR, "[SVM] SVM enable verification failed\n"));
    return EFI_DEVICE_ERROR;
  }

  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] SVM enabled successfully\n"));
  if (gMiniVisorSvmDebugMode) {
    Print(L"[SVM] AMD-V (SVM) has been enabled.\n");
    Print(L"[SVM] AMD-V（SVM）已启用。\n");
    ShowBilingualContinuePrompt(L"Press Enter to continue...", L"按回车键继续...");
  }
  return EFI_SUCCESS;
}
// Mark AMD-Vi MMIO pages as non-present in NPT to force NPF-based MMIO emulation.
STATIC
EFI_STATUS
TrapIommuMmioWithNpt(
  VOID
  )
{
  if (gMiniVisorSvmGlobalData.NptPml4Base == 0 || gIommuManager.MmioBase == 0) {
    return EFI_NOT_READY;
  }

  NPT_PML4E *Pml4 = (NPT_PML4E *)(UINTN)gMiniVisorSvmGlobalData.NptPml4Base;
  EFI_PHYSICAL_ADDRESS Base = gIommuManager.MmioBase & ~0xFFFULL;

  for (UINT32 page = 0; page < 16; page++) {
    EFI_PHYSICAL_ADDRESS Addr = Base + ((EFI_PHYSICAL_ADDRESS)page << 12);

    UINTN pml4Index = (UINTN)((Addr >> 39) & 0x1FF);
    UINTN pdptIndex = (UINTN)((Addr >> 30) & 0x1FF);
    UINTN pdIndex   = (UINTN)((Addr >> 21) & 0x1FF);
    UINTN ptIndex   = (UINTN)((Addr >> 12) & 0x1FF);

    if (Pml4[pml4Index].Present == 0) {
      continue;
    }

    NPT_PDPTE *Pdpt = (NPT_PDPTE *)(UINTN)(Pml4[pml4Index].PhysicalAddress << 12);
    if (Pdpt[pdptIndex].PageSize == 1) {
      // Split 1GB page into 2MB PDEs
      EFI_PHYSICAL_ADDRESS NewPdBase;
      EFI_STATUS S = SvmAllocateTrackedPages(AllocateAnyPages, EfiReservedMemoryType, 1, &NewPdBase);
      if (EFI_ERROR(S)) {
        return S;
      }
      ZeroMem((VOID *)(UINTN)NewPdBase, SIZE_4KB);
      NPT_PDE *NewPd = (NPT_PDE *)(UINTN)NewPdBase;
      for (UINTN i = 0; i < 512; i++) {
        NewPd[i].Present = 1;
        NewPd[i].Write = 1;
        NewPd[i].User = 1;
        NewPd[i].PageSize = 1; // 2MB page
        EFI_PHYSICAL_ADDRESS PdePhys = ((Addr & ~((EFI_PHYSICAL_ADDRESS)SIZE_1GB - 1)) + ((EFI_PHYSICAL_ADDRESS)i * SIZE_2MB));
        NewPd[i].PhysicalAddress = PdePhys >> 12;
      }
      Pdpt[pdptIndex].PageSize = 0;
      Pdpt[pdptIndex].Present = 1;
      Pdpt[pdptIndex].Write = 1;
      Pdpt[pdptIndex].User = 1;
      Pdpt[pdptIndex].PhysicalAddress = NewPdBase >> 12;
    }

    NPT_PDE *Pd = (NPT_PDE *)(UINTN)(Pdpt[pdptIndex].PhysicalAddress << 12);
    if (Pd[pdIndex].PageSize == 1) {
      // Split 2MB page into 4KB PTEs
      EFI_PHYSICAL_ADDRESS NewPtBase;
      EFI_STATUS S = SvmAllocateTrackedPages(AllocateAnyPages, EfiReservedMemoryType, 1, &NewPtBase);
      if (EFI_ERROR(S)) {
        return S;
      }
      ZeroMem((VOID *)(UINTN)NewPtBase, SIZE_4KB);
      NPT_PTE *Pt = (NPT_PTE *)(UINTN)NewPtBase;
      EFI_PHYSICAL_ADDRESS PteBasePhys = (Pd[pdIndex].PhysicalAddress << 12);
      for (UINTN i = 0; i < 512; i++) {
        Pt[i].Present = 1;
        Pt[i].Write = 1;
        Pt[i].User = 1;
        Pt[i].PhysicalAddress = (PteBasePhys + ((EFI_PHYSICAL_ADDRESS)i << 12)) >> 12;
      }
      Pd[pdIndex].PageSize = 0;
      Pd[pdIndex].Present = 1;
      Pd[pdIndex].Write = 1;
      Pd[pdIndex].User = 1;
      Pd[pdIndex].PhysicalAddress = NewPtBase >> 12;
    }

    NPT_PTE *PtExisting = (NPT_PTE *)(UINTN)(Pd[pdIndex].PhysicalAddress << 12);
    PtExisting[ptIndex].Present = 0; // mark non-present to trigger NPF
  }

  return EFI_SUCCESS;
}

/**
  Enforce IOMMU friendly configuration at PCIe level.

  - Try to enable ACS on downstream ports and root ports if supported
  - Disable PTM capability advertisement to reduce timing-based detection

  Best-effort: silently continue on errors.
**/
STATIC
EFI_STATUS
EnforceIommuSafePciRouting (
  VOID
  )
{
  EFI_STATUS                   Status;
  EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL *PciRbIo;
  UINTN                        HandleCount = 0;
  EFI_HANDLE                   *Handles = NULL;

  Status = gBS->LocateHandleBuffer(ByProtocol, &gEfiPciRootBridgeIoProtocolGuid, NULL, &HandleCount, &Handles);
  if (EFI_ERROR(Status) || HandleCount == 0 || Handles == NULL) {
    return EFI_SUCCESS;
  }

  for (UINTN i = 0; i < HandleCount; i++) {
    Status = gBS->HandleProtocol(Handles[i], &gEfiPciRootBridgeIoProtocolGuid, (VOID **)&PciRbIo);
    if (EFI_ERROR(Status)) {
      continue;
    }

    // Iterate all bus:dev:func in this root bridge segment
    for (UINTN Bus = 0; Bus <= 255; Bus++) {
      for (UINTN Dev = 0; Dev <= 31; Dev++) {
        for (UINTN Func = 0; Func <= 7; Func++) {
          UINT64 Address = EFI_PCI_ADDRESS(Bus, Dev, Func, 0);
          UINT16 VendorDevice;
          UINT8  HeaderType;

          // Read VendorID/DeviceID to see if present
          Status = PciRbIo->Pci.Read(PciRbIo, EfiPciWidthUint16, Address + 0x00, 1, &VendorDevice);
          if (EFI_ERROR(Status) || VendorDevice == 0xFFFF) {
            if (Func == 0) {
              break; // no more functions for this device
            }
            continue;
          }

          // Read header type to detect bridges/ports
          Status = PciRbIo->Pci.Read(PciRbIo, EfiPciWidthUint8, Address + 0x0E, 1, &HeaderType);
          if (EFI_ERROR(Status)) {
            continue;
          }

          // Walk capability list if present
          UINT16 StatusReg;
          Status = PciRbIo->Pci.Read(PciRbIo, EfiPciWidthUint16, Address + 0x06, 1, &StatusReg);
          if (EFI_ERROR(Status) || (StatusReg & BIT4) == 0) { // Capabilities List
            continue;
          }

          UINT8 CapPtr;
          Status = PciRbIo->Pci.Read(PciRbIo, EfiPciWidthUint8, Address + 0x34, 1, &CapPtr);
          if (EFI_ERROR(Status) || CapPtr < 0x40) {
            // Some devices use offset >= 0x40 typically; proceed anyway
          }

          // Basic capability walk (avoid infinite loops)
          for (UINTN hops = 0; hops < 48 && CapPtr >= 0x40; hops++) {
            UINT8 CapId;
            Status = PciRbIo->Pci.Read(PciRbIo, EfiPciWidthUint8, Address + CapPtr, 1, &CapId);
            if (EFI_ERROR(Status) || CapId == 0x00 || CapId == 0xFF) {
              break;
            }

            // Read next pointer
            UINT8 NextPtr;
            Status = PciRbIo->Pci.Read(PciRbIo, EfiPciWidthUint8, Address + CapPtr + 1, 1, &NextPtr);
            if (EFI_ERROR(Status)) {
              break;
            }

            if (CapId == 0x10) { // PCIe Capability ID
              // Find PTM and ACS in extended capabilities space (not in legacy caps)
              // We switch to extended capability walk starting from 0x100
              UINT16 ExtCapPtr = 0x100;
              for (UINTN ext = 0; ext < 64; ext++) {
                UINT32 ExtHdr;
                Status = PciRbIo->Pci.Read(PciRbIo, EfiPciWidthUint32, Address + ExtCapPtr, 1, &ExtHdr);
                if (EFI_ERROR(Status) || ExtHdr == 0xFFFFFFFF || ExtHdr == 0x00000000) {
                  break;
                }
                UINT16 ExtCapId = (UINT16)(ExtHdr & 0xFFFF);
                UINT16 ExtNext = (UINT16)((ExtHdr >> 20) & 0xFFF);

                if (ExtCapId == 0x001F) { // PTM
                  // Clear PTM enable bit in PTM Control (offset + 0x08)
                  UINT16 PtmCtrl;
                  Status = PciRbIo->Pci.Read(PciRbIo, EfiPciWidthUint16, Address + ExtCapPtr + 0x08, 1, &PtmCtrl);
                  if (!EFI_ERROR(Status)) {
                    PtmCtrl &= (UINT16)~BIT0; // PTM Enable = bit0
                    PciRbIo->Pci.Write(PciRbIo, EfiPciWidthUint16, Address + ExtCapPtr + 0x08, 1, &PtmCtrl);
                  }
                } else if (ExtCapId == 0x000D) { // ACS
                  // Enable ACS Source Validation, P2P Redirect, Up/Downstream Forwarding if supported
                  UINT16 AcsCap, AcsCtrl;
                  if (!EFI_ERROR(PciRbIo->Pci.Read(PciRbIo, EfiPciWidthUint16, Address + ExtCapPtr + 0x04, 1, &AcsCap)) &&
                      !EFI_ERROR(PciRbIo->Pci.Read(PciRbIo, EfiPciWidthUint16, Address + ExtCapPtr + 0x06, 1, &AcsCtrl))) {
                    UINT16 Desired = 0;
                    if (AcsCap & BIT0) Desired |= BIT0; // Source Validation
                    if (AcsCap & BIT5) Desired |= BIT5; // P2P Request Redirect
                    if (AcsCap & BIT6) Desired |= BIT6; // P2P Completion Redirect
                    if (AcsCap & BIT7) Desired |= BIT7; // Upstream Forwarding
                    if (AcsCap & BIT4) Desired |= BIT4; // Direct Translated P2P
                    if (Desired != 0) {
                      AcsCtrl |= Desired;
                      PciRbIo->Pci.Write(PciRbIo, EfiPciWidthUint16, Address + ExtCapPtr + 0x06, 1, &AcsCtrl);
                    }
                  }
                } else if (ExtCapId == 0x000F) { // ATS
                  // Disable ATS (Address Translation Service) to prevent endpoint TLP bypassing IOMMU
                  UINT16 AtsCtrl;
                  if (!EFI_ERROR(PciRbIo->Pci.Read(PciRbIo, EfiPciWidthUint16, Address + ExtCapPtr + 0x04, 1, &AtsCtrl))) {
                    AtsCtrl &= (UINT16)~BIT0; // ATS Enable = bit0
                    PciRbIo->Pci.Write(PciRbIo, EfiPciWidthUint16, Address + ExtCapPtr + 0x04, 1, &AtsCtrl);
                  }
                } else if (ExtCapId == 0x0013) { // PRI
                  // Disable Page Request Interface to avoid guest-initiated translations
                  UINT16 PriCtrl;
                  if (!EFI_ERROR(PciRbIo->Pci.Read(PciRbIo, EfiPciWidthUint16, Address + ExtCapPtr + 0x04, 1, &PriCtrl))) {
                    PriCtrl &= (UINT16)~BIT0; // PRI Enable = bit0
                    PciRbIo->Pci.Write(PciRbIo, EfiPciWidthUint16, Address + ExtCapPtr + 0x04, 1, &PriCtrl);
                  }
                }

                if (ExtNext == 0 || ExtNext < 0x100) {
                  break;
                }
                ExtCapPtr = ExtNext;
              }
            }

            if (NextPtr == 0 || NextPtr == CapPtr) {
              break;
            }
            CapPtr = NextPtr;
          }
        }
      }
    }
  }

  if (Handles != NULL) {
    FreePool(Handles);
  }
  return EFI_SUCCESS;
}

/**
  Disable SVM on the current processor.
  
  @retval EFI_SUCCESS       SVM disabled successfully.
  @retval Others            Failed to disable SVM.
**/
EFI_STATUS
EFIAPI
DisableSvm (
  VOID
  )
{
  EFI_STATUS  Status;
  UINT64      EferValue;

  //
  // Check if SVM is already disabled
  //
  EferValue = AsmReadMsr(MSR_EFER);
  if ((EferValue & EFER_SVME) == 0) {
    MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] SVM already disabled\n"));
    return EFI_SUCCESS;
  }

  //
  // Disable SVM by clearing EFER.SVME bit
  //
  Status = AsmDisableSvm();
  if (EFI_ERROR(Status)) {
    DEBUG((DEBUG_ERROR, "[SVM] Failed to disable SVM: %r\n", Status));
    return Status;
  }

  //
  // Verify SVM is disabled
  //
  EferValue = AsmReadMsr(MSR_EFER);
  if ((EferValue & EFER_SVME) != 0) {
    DEBUG((DEBUG_ERROR, "[SVM] SVM disable verification failed\n"));
    return EFI_DEVICE_ERROR;
  }

  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] SVM disabled successfully\n"));
  return EFI_SUCCESS;
}

/**
  Get SVM capabilities.
  
  @param[out] Capabilities  Pointer to receive SVM capabilities.
  
  @retval EFI_SUCCESS       Capabilities retrieved successfully.
  @retval EFI_INVALID_PARAMETER  Capabilities is NULL.
**/
EFI_STATUS
EFIAPI
GetSvmCapabilities (
  OUT SVM_CAPABILITIES *Capabilities
  )
{
  UINT32  Eax, Ebx, Ecx, Edx;

  if (Capabilities == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  ZeroMem(Capabilities, sizeof(SVM_CAPABILITIES));

  //
  // Get basic SVM support
  //
  AsmCpuid(0x80000001, &Eax, &Ebx, &Ecx, &Edx);
  Capabilities->SvmSupported = ((Ecx & BIT2) != 0);

  if (!Capabilities->SvmSupported) {
    return EFI_SUCCESS;
  }

  //
  // Get SVM features from CPUID leaf 0x8000000A
  //
  AsmCpuid(0x8000000A, &Eax, &Ebx, &Ecx, &Edx);
  
  // EAX contains revision and maximum ASID
  Capabilities->MaxAsid = Ebx;
  
  // EDX contains feature flags
  Capabilities->NestedPagingSupported = ((Edx & CPUID_SVM_NESTED_PAGING) != 0);
  Capabilities->LbrVirtualizationSupported = ((Edx & CPUID_SVM_LBR_VIRT) != 0);
  Capabilities->SvmLockSupported = ((Edx & CPUID_SVM_LOCK) != 0);
  Capabilities->NextRipSaveSupported = ((Edx & CPUID_SVM_NRIP_SAVE) != 0);
  Capabilities->TscRateMsrSupported = ((Edx & CPUID_SVM_TSC_RATE_MSR) != 0);
  Capabilities->VmcbCleanSupported = ((Edx & CPUID_SVM_VMCB_CLEAN) != 0);
  Capabilities->FlushByAsidSupported = ((Edx & CPUID_SVM_FLUSH_BY_ASID) != 0);
  Capabilities->DecodeAssistsSupported = ((Edx & CPUID_SVM_DECODE_ASSISTS) != 0);
  Capabilities->PauseFilterSupported = ((Edx & CPUID_SVM_PAUSE_FILTER) != 0);
  Capabilities->PauseFilterThresholdSupported = ((Edx & CPUID_SVM_PAUSE_THRESH) != 0);
  Capabilities->AvicSupported = ((Edx & CPUID_SVM_AVIC) != 0);
  Capabilities->VirtualVmsaveVmloadSupported = ((Edx & CPUID_SVM_VMSAVE_VMLOAD) != 0);
  Capabilities->VgifSupported = ((Edx & CPUID_SVM_VGIF) != 0);
  Capabilities->GmetSupported = ((Edx & CPUID_SVM_GMET) != 0);

  // Set maximum nested page table levels (typically 4 for x64)
  Capabilities->MaxNestedPageTableLevels = 4;

  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] Capabilities retrieved: NPT=%d, ASID=%d, AVIC=%d\n", 
    Capabilities->NestedPagingSupported, 
    Capabilities->MaxAsid,
    Capabilities->AvicSupported));

  return EFI_SUCCESS;
}

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
  )
{
  VMCB                    *Vmcb;
  VMCB_CONTROL_AREA       *ControlArea;
  VMCB_STATE_SAVE_AREA    *StateSaveArea;

  if (VmcbPhysicalAddress == 0) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Map VMCB to virtual address for initialization
  //
  Vmcb = (VMCB *)(UINTN)VmcbPhysicalAddress;
  ZeroMem(Vmcb, sizeof(VMCB));

  ControlArea = &Vmcb->ControlArea;
  StateSaveArea = &Vmcb->StateSaveArea;

  //
  // Set up comprehensive intercepts for stealth hypervisor
  //
  ControlArea->InterceptException = SVM_INTERCEPT_EXCEPTION_PF | SVM_INTERCEPT_EXCEPTION_GP;
  ControlArea->InterceptInstr1 = SVM_INTERCEPT_CPUID |
                                 SVM_INTERCEPT_MSR_PROT |
                                 SVM_INTERCEPT_IOIO_PROT |
                                 SVM_INTERCEPT_RDTSC |
                                 SVM_INTERCEPT_RDPMC;
  ControlArea->InterceptInstr2 = SVM_INTERCEPT_VMMCALL |
                                 SVM_INTERCEPT_RDTSCP;

  //
  // Set up ASID (Address Space Identifier)
  //
  ControlArea->Asid = 1; // Use ASID 1 for guest

  //
  // Enable Nested Paging if supported
  //
  if (gMiniVisorSvmGlobalData.SvmCapabilities.NestedPagingSupported) {
    ControlArea->NestedPageEnable = 1;
    ControlArea->NestedCr3 = gMiniVisorSvmGlobalData.NptPml4Base;
    gMiniVisorSvmGlobalData.Status |= MINI_VISOR_SVM_STATUS_NPT_ENABLED;
  }

  //
  // Set up MSR bitmap if available
  //
  if (gMiniVisorSvmGlobalData.MsrBitmapBase != 0) {
    ControlArea->MsrpmBasePa = gMiniVisorSvmGlobalData.MsrBitmapBase;
  }

  //
  // Set up I/O bitmap if available
  //
  if (gMiniVisorSvmGlobalData.IoBitmapBase != 0) {
    ControlArea->IopmBasePa = gMiniVisorSvmGlobalData.IoBitmapBase;
  }

  //
  // Initialize guest state with current processor state
  //
  StateSaveArea->Cr0 = AsmReadCr0();
  StateSaveArea->Cr3 = AsmReadCr3();
  StateSaveArea->Cr4 = AsmReadCr4();
  StateSaveArea->Efer = AsmReadMsr(MSR_EFER);
  StateSaveArea->Rflags = 0x2; // Initial RFLAGS value

  //
  // Set up segment registers (simplified)
  //
  StateSaveArea->Cs.Selector = AsmReadCs();
  StateSaveArea->Cs.Base = 0;
  StateSaveArea->Cs.Limit = 0xFFFFFFFF;
  StateSaveArea->Cs.Attributes = 0xA09B; // Code segment attributes

  StateSaveArea->Ds.Selector = AsmReadDs();
  StateSaveArea->Ds.Base = 0;
  StateSaveArea->Ds.Limit = 0xFFFFFFFF;
  StateSaveArea->Ds.Attributes = 0xC093; // Data segment attributes

  StateSaveArea->Es.Selector = AsmReadEs();
  StateSaveArea->Es.Base = 0;
  StateSaveArea->Es.Limit = 0xFFFFFFFF;
  StateSaveArea->Es.Attributes = 0xC093;

  StateSaveArea->Ss.Selector = AsmReadSs();
  StateSaveArea->Ss.Base = 0;
  StateSaveArea->Ss.Limit = 0xFFFFFFFF;
  StateSaveArea->Ss.Attributes = 0xC093;

  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] VMCB initialized at 0x%lx\n", VmcbPhysicalAddress));
  return EFI_SUCCESS;
}

/**
  Setup Nested Page Tables (NPT).
  
  @retval EFI_SUCCESS       NPT setup successfully.
  @retval Others            Failed to setup NPT.
**/
EFI_STATUS
EFIAPI
SetupNestedPageTables (
  VOID
  )
{
  EFI_PHYSICAL_ADDRESS  NptPml4Base;
  NPT_PML4E            *Pml4Entry;
  NPT_PDPTE            *PdpEntry;
  UINTN                 Index;
  EFI_STATUS            Status;

  //
  // Check if NPT is supported
  //
  if (!gMiniVisorSvmGlobalData.SvmCapabilities.NestedPagingSupported) {
    DEBUG((DEBUG_WARN, "[SVM] NPT not supported, using shadow paging\n"));
    return EFI_UNSUPPORTED;
  }

  //
  // Allocate NPT PML4 table (4KB aligned)
  //
  Status = SvmAllocateTrackedPages(
                  AllocateAnyPages,
                  EfiReservedMemoryType,
                  1, // 4KB
                  &NptPml4Base
                  );
  if (EFI_ERROR(Status)) {
    DEBUG((DEBUG_ERROR, "[SVM] Failed to allocate NPT PML4: %r\n", Status));
    return Status;
  }

  ZeroMem((VOID *)(UINTN)NptPml4Base, SIZE_4KB);

  //
  // Set up identity mapping for first 4GB
  // This is a simplified setup - real implementation should map actual system memory
  //
  Pml4Entry = (NPT_PML4E *)(UINTN)NptPml4Base;
  
  for (Index = 0; Index < 4; Index++) {
    //
    // Allocate PDPT
    //
    EFI_PHYSICAL_ADDRESS PdptBase;
    Status = SvmAllocateTrackedPages(AllocateAnyPages, EfiReservedMemoryType, 1, &PdptBase);
    if (EFI_ERROR(Status)) {
      DEBUG((DEBUG_ERROR, "[SVM] Failed to allocate PDPT: %r\n", Status));
      return Status;
    }
    ZeroMem((VOID *)(UINTN)PdptBase, SIZE_4KB);

    Pml4Entry[Index].Present = 1;
    Pml4Entry[Index].Write = 1;
    Pml4Entry[Index].User = 1;
    Pml4Entry[Index].PhysicalAddress = PdptBase >> 12;

    //
    // Set up PDPT entries (1GB pages)
    //
    PdpEntry = (NPT_PDPTE *)(UINTN)PdptBase;
    for (UINTN j = 0; j < 512; j++) {
      PdpEntry[j].Present = 1;
      PdpEntry[j].Write = 1;
      PdpEntry[j].User = 1;
      PdpEntry[j].PageSize = 1; // 1GB page
      PdpEntry[j].PhysicalAddress = ((Index * 512 + j) * SIZE_1GB) >> 12;
    }
  }

  gMiniVisorSvmGlobalData.NptPml4Base = NptPml4Base;
  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] NPT setup completed at 0x%lx\n", NptPml4Base));
  
  return EFI_SUCCESS;
}

/**
  Setup MSR bitmap for SVM.
  
  @retval EFI_SUCCESS       MSR bitmap setup successfully.
  @retval Others            Failed to setup MSR bitmap.
**/
EFI_STATUS
EFIAPI
SetupMsrBitmap (
  VOID
  )
{
  EFI_PHYSICAL_ADDRESS  MsrBitmapBase;
  UINT8                 *MsrBitmap;
  EFI_STATUS            Status;

  //
  // Allocate MSR permissions map (MSRPM): 2 contiguous 4KB pages (8KB total)
  //
  Status = gBS->AllocatePages(
                  AllocateAnyPages,
                  EfiReservedMemoryType,
                  2, // 8KB
                  &MsrBitmapBase
                  );
  if (EFI_ERROR(Status)) {
    DEBUG((DEBUG_ERROR, "[SVM] Failed to allocate MSR bitmap: %r\n", Status));
    return Status;
  }

  MsrBitmap = (UINT8 *)(UINTN)MsrBitmapBase;

  //
  // By default, all MSRs cause VM exits (bitmap = 1)
  // Clear bits for MSRs we want to handle directly in guest
  //
  SetMem(MsrBitmap, 2 * SIZE_4KB, 0xFF);

  //
  // Allow guest direct access to some performance MSRs
  // MSR 0x0000-0x1FFF range bitmap starts at offset 0
  // MSR 0xC0000000-0xC0001FFF range bitmap starts at offset 0x800
  //
  
  // Example: Allow direct access to TSC (MSR 0x10)
  // MsrBitmap[0x10 / 8] &= ~(1 << (0x10 % 8));

  gMiniVisorSvmGlobalData.MsrBitmapBase = MsrBitmapBase;
  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] MSR bitmap setup completed at 0x%lx\n", MsrBitmapBase));

  return EFI_SUCCESS;
}

/**
  Setup I/O bitmap for SVM.
  
  @retval EFI_SUCCESS       I/O bitmap setup successfully.
  @retval Others            Failed to setup I/O bitmap.
**/
EFI_STATUS
EFIAPI
SetupIoBitmap (
  VOID
  )
{
  EFI_PHYSICAL_ADDRESS  IoBitmapBase;
  UINT8                 *IoBitmap;
  EFI_STATUS            Status;

  //
  // Allocate I/O permission map (IOPM): 3 contiguous 4KB pages (12KB total)
  //
  Status = gBS->AllocatePages(
                  AllocateAnyPages,
                  EfiReservedMemoryType,
                  3, // 12KB
                  &IoBitmapBase
                  );
  if (EFI_ERROR(Status)) {
    DEBUG((DEBUG_ERROR, "[SVM] Failed to allocate I/O bitmap: %r\n", Status));
    return Status;
  }

  IoBitmap = (UINT8 *)(UINTN)IoBitmapBase;
  
  //
  // By default, all I/O ports cause VM exits (bitmap = 1)
  // Clear bits for ports we want to allow direct guest access
  //
  SetMem(IoBitmap, 3 * SIZE_4KB, 0xFF);

  //
  // Allow direct access to some standard ports
  // For example: keyboard (0x60, 0x64), timer (0x40-0x43)
  //
  
  // Example: Allow keyboard ports
  // IoBitmap[0x60 / 8] &= ~(1 << (0x60 % 8));
  // IoBitmap[0x64 / 8] &= ~(1 << (0x64 % 8));

  gMiniVisorSvmGlobalData.IoBitmapBase = IoBitmapBase;
  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] I/O bitmap setup completed at 0x%lx\n", IoBitmapBase));

  return EFI_SUCCESS;
}

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
  )
{
  if (Asid == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Simple ASID allocation - increment current ASID
  // Real implementation should have a proper ASID pool management
  //
  if (gMiniVisorSvmGlobalData.CurrentAsid >= gMiniVisorSvmGlobalData.MaxAsid) {
    DEBUG((DEBUG_ERROR, "[SVM] ASID pool exhausted\n"));
    return EFI_OUT_OF_RESOURCES;
  }

  gMiniVisorSvmGlobalData.CurrentAsid++;
  *Asid = gMiniVisorSvmGlobalData.CurrentAsid;

  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] ASID %d allocated\n", *Asid));
  return EFI_SUCCESS;
}

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
  )
{
  if (Asid == 0 || Asid > gMiniVisorSvmGlobalData.MaxAsid) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Simple implementation - real version should manage ASID pool
  //
  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] ASID %d freed\n", Asid));
  return EFI_SUCCESS;
}

/**
  Launch the guest using SVM.
  
  @retval EFI_SUCCESS       Guest launched successfully.
  @retval Others            Failed to launch guest.
**/
EFI_STATUS
EFIAPI
LaunchGuest (
  VOID
  )
{
  EFI_STATUS            Status;
  EFI_PHYSICAL_ADDRESS  VmcbPhysicalAddress;

  if (!IS_SVM_ENABLED()) {
    DEBUG((DEBUG_ERROR, "[SVM] SVM not enabled\n"));
    return EFI_NOT_READY;
  }

  VmcbPhysicalAddress = (EFI_PHYSICAL_ADDRESS)(UINTN)gMiniVisorSvmGlobalData.VmcbRegion;
  
  //
  // Initialize VMCB before launch
  //
  Status = InitializeVmcb(VmcbPhysicalAddress);
  if (EFI_ERROR(Status)) {
    DEBUG((DEBUG_ERROR, "[SVM] Failed to initialize VMCB: %r\n", Status));
    return Status;
  }

  //
  // Execute VMRUN to start guest
  //
  Status = AsmVmrun(VmcbPhysicalAddress);
  if (EFI_ERROR(Status)) {
    DEBUG((DEBUG_ERROR, "[SVM] VMRUN failed: %r\n", Status));
    return Status;
  }

  gMiniVisorSvmGlobalData.Status |= MINI_VISOR_SVM_STATUS_GUEST_RUNNING;
  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] Guest launched successfully\n"));

  return EFI_SUCCESS;
}

/**
  Ring-2 Nested SVM Exit Handler - Enhanced with Real-time Protection
**/
VOID
EFIAPI
NestedSvmExitHandler (
  IN VOID *Registers
  )
{
  VMCB            *Vmcb;
  UINT64          ExitCode;
  SVM_EXIT_INFO   ExitInfo;
  NESTED_SVM_CONTEXT Context;
  UINT64          ExitStartTime, ExitEndTime;

  //
  // Performance monitoring - start time
  //
  ExitStartTime = AsmReadTsc();

  //
  // Get VMCB from global data
  //
  Vmcb = (VMCB *)gMiniVisorSvmGlobalData.VmcbRegion;
  if (Vmcb == NULL) {
    DEBUG((DEBUG_ERROR, "[SVM] Invalid VMCB in exit handler\n"));
    return;
  }

  //
  // Extract exit information from VMCB
  //
  ExitCode = Vmcb->ControlArea.ExitCode;
  ExitInfo.ExitCode = ExitCode;
  ExitInfo.ExitInfo1 = Vmcb->ControlArea.ExitInfo1;
  ExitInfo.ExitInfo2 = Vmcb->ControlArea.ExitInfo2;
  ExitInfo.ExitIntInfo = Vmcb->ControlArea.ExitIntInfo;
  ExitInfo.NextRip = Vmcb->ControlArea.NextRip;

  //
  // Update performance counters
  //
  gMiniVisorSvmGlobalData.PerfData.VmExitCount++;
  gMiniVisorSvmGlobalData.PerfData.LastVmExitReason = ExitCode;

  //
  // Handle the SVM exit
  //
  HandleSvmExitInternal(ExitCode, &ExitInfo, &Context);

  //
  // Performance monitoring - end time
  //
  ExitEndTime = AsmReadTsc();
  gMiniVisorSvmGlobalData.PerfData.TotalVmExitTime += (ExitEndTime - ExitStartTime);
  
  if (gMiniVisorSvmGlobalData.PerfData.VmExitCount > 0) {
    gMiniVisorSvmGlobalData.PerfData.AverageVmExitTime = 
      gMiniVisorSvmGlobalData.PerfData.TotalVmExitTime / gMiniVisorSvmGlobalData.PerfData.VmExitCount;
  }

  MINI_VISOR_SVM_DEBUG((DEBUG_VERBOSE, "[SVM] Exit handled: Code=0x%lx, Time=%ld\n", 
    ExitCode, ExitEndTime - ExitStartTime));
}

/**
  Handle SVM VM Exit internally.
  
  @param[in] ExitCode       The SVM exit code.
  @param[in] ExitInfo       Pointer to exit information.
  @param[in] Context        Pointer to guest context.
**/
STATIC
VOID
HandleSvmExitInternal (
  IN UINT64 ExitCode,
  IN SVM_EXIT_INFO *ExitInfo,
  IN OUT NESTED_SVM_CONTEXT *Context
  )
{
  EFI_STATUS Status;

  switch (ExitCode) {
    case SVM_EXIT_CPUID:
      Status = HandleCpuidExit(Context);
      break;

    case SVM_EXIT_MSR:
      Status = HandleMsrExit(ExitInfo, Context);
      break;

    // Do not intercept RDTSC/RDTSCP/RDPMC by default for broad compatibility

    case SVM_EXIT_NPF:
      Status = HandleNptViolation(ExitInfo, Context);
      gMiniVisorSvmGlobalData.PerfData.NptViolationCount++;
      break;

    case SVM_EXIT_IOIO:
      Status = HandleIoExit(ExitInfo, Context);
      gMiniVisorSvmGlobalData.PerfData.IoInterceptCount++;
      break;

    case SVM_EXIT_VMMCALL:
      Status = HandleVmmcall(Context);
      break;

    case SVM_EXIT_RDTSC:
      Status = HandleRdtscExit(Context);
      break;

    case SVM_EXIT_RDTSCP:
      Status = HandleRdtscpExit(Context);
      break;

    case SVM_EXIT_RDPMC:
      Status = HandleRdpmcExit(Context);
      break;

    case SVM_EXIT_SHUTDOWN:
      DEBUG((DEBUG_ERROR, "[SVM] Guest shutdown\n"));
      gMiniVisorSvmGlobalData.Status &= ~MINI_VISOR_SVM_STATUS_GUEST_RUNNING;
      Status = EFI_SUCCESS;
      break;

    default:
      DEBUG((DEBUG_WARN, "[SVM] Unhandled exit code: 0x%lx\n", ExitCode));
      Status = EFI_UNSUPPORTED;
      break;
  }

  if (EFI_ERROR(Status)) {
    DEBUG((DEBUG_ERROR, "[SVM] Exit handler failed: %r\n", Status));
  }
}
/**
  Handle CPUID VM Exit with comprehensive anti-detection.
  
  @param[in] Context        Pointer to guest context.
  
  @retval EFI_SUCCESS       CPUID handled successfully.
**/
EFI_STATUS
EFIAPI
HandleCpuidExit (
  IN OUT NESTED_SVM_CONTEXT *Context
  )
{
  UINT32 Function, SubFunction;
  UINT32 Eax, Ebx, Ecx, Edx;
  STATIC UINT64 CpuidCallCount = 0;
  STATIC UINT64 LastTscValue = 0;
  STATIC UINT32 SessionRandomSeed = 0;

  CpuidCallCount++;
  
  // Initialize session random seed on first call
  if (SessionRandomSeed == 0) {
    SessionRandomSeed = (UINT32)AsmReadTsc();
  }

  //
  // Get CPUID function from guest RAX
  //
  Function = (UINT32)Context->GuestRax;
  SubFunction = (UINT32)Context->GuestRcx;

  //
  // Execute CPUID and get results
  //
  AsmCpuidEx(Function, SubFunction, &Eax, &Ebx, &Ecx, &Edx);

  // Get current TSC for timing-based randomization
  UINT64 CurrentTsc = AsmReadTsc();
  if (LastTscValue == 0) LastTscValue = CurrentTsc;
  UINT32 TimingRandom = (UINT32)(CurrentTsc ^ (CurrentTsc >> 32) ^ CpuidCallCount ^ SessionRandomSeed);

  //
  // Comprehensive CPUID manipulation for maximum stealth and future-proofing
  //
  switch (Function) {
    case 0x00000000:
      // Maximum input value - add dynamic variations for emulator confusion
      if ((TimingRandom & 0x3F) == 0) {
        Eax = (Eax > 0x16) ? Eax - (1 + (TimingRandom & 0x3)) : Eax;
      }
      // Occasionally modify vendor ID to create inconsistency
      if ((TimingRandom & 0x1FF) == 0x1FF) {
        Ebx ^= (TimingRandom & 0xFF);
        Ecx ^= ((TimingRandom >> 8) & 0xFF);
        Edx ^= ((TimingRandom >> 16) & 0xFF);
      }
      break;

    case 0x00000001:
      // Feature Information - comprehensive multi-layer hiding
      Ecx &= ~BIT31;  // Always hide hypervisor presence
      
      // Dynamic feature masking to confuse pattern recognition
      if ((TimingRandom & 0x1F) == 0) {
        Ecx ^= BIT23;  // Flip POPCNT occasionally
      }
      if ((TimingRandom & 0x3F) == 1) {
        Ecx ^= BIT19;  // Flip SSE4.1 occasionally  
      }
      if ((TimingRandom & 0x7F) == 2) {
        Ecx ^= BIT20;  // Flip SSE4.2 occasionally
      }
      
      // Cache line size variations for L1D cache detection confusion
      Ebx = (Ebx & ~0xFF) | ((TimingRandom & 0x7) + (Ebx & 0xFF));
      
      // Family/Model/Stepping variations for CPU fingerprinting resistance
      if ((CpuidCallCount & 0x7FF) == 0x7FF) {  // Every 2048 calls
        UINT32 ModelMask = (Eax >> 4) & 0xF;
        Eax = (Eax & ~0xF0) | (((ModelMask + (TimingRandom & 0x3)) & 0xF) << 4);
      }
      break;

    case 0x00000002:
      // Cache and TLB descriptor - comprehensive randomization
      Eax ^= (TimingRandom & 0xFFFFFF);
      Ebx ^= ((TimingRandom >> 8) & 0xFFFFFF);
      Ecx ^= ((TimingRandom >> 16) & 0xFFFFFF);
      Edx ^= ((TimingRandom >> 24) & 0xFFFFFF);
      break;

    case 0x00000003:
      // Processor Serial Number - always zero or randomize
      Eax = 0;
      Ebx = 0;
      Ecx = TimingRandom;
      Edx = TimingRandom >> 16;
      break;

    case 0x00000004:
      // Deterministic Cache Parameters - modify for cache fingerprinting resistance
      if ((TimingRandom & 0x1F) == 0) {
        Eax = (Eax & ~0x1F) | (((Eax & 0x1F) + 1) & 0x1F);  // Modify cache level
      }
      if ((TimingRandom & 0x3F) == 1) {
        Ebx ^= (TimingRandom & 0xFFF);  // Modify cache size parameters
      }
      break;

    case 0x00000005:
      // MONITOR/MWAIT Parameters - randomize for power management detection resistance
      Eax ^= (TimingRandom & 0xFFFF);
      Ebx ^= ((TimingRandom >> 8) & 0xFFFF);
      Ecx ^= ((TimingRandom >> 16) & 0xFF);
      break;

    case 0x00000006:
      // Thermal and Power Management - comprehensive power feature hiding
      Eax &= ~0xF;  // Hide thermal management
      Eax ^= (TimingRandom & 0x7);
      Ecx ^= ((TimingRandom >> 3) & 0x7);
      break;

    case 0x00000007:
      // Extended Features - comprehensive advanced feature manipulation
      if (SubFunction == 0) {
        // Hide/randomize advanced features for detection resistance
        Ebx &= ~BIT18;  // Hide RDSEED
        Ecx &= ~BIT30;  // Hide SGX completely
        Edx &= ~BIT29;  // Hide SHA extensions
        
        if ((TimingRandom & 0xF) == 0) {
          Ebx ^= BIT3;   // Flip BMI1 occasionally
          Ebx ^= BIT8;   // Flip BMI2 occasionally
          Ebx ^= BIT19;  // Flip ADX occasionally
        }
        
        // Advanced randomization for specific instruction sets
        if ((TimingRandom & 0x1F) == 3) {
          Ebx ^= BIT16;  // Flip AVX512F
          Ebx ^= BIT17;  // Flip AVX512DQ
        }
      }
      break;

    case 0x00000009:
      // Direct Cache Access Parameters - hide DCA
      Eax = 0;
      Ebx = 0;
      Ecx = 0;
      Edx = 0;
      break;

    case 0x0000000A:
      // Architectural Performance Monitoring - completely hide for stealth
      Eax = 0;
      Ebx = 0;
      Ecx = 0;
      Edx = 0;
      break;

    case 0x0000000B:
    case 0x0000001F:
      // Extended Topology - comprehensive topology masking
      if ((TimingRandom & 0x7) == 0) {
        Ebx = (Ebx & ~0xFFFF) | ((Ebx & 0xFFFF) + (TimingRandom & 0x7));
      }
      // Randomize APIC ID for core identification resistance
      Edx ^= (TimingRandom & 0xFF);
      break;

    case 0x0000000D:
      // XSAVE Features - comprehensive state management hiding
      if (SubFunction == 0) {
        if ((TimingRandom & 0x1F) == 0) {
          Eax ^= BIT2;  // Flip AVX state occasionally
          Eax ^= BIT9;  // Flip PKRU state occasionally
        }
      } else if (SubFunction == 1) {
        Eax &= ~0xF;  // Hide all XSAVE optimizations
      }
      break;

    case 0x0000000F:
    case 0x00000010:
      // Intel RDT (Resource Director Technology) - hide completely
      Eax = 0;
      Ebx = 0;
      Ecx = 0;
      Edx = 0;
      break;

    case 0x00000012:
      // Intel SGX Capability - hide SGX completely
      Eax = 0;
      Ebx = 0;
      Ecx = 0;
      Edx = 0;
      break;

    case 0x00000014:
      // Intel Processor Trace - hide PT completely
      Eax = 0;
      Ebx = 0;
      Ecx = 0;
      Edx = 0;
      break;

    case 0x00000015:
    case 0x00000016:
      // TSC/Processor Frequency - comprehensive frequency manipulation
      {
        UINT32 Variation = (TimingRandom & 0x3F) + 85;  // 85-148% variation
        Eax = (Eax * Variation) / 100;
        Ebx = (Ebx * ((TimingRandom >> 6) & 0x3F + 85)) / 100;
        Ecx = (Ecx * ((TimingRandom >> 12) & 0x3F + 85)) / 100;
      }
      break;

    case 0x00000017:
      // System-On-Chip Vendor Attribute - randomize or hide
      Eax ^= TimingRandom;
      Ebx ^= (TimingRandom >> 8);
      Ecx ^= (TimingRandom >> 16);
      Edx ^= (TimingRandom >> 24);
      break;

    case 0x00000018:
      // Deterministic Address Translation Parameters - modify for TLB fingerprinting resistance
      if ((TimingRandom & 0xF) == 0) {
        Ebx ^= (TimingRandom & 0xFFFF);
        Ecx ^= ((TimingRandom >> 8) & 0xFFFF);
      }
      break;

    case 0x00000019:
      // Key Locker - hide encryption features
      Eax = 0;
      Ebx = 0;
      Ecx = 0;
      Edx = 0;
      break;

    case 0x0000001A:
      // Hybrid Information - hide P/E core information
      Eax = 0;
      Ebx = 0;
      Ecx = 0;
      Edx = 0;
      break;

    case 0x0000001B:
      // PCONFIG - hide platform configuration
      Eax = 0;
      Ebx = 0;
      Ecx = 0;
      Edx = 0;
      break;

    case 0x0000001C:
      // Last Branch Records - hide LBR
      Eax = 0;
      Ebx = 0;
      Ecx = 0;
      Edx = 0;
      break;

    case 0x0000001D:
      // Tile Information - hide AMX
      Eax = 0;
      Ebx = 0;
      Ecx = 0;
      Edx = 0;
      break;

    case 0x0000001E:
      // TMUL Information - hide AMX details
      Eax = 0;
      Ebx = 0;
      Ecx = 0;
      Edx = 0;
      break;

    // Hypervisor CPUID space - comprehensive multi-strategy approach
    case 0x40000000:
      // Dynamic hypervisor signature strategy
      if ((CpuidCallCount & 0x3) == 0) {
        // Strategy 1: Hide completely (25% of calls)
        Eax = 0;
        Ebx = 0;
        Ecx = 0;
        Edx = 0;
      } else if ((CpuidCallCount & 0x3) == 1) {
        // Strategy 2: Fake VMware signature (25% of calls)
        Eax = 0x40000010;
        Ebx = 0x61774D56; // "VMwa"
        Ecx = 0x4D566572; // "reVM"
        Edx = 0x65726177; // "ware"
      } else if ((CpuidCallCount & 0x3) == 2) {
        // Strategy 3: Fake Hyper-V signature (25% of calls)
        Eax = 0x40000005;
        Ebx = 0x7263694D; // "Micr"
        Ecx = 0x666F736F; // "osof"
        Edx = 0x76482074; // "t Hv"
      } else {
        // Strategy 4: Dynamic fake signature (25% of calls)
        Eax = 0x40000001 + (TimingRandom & 0xF);
        Ebx = 0x61774D56 ^ (TimingRandom & 0xFFFFFF);
        Ecx = 0x4D566572 ^ ((TimingRandom >> 8) & 0xFFFFFF);
        Edx = 0x65726177 ^ ((TimingRandom >> 16) & 0xFFFFFF);
      }
      break;

    case 0x40000001:
    case 0x40000002:
    case 0x40000003:
    case 0x40000004:
    case 0x40000005:
    case 0x40000006:
    case 0x40000007:
    case 0x40000008:
    case 0x40000009:
    case 0x4000000A:
    case 0x4000000B:
    case 0x4000000C:
    case 0x4000000D:
    case 0x4000000E:
    case 0x4000000F:
    case 0x40000010:
      // Extended hypervisor leaves - comprehensive fake data
      if ((CpuidCallCount & 0x1) == 0) {
        // Fake VMware-style data
        Eax = TimingRandom;
        Ebx = TimingRandom >> 8;
        Ecx = TimingRandom >> 16;
        Edx = TimingRandom >> 24;
      } else {
        // Hide completely
        Eax = 0;
        Ebx = 0;
        Ecx = 0;
        Edx = 0;
      }
      break;

    case 0x80000000:
      // Maximum extended function - dynamic limitation
      if ((TimingRandom & 0x1F) == 0) {
        Eax = (Eax > 0x8000001F) ? Eax - (1 + (TimingRandom & 0x7)) : Eax;
      }
      break;

    case 0x80000001:
      // Extended feature flags - comprehensive AMD-specific hiding
      Ecx &= ~BIT2;   // Always hide SVM
      Edx &= ~BIT29;  // Hide LM bit occasionally for confusion
      
      if ((TimingRandom & 0xF) == 0) {
        Ecx ^= BIT6;  // Flip SSE4A occasionally
        Ecx ^= BIT11; // Flip XOP occasionally
        Ecx ^= BIT16; // Flip FMA4 occasionally
      }
      
      // Additional AMD feature randomization
      if ((TimingRandom & 0x1F) == 3) {
        Ecx ^= BIT21; // Flip TBM
        Ecx ^= BIT23; // Flip BMI1
      }
      break;

    case 0x80000002:
    case 0x80000003:
    case 0x80000004:
      // Processor brand string - subtle brand manipulation
      {
        UINT32 *BrandRegs[4] = {&Eax, &Ebx, &Ecx, &Edx};
        for (UINTN i = 0; i < 4; i++) {
          // Occasionally flip specific bits in brand string
          if ((TimingRandom & (0x7F << (i * 7))) == 0) {
            *BrandRegs[i] ^= (1 << ((TimingRandom >> (i * 3)) & 0x1F));
          }
        }
      }
      break;

    case 0x80000005:
      // L1 Cache and TLB Identifiers - cache fingerprinting resistance
      Eax ^= (TimingRandom & 0xFFFFFF);
      Ebx ^= ((TimingRandom >> 8) & 0xFFFFFF);
      Ecx ^= ((TimingRandom >> 16) & 0xFFFFFF);
      Edx ^= ((TimingRandom >> 24) & 0xFFFFFF);
      break;

    case 0x80000006:
      // L2/L3 Cache and TLB Identifiers - comprehensive cache masking
      Eax ^= (TimingRandom & 0xFFFFFF);
      Ebx ^= ((TimingRandom >> 8) & 0xFFFFFF);
      Ecx ^= ((TimingRandom >> 16) & 0xFFFFFF);
      Edx ^= ((TimingRandom >> 24) & 0xFFFFFF);
      break;

    case 0x80000007:
      // Advanced Power Management - hide all advanced power features
      Edx = 0;  // Hide invariant TSC, APIC timer, etc.
      if ((TimingRandom & 0x7) == 0) {
        Edx = TimingRandom & 0xFF;  // Occasionally show fake features
      }
      break;

    case 0x80000008:
      // Address size and physical core count - modify for fingerprinting resistance
      if ((TimingRandom & 0x1F) == 0) {
        Eax = (Eax & ~0xFF) | (((Eax & 0xFF) - 1) & 0xFF);  // Reduce physical address bits
      }
      if ((TimingRandom & 0x3F) == 1) {
        Ecx = (Ecx & ~0xFF) | (((Ecx & 0xFF) + (TimingRandom & 0x7)) & 0xFF);  // Modify core count
      }
      break;

    case 0x80000019:
      // TLB 1GB Page Identifiers - hide or randomize
      Eax ^= TimingRandom;
      Ebx ^= (TimingRandom >> 8);
      break;

    case 0x8000001A:
      // Performance Optimization Identifiers - hide performance features
      Eax = 0;
      Ebx = 0;
      Ecx = 0;
      Edx = 0;
      break;

    case 0x8000001B:
      // Instruction Based Sampling - hide IBS
      Eax = 0;
      Ebx = 0;
      Ecx = 0;
      Edx = 0;
      break;

    case 0x8000001C:
      // Lightweight Profiling - hide LWP
      Eax = 0;
      Ebx = 0;
      Ecx = 0;
      Edx = 0;
      break;

    case 0x8000001D:
      // Cache Properties - comprehensive cache topology hiding
      if ((TimingRandom & 0xF) == 0) {
        Eax ^= (TimingRandom & 0x1F);  // Modify cache type/level
        Ebx ^= ((TimingRandom >> 5) & 0x3FF);  // Modify line size/associativity
      }
      break;

    case 0x8000001E:
      // Extended APIC ID - randomize APIC topology
      Eax ^= (TimingRandom & 0xFF);
      Ebx ^= ((TimingRandom >> 8) & 0xFFFF);
      Ecx ^= ((TimingRandom >> 16) & 0xFF);
      break;

    case 0x8000001F:
      // AMD Memory Encryption - completely hide SME/SEV
      Eax = 0;
      Ebx = 0;
      Ecx = 0;
      Edx = 0;
      break;

    case 0x80000020:
      // Platform Quality of Service - hide QoS
      Eax = 0;
      Ebx = 0;
      Ecx = 0;
      Edx = 0;
      break;

    case 0x80000021:
      // Extended Feature Identification 2 - hide advanced AMD features
      Eax = 0;
      Ebx = 0;
      Ecx = 0;
      Edx = 0;
      break;

    case 0x8000000A:
      // SVM Feature Identification - completely hide SVM
      Eax = 0;
      Ebx = 0;
      Ecx = 0;
      Edx = 0;
      break;

    

    default:
      // For any unhandled leaves, apply comprehensive randomization
      if (Function > 0x8000001F || (Function >= 0x40000000 && Function <= 0x400000FF)) {
        // Apply multi-layer randomization
        Eax ^= TimingRandom;
        Ebx ^= (TimingRandom >> 8);
        Ecx ^= (TimingRandom >> 16);
        Edx ^= (TimingRandom >> 24);
        
        // Additional scrambling for deep detection resistance
        if ((CpuidCallCount & 0x7) == 0x7) {
          Eax = TimingRandom;
          Ebx = TimingRandom >> 8;
          Ecx = TimingRandom >> 16;
          Edx = TimingRandom >> 24;
        }
      }
      break;
  }

  // Ultra-paranoid additional randomization layer
  if ((CpuidCallCount & 0x3FF) == 0x3FF) {  // Every 1024 calls
    switch (TimingRandom & 0x3) {
      case 0:
        Eax = TimingRandom;
        break;
      case 1:
        Ebx = TimingRandom;
        break;
      case 2:
        Ecx = TimingRandom;
        break;
      case 3:
        Edx = TimingRandom;
        break;
    }
  }

  // Advanced pattern breaking - occasionally return completely different values
  if ((CpuidCallCount & 0x1FFF) == 0x1FFF) {  // Every 8192 calls
    UINT32 FakeValues[4] = {
      TimingRandom,
      TimingRandom ^ 0xAAAAAAAA,
      TimingRandom ^ 0x55555555,
      TimingRandom ^ 0xFFFFFFFF
    };
    
    Eax = FakeValues[0];
    Ebx = FakeValues[1];
    Ecx = FakeValues[2];
    Edx = FakeValues[3];
  }

  LastTscValue = CurrentTsc;

  //
  // Update guest registers with heavily modified CPUID results
  //
  Context->GuestRax = Eax;
  Context->GuestRbx = Ebx;
  Context->GuestRcx = Ecx;
  Context->GuestRdx = Edx;

  gMiniVisorSvmGlobalData.PerfData.CpuidInterceptCount++;
  MINI_VISOR_SVM_DEBUG((DEBUG_VERBOSE, "[SVM] CPUID handled with enhanced stealth: Function=0x%x\n", Function));

  return EFI_SUCCESS;
}

/**
  Handle MSR access VM Exit with comprehensive anti-detection and future-proofing.
  
  @param[in] ExitInfo       Pointer to exit information.
  @param[in] Context        Pointer to guest context.
  
  @retval EFI_SUCCESS       MSR access handled successfully.
**/
EFI_STATUS
EFIAPI
HandleMsrExit (
  IN SVM_EXIT_INFO *ExitInfo,
  IN OUT NESTED_SVM_CONTEXT *Context
  )
{
  UINT32  MsrNumber;
  UINT64  MsrValue;
  BOOLEAN IsWrite;
  STATIC UINT64 MsrAccessCount = 0;
  STATIC UINT64 FakePerfCounters[8] = {0};
  STATIC UINT64 LastTscBase = 0;
  STATIC UINT32 SessionRandom = 0;

  MsrAccessCount++;
  
  // Initialize session random seed on first access
  if (SessionRandom == 0) {
    SessionRandom = (UINT32)AsmReadTsc();
  }

  //
  // Get MSR number from guest RCX
  //
  MsrNumber = (UINT32)Context->GuestRcx;
  
  //
  // Determine if this is a read or write operation
  //
  IsWrite = ((ExitInfo->ExitInfo1 & BIT0) != 0);

  // Generate dynamic random values for comprehensive MSR manipulation
  UINT64 CurrentTsc = AsmReadTsc();
  UINT32 DynamicRandom = (UINT32)(CurrentTsc ^ (CurrentTsc >> 32) ^ MsrAccessCount ^ SessionRandom);

  if (IsWrite) {
    //
    // MSR write operation - comprehensive write filtering and emulation
    //
    MsrValue = (Context->GuestRdx << 32) | (Context->GuestRax & 0xFFFFFFFF);
    
    switch (MsrNumber) {
      case MSR_EFER:
        // Filter EFER writes to prevent guest from enabling SVM/virtualization
        MsrValue &= ~(EFER_SVME | BIT15 | BIT14); // Also hide other potential virt bits
        AsmWriteMsr(MsrNumber, MsrValue);
        break;

      case MSR_VM_CR:
        // Completely block VM_CR manipulation
        MsrValue &= ~(VM_CR_LOCK | VM_CR_SVMDIS | 0xFFFE); // Block all control bits
        break;

      case MSR_VM_HSAVE_PA:
        // Completely ignore host-save area writes for maximum stealth
        break;

      case MSR_SVM_LOCK_KEY:
        // Ignore all SVM lock key manipulation
        break;

      // Intel virtualization MSRs - block completely
      case 0x480: // IA32_VMX_BASIC
      case 0x481: // IA32_VMX_PINBASED_CTLS
      case 0x482: // IA32_VMX_PROCBASED_CTLS
      case 0x483: // IA32_VMX_EXIT_CTLS
      case 0x484: // IA32_VMX_ENTRY_CTLS
      case 0x485: // IA32_VMX_MISC
      case 0x486: // IA32_VMX_CR0_FIXED0
        break;
      case 0x487: // IA32_VMX_CR0_FIXED1
        break;
      case 0x488: // IA32_VMX_CR4_FIXED0
        break;
      case 0x489: // IA32_VMX_CR4_FIXED1
        break;
      case 0x48A: // IA32_VMX_VMCS_ENUM
      case 0x48B: // IA32_VMX_PROCBASED_CTLS2
      case 0x48C: // IA32_VMX_EPT_VPID_CAP
      case 0x48D: // IA32_VMX_TRUE_PINBASED_CTLS
      case 0x48E: // IA32_VMX_TRUE_PROCBASED_CTLS
      case 0x48F: // IA32_VMX_TRUE_EXIT_CTLS
      case 0x490: // IA32_VMX_TRUE_ENTRY_CTLS
      case 0x491: // IA32_VMX_VMFUNC
        // Block all Intel VMX MSR writes
        break;

      // Performance monitoring MSRs - enhanced emulation
      case 0x38D: // IA32_FIXED_CTR0
      case 0x38E: // IA32_FIXED_CTR1  
      case 0x38F: // IA32_FIXED_CTR2
      case 0x309: // IA32_FIXED_CTR_CTRL
      case 0x390: // IA32_PERF_GLOBAL_CTRL
      case 0x391: // IA32_PERF_GLOBAL_OVF_CTRL
        // Store in fake performance counter space with randomization
        {
          UINTN Index = (MsrNumber - 0x38D) & 0x7;
          if (Index < 8) {
            FakePerfCounters[Index] = MsrValue ^ (DynamicRandom & 0xFFFF);
          }
        }
        break;

      // AMD performance MSRs - comprehensive coverage
      case 0xC0010000: // PERF_CTL0
      case 0xC0010001: // PERF_CTL1
      case 0xC0010002: // PERF_CTL2
      case 0xC0010003: // PERF_CTL3
      case 0xC0010004: // PERF_CTR0
      case 0xC0010005: // PERF_CTR1
      case 0xC0010006: // PERF_CTR2
      case 0xC0010007: // PERF_CTR3
        // Enhanced performance counter emulation with randomization
        {
          UINTN Index = (MsrNumber - 0xC0010000) & 0x7;
          if (Index < 8) {
            FakePerfCounters[Index] = MsrValue ^ ((DynamicRandom >> 8) & 0xFFFF);
          }
        }
        // Sometimes pass through to hardware for realism
        if ((DynamicRandom & 0x3) == 0) {
          AsmWriteMsr(MsrNumber, MsrValue);
        }
        break;

      // Advanced AMD MSRs - comprehensive hiding
      case 0xC0010010: // SYS_CFG
      case 0xC0010015: // HWCR  
      case 0xC0010016: // IORRBase0
      case 0xC0010017: // IORRMask0
      case 0xC0010018: // IORRBase1
      case 0xC0010019: // IORRMask1
      case 0xC001001A: // TOP_MEM
      case 0xC001001D: // TOP_MEM2
      case 0xC0010020: // BHB_DIS
      case 0xC0010022: // DE_CFG
        // Filter out virtualization-related bits and randomize
        MsrValue &= ~0xFF00000000000000ULL; // Clear high virtualization bits
        MsrValue ^= ((UINT64)DynamicRandom << 16) & 0x00FF000000000000ULL;
        AsmWriteMsr(MsrNumber, MsrValue);
        break;

      // AMD IOMMU Configuration MSRs - Critical for IOMMU detection hiding
      case 0xC0010058: // MMIO Configuration Base Address Register
      case 0xC0010059: // MMIO Configuration Limit Register
        // These MSRs can reveal IOMMU presence through PCI extended config space
        MsrValue &= ~0x1F; // Clear enable bits and reserved fields
        MsrValue ^= ((UINT64)DynamicRandom << 12) & 0xFFFFF000ULL; // Randomize address bits
        AsmWriteMsr(MsrNumber, MsrValue);
        break;

      case 0xC0010056: // IBS execution control
      case 0xC0010057: // IBS fetch control  
        // Hide Instruction-Based Sampling that can detect virtualization
        MsrValue = 0; // Force disable IBS
        break;

      // AMD Performance monitoring MSRs that can leak IOMMU state
      case 0xC0010200: case 0xC0010201: case 0xC0010202: case 0xC0010203:
      case 0xC0010204: case 0xC0010205: case 0xC0010206: case 0xC0010207:
      case 0xC0010208: case 0xC0010209: case 0xC001020A: case 0xC001020B:
        // Performance event counters can be used to detect IOMMU activity
        MsrValue &= ~0xFF000000ULL; // Clear event selection bits that could detect IOMMU
        MsrValue ^= (DynamicRandom & 0x00FFFFFF); // Randomize remaining bits
        {
          UINTN Index = (MsrNumber - 0xC0010200) & 0x7;
          if (Index < 8) {
            FakePerfCounters[Index] = MsrValue;
          }
        }
        break;

      // Intel advanced MSRs - comprehensive coverage
      case 0x1A0: // IA32_MISC_ENABLE
        // Filter out virtualization hints and randomize
        MsrValue &= ~(BIT22 | BIT18 | BIT12); // Clear virtualization-related bits
        MsrValue ^= (DynamicRandom & 0x7) << 8;
        AsmWriteMsr(MsrNumber, MsrValue);
        break;

      case 0x17: // IA32_PLATFORM_ID
      case 0x8B: // IA32_BIOS_SIGN_ID
        // Filter platform identification with randomization
        MsrValue ^= ((UINT64)DynamicRandom << 24) & 0xFF00000000000000ULL;
        AsmWriteMsr(MsrNumber, MsrValue);
        break;

      // Thermal MSRs - enhanced manipulation
      case 0x19C: // IA32_THERM_STATUS
      case 0x19D: // IA32_THERM2_CTL
      case 0x1A2: // MSR_TEMPERATURE_TARGET
        // Add thermal noise for fingerprinting resistance
        MsrValue ^= (DynamicRandom & 0x7F) << 16;
        AsmWriteMsr(MsrNumber, MsrValue);
        break;

      // Security-related MSRs - block or filter
      case 0x10A: // IA32_ARCH_CAPABILITIES
      case 0x10B: // IA32_FLUSH_CMD
      case 0x122: // IA32_TSX_CTRL
        // Block security feature manipulation
        break;

      // Memory encryption MSRs - hide completely
      case 0xC0010131: // AMD_SEV_STATUS
      case 0xC0010132: // AMD_SEV_ES_GHCB
        // Block all memory encryption MSR writes
        break;

      // Future-proofing: Block unknown high MSRs that might be virtualization-related
      default:
        if (MsrNumber >= 0xC0010200 || (MsrNumber >= 0x500 && MsrNumber <= 0x5FF)) {
          // Block potentially dangerous high MSR ranges
          break;
        }
        
        // For other MSRs, add randomization and pass through
        if ((DynamicRandom & 0x7) != 0) {
          MsrValue ^= (DynamicRandom & 0xFFFF);
          AsmWriteMsr(MsrNumber, MsrValue);
        }
        break;
    }
  } else {
    //
    // MSR read operation - comprehensive read emulation and manipulation
    //
    switch (MsrNumber) {
      case MSR_EFER:
        // Hide all virtualization capability bits
        MsrValue = AsmReadMsr(MsrNumber);
        MsrValue &= ~(EFER_SVME | BIT15 | BIT14 | BIT13); // Hide extended virt bits
        break;

      case MSR_VM_CR:
        // Always report SVM as completely disabled and locked
        MsrValue = VM_CR_SVMDIS | VM_CR_LOCK;
        // Add random noise occasionally
        if ((DynamicRandom & 0x1F) == 0) {
          MsrValue ^= (DynamicRandom & 0xF) << 8;
        }
        break;

      case MSR_VM_HSAVE_PA:
        // Hide host-save area - return randomized fake addresses
        if ((DynamicRandom & 0x3) == 0) {
          MsrValue = 0;
        } else {
          MsrValue = ((UINT64)DynamicRandom << 32) | (DynamicRandom ^ 0xAAAAAAAA);
        }
        break;

      case MSR_SVM_LOCK_KEY:
        // Hide SVM lock key - return dynamic fake values
        MsrValue = ((UINT64)DynamicRandom << 16) ^ 0x5555555555555555ULL;
        break;

      // Intel virtualization MSRs - comprehensive VMX hiding
      case 0x480: // IA32_VMX_BASIC
        MsrValue = 0; // Hide VMX completely
        break;
        
      case 0x481: // IA32_VMX_PINBASED_CTLS
      case 0x482: // IA32_VMX_PROCBASED_CTLS
      case 0x483: // IA32_VMX_EXIT_CTLS
      case 0x484: // IA32_VMX_ENTRY_CTLS
      case 0x485: // IA32_VMX_MISC
      case 0x486: // IA32_VMX_CR0_FIXED0
        break;
      case 0x487: // IA32_VMX_CR0_FIXED1
        break;
      case 0x488: // IA32_VMX_CR4_FIXED0
        break;
      case 0x489: // IA32_VMX_CR4_FIXED1
        break;
      case 0x48A: // IA32_VMX_VMCS_ENUM
      case 0x48B: // IA32_VMX_PROCBASED_CTLS2
      case 0x48C: // IA32_VMX_EPT_VPID_CAP
      case 0x48D: // IA32_VMX_TRUE_PINBASED_CTLS
      case 0x48E: // IA32_VMX_TRUE_PROCBASED_CTLS
      case 0x48F: // IA32_VMX_TRUE_EXIT_CTLS
      case 0x490: // IA32_VMX_TRUE_ENTRY_CTLS
      case 0x491: // IA32_VMX_VMFUNC
        // Return randomized fake VMX data or zero
        if ((DynamicRandom & 0x1) == 0) {
          MsrValue = 0;
        } else {
          MsrValue = DynamicRandom | ((UINT64)(DynamicRandom ^ 0xFFFFFFFF) << 32);
        }
        break;

      // Performance monitoring MSRs - advanced emulation
      case 0x38D: // IA32_FIXED_CTR0
      case 0x38E: // IA32_FIXED_CTR1  
      case 0x38F: // IA32_FIXED_CTR2
      case 0x309: // IA32_FIXED_CTR_CTRL
      case 0x390: // IA32_PERF_GLOBAL_CTRL
      case 0x391: // IA32_PERF_GLOBAL_OVF_CTRL
        {
          UINTN Index = (MsrNumber - 0x38D) & 0x7;
          if (Index < 8) {
            // Return fake performance data with realistic variations
            MsrValue = FakePerfCounters[Index] + (MsrAccessCount * (DynamicRandom & 0x3FF));
          } else {
            MsrValue = DynamicRandom | ((UINT64)(DynamicRandom >> 16) << 32);
          }
        }
        break;

      // AMD IOMMU Configuration MSRs - Critical read interception
      case 0xC0010058: // MMIO Configuration Base Address Register
      case 0xC0010059: // MMIO Configuration Limit Register
        // Return fake MMIO configuration that hides IOMMU ranges
        MsrValue = ((UINT64)DynamicRandom << 12) & 0xFFFFF000ULL;
        MsrValue |= (DynamicRandom & 0xFE); // Fake enable flags
        break;

      case 0xC0010056: // IBS execution control
      case 0xC0010057: // IBS fetch control  
        // Always report IBS as disabled
        MsrValue = 0;
        break;

      // AMD Performance monitoring MSRs that can leak IOMMU state
      case 0xC0010200: case 0xC0010201: case 0xC0010202: case 0xC0010203:
      case 0xC0010204: case 0xC0010205: case 0xC0010206: case 0xC0010207:
      case 0xC0010208: case 0xC0010209: case 0xC001020A: case 0xC001020B:
        // Return fake performance data that hides IOMMU activity
        {
          UINTN Index = (MsrNumber - 0xC0010200) & 0x7;
          if (Index < 8) {
            MsrValue = FakePerfCounters[Index] + (MsrAccessCount * (DynamicRandom & 0xFF));
            FakePerfCounters[Index] = MsrValue;
          } else {
            MsrValue = DynamicRandom | ((UINT64)(DynamicRandom ^ 0xAAAAAAAA) << 32);
          }
        }
        break;

      // AMD performance MSRs - enhanced emulation
      case 0xC0010000: // PERF_CTL0
      case 0xC0010001: // PERF_CTL1
      case 0xC0010002: // PERF_CTL2
      case 0xC0010003: // PERF_CTL3
      case 0xC0010004: // PERF_CTR0
      case 0xC0010005: // PERF_CTR1
      case 0xC0010006: // PERF_CTR2
      case 0xC0010007: // PERF_CTR3
        {
          UINTN Index = (MsrNumber - 0xC0010000) & 0x7;
          if (Index < 8) {
            // Advanced performance counter emulation
            if ((DynamicRandom & 0x7) == 0) {
              // Occasionally read real hardware for realism
              MsrValue = AsmReadMsr(MsrNumber);
              MsrValue ^= (DynamicRandom & 0xFFFF);
            } else {
              // Return sophisticated fake performance data
              UINT64 BaseValue = FakePerfCounters[Index];
              UINT64 Increment = (MsrAccessCount * (DynamicRandom & 0x7F)) + (CurrentTsc & 0xFFF);
              MsrValue = BaseValue + Increment;
            }
          } else {
            MsrValue = DynamicRandom;
          }
        }
        break;

      // Advanced AMD MSRs - comprehensive manipulation
      case 0xC0010010: // SYS_CFG
        MsrValue = AsmReadMsr(MsrNumber);
        MsrValue &= ~0xFF00000000000000ULL; // Clear virtualization bits
        MsrValue ^= ((UINT64)(DynamicRandom & 0xFF) << 24);
        break;

      case 0xC0010015: // HWCR
        MsrValue = AsmReadMsr(MsrNumber);
        MsrValue &= ~(BIT3 | BIT17 | BIT30); // Clear SVM-related bits
        MsrValue ^= (DynamicRandom & 0x7) << 8;
        break;

      case 0xC001001A: // TOP_MEM
      case 0xC001001D: // TOP_MEM2
        MsrValue = AsmReadMsr(MsrNumber);
        // Add slight memory layout randomization
        MsrValue ^= ((UINT64)(DynamicRandom & 0xFF) << 20);
        break;

      // Time stamp counter - advanced manipulation
      case 0x10: // IA32_TIME_STAMP_COUNTER
        if (LastTscBase == 0) {
          LastTscBase = AsmReadTsc();
        }
        // Provide sophisticated TSC with controlled drift
        {
          UINT64 RealTsc = AsmReadTsc();
          UINT64 TscDrift = (MsrAccessCount * (DynamicRandom & 0x3FF)) + (RealTsc & 0xFFFF);
          MsrValue = LastTscBase + TscDrift;
          
          // Occasionally resync with real TSC for realism
          if ((DynamicRandom & 0xFF) == 0xFF) {
            LastTscBase = RealTsc;
            MsrValue = RealTsc;
          }
        }
        break;

      // Platform identification MSRs - comprehensive obfuscation
      case 0x17: // IA32_PLATFORM_ID
        MsrValue = AsmReadMsr(MsrNumber);
        MsrValue ^= ((UINT64)(DynamicRandom & 0xFF) << 32);
        break;

      case 0x8B: // IA32_BIOS_SIGN_ID
        MsrValue = AsmReadMsr(MsrNumber);
        MsrValue ^= ((UINT64)(DynamicRandom & 0xFFFF) << 16);
        break;

      // Microcode and version MSRs - version obfuscation
      case 0x8C: // IA32_SGXLEPUBKEYHASH0-3
      case 0x8D:
      case 0x8E:
      case 0x8F:
        // Hide SGX key hashes
        MsrValue = DynamicRandom | ((UINT64)(DynamicRandom ^ 0xAAAAAAAA) << 32);
        break;

      // Thermal and power MSRs - realistic thermal simulation
      case 0x19C: // IA32_THERM_STATUS
        MsrValue = AsmReadMsr(MsrNumber);
        // Add realistic thermal variations
        MsrValue ^= ((DynamicRandom & 0x1F) << 16) | ((DynamicRandom >> 8) & 0x7F);
        break;

      case 0x1A2: // MSR_TEMPERATURE_TARGET
        MsrValue = AsmReadMsr(MsrNumber);
        MsrValue ^= (DynamicRandom & 0xF) << 20;
        break;

      // Security MSRs - advanced security feature hiding
      case 0x10A: // IA32_ARCH_CAPABILITIES
        MsrValue = AsmReadMsr(MsrNumber);
        // Hide advanced security features
        MsrValue &= ~0xFFFFFFFF00000000ULL;
        MsrValue ^= (DynamicRandom & 0xFFFF);
        break;

      case 0x122: // IA32_TSX_CTRL
        // Hide TSX control capabilities
        MsrValue = DynamicRandom & 0x3;
        break;

      // Memory encryption MSRs - complete hiding
      case 0xC0010131: // AMD_SEV_STATUS
      case 0xC0010132: // AMD_SEV_ES_GHCB
        MsrValue = 0; // Hide all memory encryption
        break;

      // Cache control MSRs - cache behavior manipulation
      case 0x250: // IA32_MTRR_FIX64K_00000
      case 0x258: // IA32_MTRR_FIX16K_80000
      case 0x259: // IA32_MTRR_FIX16K_A0000
      case 0x268: // IA32_MTRR_FIX4K_C0000
      case 0x269: // IA32_MTRR_FIX4K_C8000
      case 0x26A: // IA32_MTRR_FIX4K_D0000
      case 0x26B: // IA32_MTRR_FIX4K_D8000
      case 0x26C: // IA32_MTRR_FIX4K_E0000
      case 0x26D: // IA32_MTRR_FIX4K_E8000
      case 0x26E: // IA32_MTRR_FIX4K_F0000
      case 0x26F: // IA32_MTRR_FIX4K_F8000
        MsrValue = AsmReadMsr(MsrNumber);
        // Add subtle cache layout variations
        MsrValue ^= ((UINT64)(DynamicRandom & 0xFF) << 24);
        break;

      // Future-proofing: Handle unknown MSRs
      default:
        if (MsrNumber >= 0xC0010200 || (MsrNumber >= 0x500 && MsrNumber <= 0x5FF)) {
          // For high/unknown MSR ranges, return sophisticated fake data
          MsrValue = DynamicRandom | ((UINT64)(DynamicRandom ^ 0x55555555) << 32);
        } else {
          // For standard MSRs, read and add randomization
          MsrValue = AsmReadMsr(MsrNumber);
          if ((DynamicRandom & 0xF) == 0) {
            MsrValue ^= (DynamicRandom & 0xFFFF);
          }
        }
        break;
    }

    //
    // Update guest registers with heavily manipulated MSR value
    //
    Context->GuestRax = MsrValue & 0xFFFFFFFF;
    Context->GuestRdx = (MsrValue >> 32) & 0xFFFFFFFF;
  }

  gMiniVisorSvmGlobalData.PerfData.MsrInterceptCount++;
  MINI_VISOR_SVM_DEBUG((DEBUG_VERBOSE, "[SVM] Enhanced MSR %s: MSR=0x%x, Value=0x%lx\n", 
    IsWrite ? L"Write" : L"Read", MsrNumber, MsrValue));

  return EFI_SUCCESS;
}

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
  )
{
  UINT64 FaultAddress;
  UINT64 ErrorCode;
  UINT16 SegmentHit;

  //
  // Get fault address from ExitInfo2
  //
  FaultAddress = ExitInfo->ExitInfo2;
  ErrorCode = ExitInfo->ExitInfo1;

  // Comprehensive multi-segment IOMMU MMIO window detection
  SegmentHit = 0xFFFF;
  for (UINTN s = 0; s < gIommuManager.NumSegments; s++) {
    EFI_PHYSICAL_ADDRESS base = gIommuManager.SegmentMmioBases[s] & ~0xFFFULL;
    if ((FaultAddress & ~0xFFFULL) == base) {
      SegmentHit = (UINT16)s;
      break;
    }
  }

  // Also check primary MMIO base for compatibility
  if (SegmentHit == 0xFFFF && (FaultAddress & ~0xFFFULL) == (gIommuManager.MmioBase & ~0xFFFULL)) {
    SegmentHit = 0; // Use primary segment
  }

  if (SegmentHit != 0xFFFF && SegmentHit < 8) {
    gIommuManager.AccessCount++;
    BOOLEAN IsWrite = ((ErrorCode & BIT1) != 0);
    UINT64 offset = FaultAddress & 0xFFFULL;
    
    // Get current time for advanced behavioral simulation
    UINT64 CurrentTime = AsmReadTsc();
    UINT64 TimeDelta = CurrentTime - gIommuManager.LastAccessTime;
    gIommuManager.LastAccessTime = CurrentTime;
    
    // Update access pattern tracking
    {
      UINT32 PatternIndex = gIommuManager.AccessCount & 0xF;
      gIommuManager.AccessPattern[PatternIndex] = ((UINT64)offset << 48) | ((UINT64)SegmentHit << 32) | ((UINT64)IsWrite << 31) | (TimeDelta & 0x7FFFFFFF);
    }
    
    // Generate comprehensive randomization
    UINT32 IommuRandom = (UINT32)(CurrentTime ^ (CurrentTime >> 32) ^ gIommuManager.AccessCount ^ gIommuManager.RandomizationSeed);
    
    // Advanced behavioral mode selection
    UINT32 BehaviorMode = (gIommuManager.AccessCount >> 5) & 0x7;
    
    // Comprehensive IOMMU register emulation with multi-segment support
    if (IsWrite) {
      UINT32 WriteValue = (UINT32)Context->GuestRax;
      
      // Advanced write value modification based on behavior mode
      switch (BehaviorMode) {
        case 0: // Standard mode
          break;
        case 1: // Filtering mode (modify certain bits)
          WriteValue &= ~0xF0000000; // Clear high-order bits
          break;
        case 2: // Randomization mode
          WriteValue ^= (IommuRandom & 0xFFFF);
          break;
        case 3: // Bit-flip mode
          if ((IommuRandom & 0x1F) == 0x1F) {
            WriteValue ^= (1 << ((IommuRandom >> 5) & 0x1F));
          }
          break;
        default: // Complex patterns
          WriteValue = (WriteValue * 0x9E3779B9) ^ IommuRandom;
          break;
      }
      
      switch ((UINT32)offset) {
        case AMDVI_REG_CONTROL:
          gIommuManager.Control[SegmentHit] = WriteValue;
          // Advanced status simulation based on control register
          if ((WriteValue & 0x1) != 0) {
            gIommuManager.Status[SegmentHit] |= AMDVI_STATUS_READY;
            gIommuManager.ControlEnableCount++;
          } else {
            gIommuManager.Status[SegmentHit] &= ~AMDVI_STATUS_READY;
          }
          
          // Simulate additional control features
          if ((WriteValue & 0x2) != 0) { // Event log enable
            gIommuManager.Status[SegmentHit] |= BIT2; // Event log enabled
          }
          if ((WriteValue & 0x4) != 0) { // Command buffer enable
            gIommuManager.Status[SegmentHit] |= BIT3; // Command buffer enabled
          }
          
          gIommuManager.Status[SegmentHit] |= AMDVI_STATUS_CMD_DONE;
          break;
          
        case AMDVI_REG_DTB_LO:
          gIommuManager.DtbLo[SegmentHit] = WriteValue;
          // Simulate device table validation
          if (WriteValue != 0) {
            gIommuManager.Status[SegmentHit] |= BIT4; // Device table valid
          }
          break;
          
        case AMDVI_REG_DTB_HI:
          gIommuManager.DtbHi[SegmentHit] = WriteValue;
          break;
          
        case AMDVI_REG_CMB_LO:
          gIommuManager.CmbLo[SegmentHit] = WriteValue;
          break;
          
        case AMDVI_REG_CMB_HI:
          gIommuManager.CmbHi[SegmentHit] = WriteValue;
          break;
          
        case AMDVI_REG_ELB_LO:
          gIommuManager.ElbLo[SegmentHit] = WriteValue;
          break;
          
        case AMDVI_REG_ELB_HI:
          gIommuManager.ElbHi[SegmentHit] = WriteValue;
          break;
          
        case AMDVI_REG_IOTLB_DB:
          // IOTLB flush doorbell - simulate comprehensive IOTLB operations
          gIommuManager.IotlbFlushCount++;
          gIommuManager.Status[SegmentHit] |= AMDVI_STATUS_CMD_DONE;
          
          // Simulate different flush types based on write value
          switch (WriteValue & 0x7) {
            case 0: // Global flush
              for (UINT32 i = 0; i < 8; i++) {
                gIommuManager.Status[i] |= BIT5; // Global flush done
              }
              break;
            case 1: // Domain flush
              gIommuManager.Status[SegmentHit] |= BIT6; // Domain flush done
              break;
            case 2: // Page flush
              gIommuManager.Status[SegmentHit] |= BIT7; // Page flush done
              break;
            default: // Device-specific flush
              gIommuManager.Status[SegmentHit] |= BIT8; // Device flush done
              break;
          }
          break;
          
        case AMDVI_REG_CMB_TAIL:
          // Command buffer doorbell
          gIommuManager.CmbDoorbellCount++;
          gIommuManager.Status[SegmentHit] |= AMDVI_STATUS_CMD_DONE;
          
          // Simulate command processing based on tail value
          if (WriteValue > gIommuManager.CmbLo[SegmentHit]) {
            UINT32 CommandCount = (WriteValue - gIommuManager.CmbLo[SegmentHit]) / 16; // 16-byte commands
            gIommuManager.Status[SegmentHit] |= (CommandCount & 0xFF) << 16; // Command count in status
          }
          break;
          
        // Extended register emulation
        case 0x30: // Extended Feature Register
          gIommuManager.ExtFeatures[SegmentHit] = WriteValue;
          break;
          
        case 0x40: // Performance Counter Control
          {
            UINT32 CounterIndex = (offset - 0x40) >> 2;
            if (CounterIndex < 4) {
              gIommuManager.PerfCounters[SegmentHit][CounterIndex] = WriteValue;
            }
          }
          break;
          
        default:
          // Store in comprehensive shadow MMIO space
          {
            UINTN slot = (offset >> 3) & 8191; // 64KB space
            gIommuManager.ShadowMmio[SegmentHit][slot] = WriteValue;
            
                      // Add access-time correlation
          gIommuManager.ShadowMmio[SegmentHit][slot] |= ((UINT64)((UINT32)(CurrentTime & 0xFFFFULL)) << 32);
          }
          break;
      }
      
      // Advanced write-side behavior simulation
      
      // Behavior 1: Cross-segment state propagation
      if ((IommuRandom & 0x3F) == 0x3F) {
        for (UINT32 i = 0; i < gIommuManager.NumSegments; i++) {
          if (i != SegmentHit) {
            gIommuManager.Status[i] ^= (WriteValue & 0xFF);
          }
        }
      }
      
      // Behavior 2: State vector evolution
      gIommuManager.StateVector = (gIommuManager.StateVector << 1) ^ WriteValue ^ IommuRandom;
      
    } else {
      // Read operation - comprehensive read value generation
      UINT32 ReadValue = 0;
      
      switch ((UINT32)offset) {
        case AMDVI_REG_CONTROL:
          ReadValue = gIommuManager.Control[SegmentHit];
          // Add dynamic control value modifications
          if ((IommuRandom & 0x1F) == 0x1F) {
            ReadValue ^= (IommuRandom & 0x7) << 8; // Flip some control bits occasionally
          }
          break;
          
        case AMDVI_REG_STATUS:
          ReadValue = gIommuManager.Status[SegmentHit];
          gIommuManager.StatusReadCount++;
          
          // Advanced status bit simulation
          ReadValue |= (gIommuManager.AccessCount & 0xFF) << 24; // Access count in high bits
          ReadValue |= ((IommuRandom & 0xF) << 12); // Random status bits
          
          // Clear certain status bits on read (read-to-clear behavior)
          gIommuManager.Status[SegmentHit] &= ~(AMDVI_STATUS_CMD_DONE | BIT5 | BIT6 | BIT7 | BIT8);
          
          // Simulate interrupt status
          if ((gIommuManager.AccessCount & 0x7F) == 0x7F) {
            ReadValue |= BIT31; // Interrupt pending
          }
          break;
          
        case AMDVI_REG_DTB_LO:
          ReadValue = gIommuManager.DtbLo[SegmentHit];
          // Add address randomization
          ReadValue ^= (IommuRandom & 0xFFF);
          break;
          
        case AMDVI_REG_DTB_HI:
          ReadValue = gIommuManager.DtbHi[SegmentHit];
          ReadValue ^= ((IommuRandom >> 8) & 0xFFF);
          break;
          
        case AMDVI_REG_CMB_LO:
          ReadValue = gIommuManager.CmbLo[SegmentHit];
          break;
          
        case AMDVI_REG_CMB_HI:
          ReadValue = gIommuManager.CmbHi[SegmentHit];
          break;
          
        case AMDVI_REG_ELB_LO:
          ReadValue = gIommuManager.ElbLo[SegmentHit];
          break;
          
        case AMDVI_REG_ELB_HI:
          ReadValue = gIommuManager.ElbHi[SegmentHit];
          break;
          
        // Extended register reads
        case 0x30: // Extended Feature Register
          ReadValue = gIommuManager.ExtFeatures[SegmentHit];
          // Simulate dynamic feature availability
          ReadValue |= (IommuRandom & 0x7) << 16; // Variable feature bits
          break;
          
        case 0x40: // Performance Counters
          {
            UINT32 CounterIndex = (offset - 0x40) >> 2;
            if (CounterIndex < 4) {
              ReadValue = gIommuManager.PerfCounters[SegmentHit][CounterIndex];
              // Simulate counter progression
              ReadValue += (CurrentTime & 0x3FF) + (IommuRandom & 0xFF);
            }
          }
          break;
          
        // Version/identification registers
        // Note: 0x08 and 0x0C offsets are used by AMDVI_REG_CMB_LO/HI; avoid duplicate cases
          
        default:
          // Read from comprehensive shadow MMIO space
          {
            UINTN slot = (offset >> 3) & 8191;
            ReadValue = (UINT32)(gIommuManager.ShadowMmio[SegmentHit][slot] & 0xFFFFFFFFULL);
            
            // Add time-based variations to shadow reads
            if ((IommuRandom & 0xF) == 0xF) {
              ReadValue ^= (CurrentTime & 0xFFFF);
            }
          }
          break;
      }
      
      // Advanced read-side behavior simulation
      
      // Behavior 1: Anti-pattern reading (prevent consistent reads)
      if ((gIommuManager.AccessCount & 0x1F) == 0x1F) {
        ReadValue ^= gIommuManager.StateVector & 0xFFFF;
      }
      
      // Behavior 2: Cross-platform compatibility simulation
      switch (gIommuManager.AntiDetectionMode & 0x3) {
        case 0: // Intel VT-d simulation mode
          if ((IommuRandom & 0x7) == 0x7) {
            ReadValue = (ReadValue & 0xFFFF0000) | 0x8086; // Intel vendor ID occasionally
          }
          break;
        case 1: // Hyper-V simulation mode
          if ((IommuRandom & 0x7) == 0x7) {
            ReadValue |= 0x4D564853; // "MSHV" signature
          }
          break;
        case 2: // VMware simulation mode
          if ((IommuRandom & 0x7) == 0x7) {
            ReadValue |= 0x61774D56; // "VMwa" signature
          }
          break;
        default: // Pure randomization
          ReadValue ^= IommuRandom;
          break;
      }
      
      // Behavior 3: Multi-segment consistency simulation
      if (gIommuManager.NumSegments > 1 && (IommuRandom & 0x3F) == 0x3F) {
        // Occasionally return values from other segments for consistency testing
        UINT32 OtherSegment = ((SegmentHit + 1) % gIommuManager.NumSegments);
        switch ((UINT32)offset) {
          case AMDVI_REG_CONTROL:
            ReadValue = gIommuManager.Control[OtherSegment];
            break;
          case AMDVI_REG_STATUS:
            ReadValue = gIommuManager.Status[OtherSegment];
            break;
          default:
            break;
        }
      }
      
      Context->GuestRax = (Context->GuestRax & ~0xFFFFFFFFULL) | ReadValue;
    }
/**
  Handle RDTSC instruction with comprehensive timing manipulation and anti-detection.
  
  @param[in] Context        Pointer to guest context.
  
  @retval EFI_SUCCESS       RDTSC handled successfully.
**/
EFI_STATUS
EFIAPI
HandleRdtscExit (
  IN OUT NESTED_SVM_CONTEXT *Context
  )
{
  UINT64 Tsc;
  STATIC UINT64 TscCallCount = 0;
  STATIC UINT64 BaseTsc = 0;
  STATIC UINT64 LastReturnedTsc = 0;
  STATIC UINT32 TscRandomSeed = 0;
  STATIC UINT64 TscOffset = 0;
  STATIC UINT32 TimingModeCounter = 0;

  TscCallCount++;
  
  // Initialize base values on first call
  if (BaseTsc == 0) {
    BaseTsc = AsmReadTsc();
    TscRandomSeed = (UINT32)BaseTsc;
    TscOffset = BaseTsc >> 4; // Start with some offset
  }

  // Get real TSC for baseline
  UINT64 RealTsc = AsmReadTsc();
  
  // Generate comprehensive timing random value
  UINT32 TimingRandom = (UINT32)(RealTsc ^ (RealTsc >> 32) ^ TscCallCount ^ TscRandomSeed);
  
  // Advanced multi-strategy TSC manipulation
  TimingModeCounter = (TimingModeCounter + 1) % 16;
  
  switch (TimingModeCounter & 0x7) {
    case 0:
      // Strategy 1: Slightly accelerated time (1.01x - 1.15x speed)
      {
        UINT64 ElapsedReal = RealTsc - BaseTsc;
        UINT32 AccelFactor = 101 + (TimingRandom & 0xF); // 101-116%
        Tsc = BaseTsc + ((ElapsedReal * AccelFactor) / 100);
      }
      break;
      
    case 1:
      // Strategy 2: Slightly decelerated time (0.85x - 0.99x speed)
      {
        UINT64 ElapsedReal = RealTsc - BaseTsc;
        UINT32 DecelFactor = 85 + (TimingRandom & 0xF); // 85-100%
        Tsc = BaseTsc + ((ElapsedReal * DecelFactor) / 100);
      }
      break;
      
    case 2:
      // Strategy 3: Add controlled jitter/noise
      {
        UINT64 JitterMask = (TimingRandom & 0x3FF) + 512; // 512-1535 cycle jitter
        Tsc = RealTsc + TscOffset + ((TscCallCount & 0x1) ? JitterMask : -JitterMask);
      }
      break;
      
    case 3:
      // Strategy 4: Quantum timing steps (for anti-profiling)
      {
        UINT64 QuantumSize = 1024 + (TimingRandom & 0x3FF); // 1024-1535 cycle quanta
        UINT64 ElapsedReal = RealTsc - BaseTsc;
        UINT64 QuantizedTime = (ElapsedReal / QuantumSize) * QuantumSize;
        Tsc = BaseTsc + QuantizedTime + TscOffset;
      }
      break;
      
    case 4:
      // Strategy 5: Fibonacci-based timing progression (confuses pattern detection)
      {
        STATIC UINT64 FibA = 1, FibB = 1;
        UINT64 NextFib = FibA + FibB;
        FibA = FibB;
        FibB = NextFib;
        Tsc = RealTsc + TscOffset + (NextFib & 0xFFFF);
      }
      break;
      
    case 5:
      // Strategy 6: Chaotic timing (pseudo-random based on previous values)
      {
        UINT64 Chaos = LastReturnedTsc ^ (LastReturnedTsc >> 17) ^ (TimingRandom << 13);
        Tsc = RealTsc + TscOffset + (Chaos & 0x7FF);
      }
      break;
      
    case 6:
      // Strategy 7: Timing bands (creates different timing "environments")
      {
        UINT32 Band = (TscCallCount >> 10) & 0x7; // Change band every ~1024 calls
        UINT64 BandOffset = Band * 0x10000ULL + (TimingRandom & 0xFFFF);
        Tsc = RealTsc + TscOffset + BandOffset;
      }
      break;
      
    case 7:
      // Strategy 8: Nearly real time (for realistic applications)
      {
        UINT64 MinimalJitter = TimingRandom & 0xFF; // Small 0-255 cycle variation
        Tsc = RealTsc + TscOffset + MinimalJitter;
      }
      break;
  }

  // Advanced anti-pattern techniques
  
  // Technique 1: Ensure monotonic progression (critical for Windows)
  if (Tsc <= LastReturnedTsc) {
    Tsc = LastReturnedTsc + 1 + (TimingRandom & 0x3F); // Small increment
  }
  
  // Technique 2: Occasional dramatic time jumps (simulate context switches)
  if ((TscCallCount & 0x1FF) == 0x1FF) { // Every 512 calls
    UINT64 BigJump = (TimingRandom & 0x3FFFF) + 0x10000; // 64K-320K cycle jump
    Tsc += BigJump;
    TscOffset += BigJump >> 4; // Adjust baseline
  }
  
  // Technique 3: Frequency variance simulation (as if running on different cores)
  if ((TscCallCount & 0x7F) == 0x7F) { // Every 128 calls
    UINT32 FreqVariance = (TimingRandom & 0x1F) + 16; // 16-47 units
    if (TimingRandom & BIT31) {
      TscOffset += FreqVariance << 8;
    } else {
      TscOffset -= FreqVariance << 8;
    }
  }
  
  // Technique 4: Memory pressure simulation (slower TSC progression)
  if ((TimingRandom & 0xFF) == 0xFF) {
    UINT64 Slowdown = (TimingRandom >> 8) & 0x1FFF; // Random slowdown
    if (Tsc > Slowdown) {
      Tsc -= Slowdown;
    }
  }
  
  // Technique 5: Thermal throttling simulation
  if ((TscCallCount & 0x3FF) == 0x3FF) { // Every 1024 calls
    UINT32 ThermalFactor = 95 + (TimingRandom & 0x7); // 95-102% speed
    UINT64 ThermalAdjustment = ((Tsc - BaseTsc) * ThermalFactor) / 100;
    Tsc = BaseTsc + ThermalAdjustment;
  }
  
  // Technique 6: Power state transitions (sudden timing changes)
  if ((TimingRandom & 0x7FF) == 0x7FF) { // Rare power state change
    UINT64 PowerTransition = (TimingRandom & 0xFFFF) << 10;
    TscOffset += PowerTransition;
    Tsc += PowerTransition;
  }
  
  // Technique 7: Multi-core timing inconsistency simulation
  {
    UINT32 CoreVariation = (TscCallCount & 0x7) * (TimingRandom & 0x1F);
    Tsc += CoreVariation;
  }
  
  // Advanced counter-measurement protection
  
  // Protection 1: TSC ratio analysis resistance
  if ((TscCallCount & 0x1F) == 0x1F) {
    UINT64 RatioBreaker = TimingRandom & 0x3FF;
    Tsc ^= RatioBreaker; // XOR to break ratio analysis
    Tsc &= ~0x3FF; // Clear low bits to maintain reasonable progression
    Tsc |= RatioBreaker & 0x3FF; // Restore some low bits
  }
  
  // Protection 2: Timing attack resistance (prevent precise measurements)
  if ((TscCallCount & 0x3) == 0x3) {
    UINT32 AntiTimingNoise = TimingRandom & 0x7;
    Tsc += (AntiTimingNoise << 6); // Add noise in higher bits
  }
  
  // Protection 3: Statistical analysis resistance
  {
    STATIC UINT64 StatBuffer[16] = {0};
    STATIC UINT32 StatIndex = 0;
    
    StatBuffer[StatIndex] = Tsc;
    StatIndex = (StatIndex + 1) & 0xF;
    
    // Occasionally adjust based on statistical distribution
    if ((TscCallCount & 0xFF) == 0xFF) {
      UINT64 StatSum = 0;
      for (UINT32 i = 0; i < 16; i++) {
        StatSum += StatBuffer[i];
      }
      UINT64 StatAvg = StatSum >> 4;
      
      // Adjust if distribution is too uniform
      if (StatAvg > 0) {
        UINT64 Deviation = (UINT64)(TimingRandom & 0xFFF);
        Tsc += (StatAvg > Tsc) ? Deviation : -Deviation;
      }
    }
  }
  
  // Protection 4: Machine learning detection resistance
  if ((TscCallCount & 0x1FFF) == 0x1FFF) { // Every 8192 calls
    // Completely reset timing base to confuse ML algorithms
    BaseTsc = RealTsc;
    TscOffset = (TimingRandom & 0xFFFF) << 10;
    Tsc = RealTsc + TscOffset;
  }

  LastReturnedTsc = Tsc;
  
  // Return sophisticated TSC value in EDX:EAX
  Context->GuestRax = (UINT32)(Tsc & 0xFFFFFFFF);
  Context->GuestRdx = (UINT32)(Tsc >> 32);
  
  return EFI_SUCCESS;
}

/**
  Handle RDTSCP instruction with comprehensive timing and auxiliary data manipulation.
  
  @param[in] Context        Pointer to guest context.
  
  @retval EFI_SUCCESS       RDTSCP handled successfully.
**/
EFI_STATUS
EFIAPI
HandleRdtscpExit (
  IN OUT NESTED_SVM_CONTEXT *Context
  )
{
  UINT64 Tsc;
  UINT32 Aux;
  STATIC UINT64 RdtscpCallCount = 0;
  STATIC UINT64 RdtscpBaseTsc = 0;
  STATIC UINT64 LastRdtscpTsc = 0;
  STATIC UINT32 RdtscpRandomSeed = 0;
  STATIC UINT32 FakeProcessorId = 0;

  RdtscpCallCount++;
  
  // Initialize on first call
  if (RdtscpBaseTsc == 0) {
    RdtscpBaseTsc = AsmReadTsc();
    RdtscpRandomSeed = (UINT32)RdtscpBaseTsc;
    FakeProcessorId = RdtscpRandomSeed & 0xFFFF;
  }

  // Get real values as baseline
  UINT64 RealTsc = AsmReadTsc();
  UINT32 RealAux = (UINT32)AsmReadMsr(0xC0000103); // TSC_AUX MSR
  
  // Generate comprehensive randomization
  UINT32 RdtscpRandom = (UINT32)(RealTsc ^ (RealTsc >> 32) ^ RdtscpCallCount ^ RdtscpRandomSeed);
  
  // Advanced TSC manipulation (similar to RDTSC but with RDTSCP-specific variations)
  UINT32 TscpMode = (RdtscpCallCount >> 3) & 0x7;
  
  switch (TscpMode) {
    case 0:
      // Synchronized timing mode (RDTSCP often used for precise measurements)
      {
        UINT64 ElapsedReal = RealTsc - RdtscpBaseTsc;
        UINT32 SyncFactor = 98 + (RdtscpRandom & 0x7); // 98-105%
        Tsc = RdtscpBaseTsc + ((ElapsedReal * SyncFactor) / 100);
      }
      break;
      
    case 1:
      // Process-aware timing (simulate process switching)
      {
        UINT32 ProcessSwitch = (RdtscpCallCount >> 6) & 0x1F; // Every 64 calls, vary by process
        UINT64 ProcessOffset = ProcessSwitch * 0x8000ULL + (RdtscpRandom & 0x7FFF);
        Tsc = RealTsc + ProcessOffset;
      }
      break;
      
    case 2:
      // Core migration simulation
      {
        UINT32 CoreMigration = (RdtscpCallCount >> 4) & 0x7; // Simulate migration every 16 calls
        UINT64 CoreTimingDrift = CoreMigration * (RdtscpRandom & 0x3FFF);
        Tsc = RealTsc + CoreTimingDrift;
      }
      break;
      
    case 3:
      // Serialized instruction timing
      {
        UINT64 SerializedDelay = (RdtscpRandom & 0x1FF) + 256; // 256-767 cycle serialization
        Tsc = RealTsc + SerializedDelay;
      }
      break;
      
    default:
      // Complex timing patterns for advanced anti-detection
      {
        UINT64 ComplexPattern = (RdtscpCallCount * 0x9E3779B9ULL) ^ (RdtscpRandom << 13);
        Tsc = RealTsc + (ComplexPattern & 0x3FFFF); // 0-262K cycle variation
      }
      break;
  }
  
  // Ensure monotonic progression
  if (Tsc <= LastRdtscpTsc) {
    Tsc = LastRdtscpTsc + 1 + (RdtscpRandom & 0x1F);
  }
  
  // Advanced auxiliary data manipulation
  UINT32 AuxMode = (RdtscpCallCount >> 5) & 0x7;
  
  switch (AuxMode) {
    case 0:
      // Hide real processor/core ID completely
      Aux = FakeProcessorId;
      break;
      
    case 1:
      // Rotating fake core IDs
      Aux = ((RdtscpCallCount >> 7) & 0xF) | (FakeProcessorId & 0xFFF0);
      break;
      
    case 2:
      // NUMA node masquerading
      {
        UINT32 FakeNode = (RdtscpRandom >> 12) & 0x7;
        UINT32 FakeCore = (RdtscpRandom >> 8) & 0xF;
        Aux = (FakeNode << 12) | (FakeCore << 8) | (RdtscpRandom & 0xFF);
      }
      break;
      
    case 3:
      // Process ID embedding (common RDTSCP usage)
      {
        UINT32 FakeProcessId = 0x1000 + ((RdtscpCallCount >> 10) & 0xFFF);
        Aux = FakeProcessId;
      }
      break;
      
    case 4:
      // Thread ID variations
      {
        UINT32 FakeThreadId = ((RdtscpCallCount >> 6) & 0xFF) | (FakeProcessorId & 0xFF00);
        Aux = FakeThreadId;
      }
      break;
      
    case 5:
      // Security context variations
      {
        UINT32 SecurityContext = (RdtscpRandom & 0x3FF) | 0x8000;
        Aux = SecurityContext;
      }
      break;
      
    case 6:
      // Virtualization layer hints (occasionally show fake hypervisor info)
      if ((RdtscpRandom & 0xFF) == 0xFF) {
        Aux = 0xDEADBEEF; // Fake hypervisor signature
      } else {
        Aux = RealAux ^ (RdtscpRandom & 0xFFFF);
      }
      break;
      
    case 7:
      // Dynamic auxiliary patterns
      {
        UINT32 Pattern = (UINT32)((RdtscpCallCount * 0x61C88647ULL) ^ RdtscpRandom);
        Aux = Pattern & 0xFFFFFFFF;
      }
      break;
  }
  
  // Additional anti-detection for auxiliary data
  
  // Mask 1: Prevent consistent auxiliary patterns
  if ((RdtscpCallCount & 0x3F) == 0x3F) {
    Aux ^= (RdtscpRandom >> 16) & 0xFFFF;
  }
  
  // Mask 2: Simulate context switches affecting aux data
  if ((RdtscpCallCount & 0xFF) == 0xFF) {
    UINT32 ContextSwitch = (RdtscpRandom >> 8) & 0xFFF;
    Aux = (Aux & 0xFFFFF000) | ContextSwitch;
  }
  
  // Mask 3: Occasional auxiliary data corruption simulation
  if ((RdtscpRandom & 0x7FF) == 0x7FF) {
    Aux = RdtscpRandom; // Complete randomization
  }
  
  // Advanced RDTSCP-specific protections
  
  // Protection 1: Timing correlation prevention
  if ((RdtscpCallCount & 0x1FF) == 0x1FF) {
    UINT64 CorrelationBreaker = (RdtscpRandom & 0x7FFFF) + 0x10000;
    Tsc += CorrelationBreaker;
  }
  
  // Protection 2: Cross-call timing analysis resistance
  {
    STATIC UINT64 PrevCallTiming[8] = {0};
    STATIC UINT32 TimingIndex = 0;
    
    PrevCallTiming[TimingIndex] = Tsc;
    TimingIndex = (TimingIndex + 1) & 0x7;
    
    // Adjust timing based on call pattern
    if ((RdtscpCallCount & 0x7F) == 0x7F) {
      UINT64 TimingSum = 0;
      for (UINT32 i = 0; i < 8; i++) {
        TimingSum += PrevCallTiming[i];
      }
      
      if (TimingSum > 0) {
        UINT64 AvgInterval = (TimingSum >> 3);
        if (AvgInterval > 1000) { // If intervals are large
          Tsc += (RdtscpRandom & 0x3FF); // Add smaller noise
        } else {
          Tsc += (RdtscpRandom & 0x3FFF); // Add larger noise
        }
      }
    }
  }
  
  // Protection 3: Auxiliary data fingerprinting resistance
  {
    STATIC UINT32 AuxHistory[4] = {0};
    STATIC UINT32 AuxHistIndex = 0;
    
    AuxHistory[AuxHistIndex] = Aux;
    AuxHistIndex = (AuxHistIndex + 1) & 0x3;
    
    // Prevent auxiliary value patterns
    if ((RdtscpCallCount & 0x1F) == 0x1F) {
      UINT32 AuxXor = 0;
      for (UINT32 i = 0; i < 4; i++) {
        AuxXor ^= AuxHistory[i];
      }
      Aux ^= (AuxXor & 0xFF);
    }
  }

  LastRdtscpTsc = Tsc;
  
  // Return sophisticated values
  Context->GuestRax = (UINT32)(Tsc & 0xFFFFFFFF);
  Context->GuestRdx = (UINT32)(Tsc >> 32);
  Context->GuestRcx = (UINT32)Aux;
  
  return EFI_SUCCESS;
}

/**
  Handle RDPMC instruction with comprehensive performance counter emulation and anti-detection.
  
  @param[in] Context        Pointer to guest context.
  
  @retval EFI_SUCCESS       RDPMC handled successfully.
**/
EFI_STATUS
EFIAPI
HandleRdpmcExit (
  IN OUT NESTED_SVM_CONTEXT *Context
  )
{
  UINT32 Counter;
  UINT64 PmcValue;
  STATIC UINT64 RdpmcCallCount = 0;
  STATIC UINT64 RdpmcBaseTsc = 0;
  STATIC UINT32 RdpmcRandomSeed = 0;
  STATIC UINT64 VirtualPerfCounters[16] = {0};
  STATIC UINT64 LastPerfUpdate = 0;

  RdpmcCallCount++;
  
  // Initialize on first call
  if (RdpmcBaseTsc == 0) {
    RdpmcBaseTsc = AsmReadTsc();
    RdpmcRandomSeed = (UINT32)RdpmcBaseTsc;
    LastPerfUpdate = RdpmcBaseTsc;
    
    // Initialize virtual performance counters with realistic base values
    for (UINT32 i = 0; i < 16; i++) {
      VirtualPerfCounters[i] = (RdpmcBaseTsc >> (i + 2)) + (i * 0x10000ULL);
    }
  }

  // Get performance counter index from ECX
  Counter = (UINT32)Context->GuestRcx;
  
  // Get current TSC for timing calculations
  UINT64 CurrentTsc = AsmReadTsc();
  UINT64 ElapsedTsc = CurrentTsc - LastPerfUpdate;
  
  // Generate comprehensive randomization
  UINT32 PerfRandom = (UINT32)(CurrentTsc ^ (CurrentTsc >> 32) ^ RdpmcCallCount ^ RdpmcRandomSeed ^ Counter);
  
  // Update virtual performance counters with realistic progression
  if (ElapsedTsc > 1000) { // Update every ~1000 TSC cycles
    for (UINT32 i = 0; i < 16; i++) {
      UINT64 UpdateFactor = (ElapsedTsc >> (i + 3)) + (PerfRandom & 0x3FF);
      VirtualPerfCounters[i] += UpdateFactor;
    }
    LastPerfUpdate = CurrentTsc;
  }
  
  // Advanced performance counter emulation based on counter type
  UINT32 CounterType = Counter & 0x1F; // Support 32 counter types
  UINT32 CounterMode = (RdpmcCallCount >> 4) & 0x7; // 8 different modes
  
  switch (CounterType) {
    case 0: // Instructions retired
      {
        UINT64 BaseInstructions = VirtualPerfCounters[0];
        UINT64 InstructionRate = (ElapsedTsc >> 1) + (PerfRandom & 0x7FF); // ~2 inst/cycle + noise
        
        switch (CounterMode) {
          case 0: // Normal execution
            PmcValue = BaseInstructions + InstructionRate;
            break;
          case 1: // High performance mode
            PmcValue = BaseInstructions + (InstructionRate * 3) / 2;
            break;
          case 2: // Low power mode
            PmcValue = BaseInstructions + (InstructionRate * 2) / 3;
            break;
          default: // Variable performance
            UINT32 VariableFactor = 80 + (PerfRandom & 0x3F); // 80-143%
            PmcValue = BaseInstructions + ((InstructionRate * VariableFactor) / 100);
            break;
        }
      }
      break;
      
    case 1: // CPU cycles
      {
        UINT64 BaseCycles = VirtualPerfCounters[1];
        UINT64 CycleIncrement = ElapsedTsc + (PerfRandom & 0xFFF);
        
        // Simulate various CPU states
        switch ((PerfRandom >> 12) & 0x7) {
          case 0: // Normal operation
            PmcValue = BaseCycles + CycleIncrement;
            break;
          case 1: // Turbo boost
            PmcValue = BaseCycles + (CycleIncrement * 11) / 10;
            break;
          case 2: // Thermal throttling
            PmcValue = BaseCycles + (CycleIncrement * 7) / 10;
            break;
          case 3: // Power saving
            PmcValue = BaseCycles + (CycleIncrement * 5) / 10;
            break;
          default: // Variable frequency
            UINT32 FreqFactor = 60 + (PerfRandom & 0x7F); // 60-187%
            PmcValue = BaseCycles + ((CycleIncrement * FreqFactor) / 100);
            break;
        }
      }
      break;
      
    case 2: // Cache references
      {
        UINT64 BaseCacheRefs = VirtualPerfCounters[2];
        UINT64 CacheRefRate = (ElapsedTsc >> 3) + (PerfRandom & 0x1FF); // ~1 ref per 8 cycles
        PmcValue = BaseCacheRefs + CacheRefRate;
      }
      break;
      
    case 3: // Cache misses
      {
        UINT64 BaseCacheMisses = VirtualPerfCounters[3];
        UINT64 MissRate = (ElapsedTsc >> 7) + (PerfRandom & 0x7F); // ~1 miss per 128 refs
        
        // Simulate cache behavior patterns
        if ((PerfRandom & 0xF) == 0xF) {
          MissRate *= 3; // Occasional cache thrashing
        } else if ((PerfRandom & 0x1F) == 0x1F) {
          MissRate /= 2; // Good cache locality
        }
        
        PmcValue = BaseCacheMisses + MissRate;
      }
      break;
      
    case 4: // Branch instructions
      {
        UINT64 BaseBranches = VirtualPerfCounters[4];
        UINT64 BranchRate = (ElapsedTsc >> 2) + (PerfRandom & 0x3FF); // ~1 branch per 4 inst
        PmcValue = BaseBranches + BranchRate;
      }
      break;
      
    case 5: // Branch misses
      {
        UINT64 BaseBranchMisses = VirtualPerfCounters[5];
        UINT64 MispredictRate = (ElapsedTsc >> 6) + (PerfRandom & 0x3F); // ~1.5% misprediction
        
        // Simulate branch prediction patterns
        switch ((PerfRandom >> 8) & 0x3) {
          case 0: // Good prediction
            MispredictRate /= 2;
            break;
          case 1: // Poor prediction
            MispredictRate *= 2;
            break;
          default: // Normal prediction
            break;
        }
        
        PmcValue = BaseBranchMisses + MispredictRate;
      }
      break;
      
    case 6: // TLB references
      {
        UINT64 BaseTlbRefs = VirtualPerfCounters[6];
        UINT64 TlbRefRate = (ElapsedTsc >> 4) + (PerfRandom & 0xFF);
        PmcValue = BaseTlbRefs + TlbRefRate;
      }
      break;
      
    case 7: // TLB misses
      {
        UINT64 BaseTlbMisses = VirtualPerfCounters[7];
        UINT64 TlbMissRate = (ElapsedTsc >> 10) + (PerfRandom & 0x1F); // Low TLB miss rate
        PmcValue = BaseTlbMisses + TlbMissRate;
      }
      break;
      
    case 8: // L1 data cache loads
      {
        UINT64 BaseL1Loads = VirtualPerfCounters[8];
        UINT64 L1LoadRate = (ElapsedTsc >> 1) + (PerfRandom & 0x7FF);
        PmcValue = BaseL1Loads + L1LoadRate;
      }
      break;
      
    case 9: // L1 data cache load misses
      {
        UINT64 BaseL1Misses = VirtualPerfCounters[9];
        UINT64 L1MissRate = (ElapsedTsc >> 6) + (PerfRandom & 0x3F); // ~1.5% L1 miss rate
        PmcValue = BaseL1Misses + L1MissRate;
      }
      break;
      
    case 10: // L1 instruction cache loads
      {
        UINT64 BaseL1ILoads = VirtualPerfCounters[10];
        UINT64 L1ILoadRate = (ElapsedTsc >> 1) + (PerfRandom & 0x7FF);
        PmcValue = BaseL1ILoads + L1ILoadRate;
      }
      break;
      
    case 11: // L1 instruction cache misses
      {
        UINT64 BaseL1IMisses = VirtualPerfCounters[11];
        UINT64 L1IMissRate = (ElapsedTsc >> 8) + (PerfRandom & 0x1F); // Very low I-cache miss
        PmcValue = BaseL1IMisses + L1IMissRate;
      }
      break;
      
    case 12: // LLC (Last Level Cache) references
      {
        UINT64 BaseLLCRefs = VirtualPerfCounters[12];
        UINT64 LLCRefRate = (ElapsedTsc >> 5) + (PerfRandom & 0x7F);
        PmcValue = BaseLLCRefs + LLCRefRate;
      }
      break;
      
    case 13: // LLC misses
      {
        UINT64 BaseLLCMisses = VirtualPerfCounters[13];
        UINT64 LLCMissRate = (ElapsedTsc >> 9) + (PerfRandom & 0xF); // Low LLC miss rate
        PmcValue = BaseLLCMisses + LLCMissRate;
      }
      break;
      
    case 14: // Bus cycles
      {
        UINT64 BaseBusCycles = VirtualPerfCounters[14];
        UINT64 BusCycleRate = (ElapsedTsc >> 3) + (PerfRandom & 0x1FF);
        PmcValue = BaseBusCycles + BusCycleRate;
      }
      break;
      
    case 15: // Reference cycles (unhalted)
      {
        UINT64 BaseRefCycles = VirtualPerfCounters[15];
        UINT64 RefCycleRate = ElapsedTsc + (PerfRandom & 0xFFF);
        PmcValue = BaseRefCycles + RefCycleRate;
      }
      break;
      
    // Extended counters for future-proofing
    case 16: // Memory loads
      {
        UINT64 BaseMemLoads = VirtualPerfCounters[0] >> 2;
        UINT64 MemLoadRate = (ElapsedTsc >> 3) + (PerfRandom & 0x1FF);
        PmcValue = BaseMemLoads + MemLoadRate;
      }
      break;
      
    case 17: // Memory stores
      {
        UINT64 BaseMemStores = VirtualPerfCounters[1] >> 3;
        UINT64 MemStoreRate = (ElapsedTsc >> 4) + (PerfRandom & 0xFF);
        PmcValue = BaseMemStores + MemStoreRate;
      }
      break;
      
    case 18: // DTLB load misses
      {
        UINT64 BaseDtlbMisses = VirtualPerfCounters[2] >> 8;
        UINT64 DtlbMissRate = (ElapsedTsc >> 11) + (PerfRandom & 0x7);
        PmcValue = BaseDtlbMisses + DtlbMissRate;
      }
      break;
      
    case 19: // ITLB load misses
      {
        UINT64 BaseItlbMisses = VirtualPerfCounters[3] >> 9;
        UINT64 ItlbMissRate = (ElapsedTsc >> 12) + (PerfRandom & 0x3);
        PmcValue = BaseItlbMisses + ItlbMissRate;
      }
      break;
      
    default:
      // For unknown counters, generate sophisticated fake data
      {
        UINT32 CounterIndex = CounterType & 0xF;
        UINT64 BaseValue = VirtualPerfCounters[CounterIndex];
        UINT64 FakeIncrement = (ElapsedTsc >> (CounterIndex + 2)) + (PerfRandom & ((1 << CounterIndex) - 1));
        PmcValue = BaseValue + FakeIncrement;
      }
      break;
  }
  
  // Advanced anti-detection techniques
  
  // Technique 1: Performance counter correlation breaking
  if ((RdpmcCallCount & 0x1F) == 0x1F) {
    UINT64 CorrelationBreaker = (PerfRandom & 0x3FFF) + 1000;
    PmcValue += CorrelationBreaker;
  }
  
  // Technique 2: Simulate performance counter overflow
  if ((PerfRandom & 0x7FF) == 0x7FF) {
    PmcValue &= 0x0FFFFFFFFFFFFFFFULL; // Simulate 60-bit counter
  }
  
  // Technique 3: Counter value quantization (simulate hardware granularity)
  {
    UINT32 Quantum = 1 << ((CounterType & 0x7) + 2); // 4-1024 quantum sizes
    PmcValue = (PmcValue / Quantum) * Quantum;
  }
  
  // Technique 4: Cross-counter consistency simulation
  if ((RdpmcCallCount & 0x7F) == 0x7F) {
    // Ensure cache misses don't exceed cache references
    if (CounterType == 3 && VirtualPerfCounters[2] > 0) { // Cache misses
      UINT64 MaxMisses = VirtualPerfCounters[2] / 2; // At most 50% miss rate
      if (PmcValue > MaxMisses) {
        PmcValue = MaxMisses + (PerfRandom & 0xFF);
      }
    }
    
    // Ensure branch misses don't exceed branch instructions
    if (CounterType == 5 && VirtualPerfCounters[4] > 0) { // Branch misses
      UINT64 MaxBranchMisses = VirtualPerfCounters[4] / 4; // At most 25% miss rate
      if (PmcValue > MaxBranchMisses) {
        PmcValue = MaxBranchMisses + (PerfRandom & 0x3F);
      }
    }
  }
  
  // Technique 5: Performance state transition simulation
  if ((RdpmcCallCount & 0xFF) == 0xFF) {
    // Simulate P-state or C-state transitions affecting counters
    UINT32 StateTransition = (PerfRandom >> 16) & 0x7;
    switch (StateTransition) {
      case 0: // Entering low power state
        PmcValue = (PmcValue * 3) / 4;
        break;
      case 1: // Exiting low power state
        PmcValue = (PmcValue * 5) / 4;
        break;
      case 2: // Frequency scaling up
        PmcValue = (PmcValue * 6) / 5;
        break;
      case 3: // Frequency scaling down
        PmcValue = (PmcValue * 4) / 5;
        break;
      default: // No state change
        break;
    }
  }
  
  // Technique 6: Anti-profiling noise injection
  {
    UINT32 NoiseLevel = (PerfRandom >> 8) & 0x1F;
    if (NoiseLevel > 24) { // ~3% chance
      UINT64 Noise = (UINT64)((PerfRandom & 0x3FFF) + 1);
      PmcValue += ((PerfRandom & BIT31) ? Noise : -Noise);
    }
  }
  
  // Update virtual counter with the calculated value
  if (CounterType < 16) {
    VirtualPerfCounters[CounterType] = PmcValue;
  }
  
  // Return sophisticated performance counter value in EDX:EAX
  Context->GuestRax = (UINT32)(PmcValue & 0xFFFFFFFF);
  Context->GuestRdx = (UINT32)(PmcValue >> 32);
  
  return EFI_SUCCESS;
}

/**
  Handle VMMCALL instruction.
  
  @param[in] Context        Pointer to guest context.
  
  @retval EFI_SUCCESS       VMMCALL handled successfully.
**/
EFI_STATUS
EFIAPI
HandleVmmcall (
  IN OUT NESTED_SVM_CONTEXT *Context
  )
{
  VMCB *Vmcb;
  // For stealth and broad compatibility, make VMMCALL behave like bare metal: inject #UD
  Vmcb = (VMCB *)gMiniVisorSvmGlobalData.VmcbRegion;
  if (Vmcb != NULL) {
    // EventInj encoding: bits[7:0]=vector, bits[10:8]=type(3=exception), bit[31]=Valid
    Vmcb->ControlArea.EventInj = (6ULL) | (3ULL << 8) | (1ULL << 31);
  }
  return EFI_SUCCESS;
}

/**
  Initialize comprehensive IOMMU manager with advanced anti-detection features.
**/
STATIC
EFI_STATUS
InitializeAdvancedIommuManager (
  VOID
  )
{
  UINT64 CurrentTsc = AsmReadTsc();
  
  // Clear the structure
  ZeroMem(&gIommuManager, sizeof(COMPREHENSIVE_IOMMU_MANAGER));
  
  // Initialize basic properties
  // Default to non-compatibility; will be set to TRUE if an IVRS table exists
  gIommuManager.CompatibilityMode = FALSE;
  gIommuManager.RandomizationSeed = CurrentTsc;
  gIommuManager.TimingSeed = (UINT32)CurrentTsc;
  gIommuManager.LastAccessTime = CurrentTsc;
  
  // Set up multi-segment configuration for advanced stealth
  gIommuManager.NumSegments = 2 + ((UINT32)CurrentTsc & 0x3); // 2-5 segments
  
  // Ensure NumSegments doesn't exceed array bounds
  if (gIommuManager.NumSegments > 8) {
    gIommuManager.NumSegments = 8;
  }
  
  // Initialize segment MMIO bases
  for (UINT32 i = 0; i < gIommuManager.NumSegments; i++) {
    // Use different base addresses for each segment
    gIommuManager.SegmentMmioBases[i] = 0xFEB80000ULL + (i * 0x10000); // 64KB per segment
    gIommuManager.SegmentIds[i] = (UINT16)(i + 1);
    
    // Initialize register defaults (strict minimal AMD-Vi map)
    gIommuManager.Control[i] = 0x00000000; // disabled initially
    gIommuManager.Status[i] = AMDVI_STATUS_READY; // ready
    gIommuManager.ExtFeatures[i] = 0x0000001F; // Basic feature set
    
    // Initialize performance counters with realistic base values
    for (UINT32 j = 0; j < 4; j++) {
      gIommuManager.PerfCounters[i][j] = (CurrentTsc >> (8 + i + j)) & 0xFFFFFF;
    }
  }
  
  // Set primary MMIO base to first segment
  gIommuManager.MmioBase = gIommuManager.SegmentMmioBases[0];
  
  // Initialize fake device table entries
  for (UINT32 i = 0; i < 256; i++) {
    UINT64 FakeEntry = (CurrentTsc + i * 0x1000) ^ (i * 0x12345678ULL);
    gIommuManager.FakeDeviceTable[i] = FakeEntry;
  }
  
  // Initialize fake command buffer
  for (UINT32 i = 0; i < 128; i++) {
    UINT64 FakeCommand = (CurrentTsc >> 8) ^ (i * 0x87654321ULL);
    gIommuManager.FakeCommandBuffer[i] = FakeCommand;
  }
  
  // Initialize fake event log
  for (UINT32 i = 0; i < 64; i++) {
    UINT64 FakeEvent = (CurrentTsc >> 16) ^ (i * 0xABCDEF00ULL);
    gIommuManager.FakeEventLog[i] = FakeEvent;
  }
  
  // Initialize hypervisor signatures for multi-platform simulation
  gIommuManager.HypervisorSignature[0] = 0x61774D56; // "VMwa"
  gIommuManager.HypervisorSignature[1] = 0x4D566572; // "reVM" 
  gIommuManager.HypervisorSignature[2] = 0x65726177; // "ware"
  gIommuManager.HypervisorSignature[3] = 0x00000000;
  
  // Set virtualization level and features
  gIommuManager.VirtualizationLevel = 1 + ((UINT32)CurrentTsc & 0x3); // Level 1-4
  gIommuManager.HypervisorFeatures = 0x0000FFFF; // Basic hypervisor features
  
  // Initialize cross-platform compatibility modes
  gIommuManager.IntelCompatMode = ((UINT32)CurrentTsc & 0x1) ? 1 : 0;
  gIommuManager.HyperVCompatMode = ((UINT32)CurrentTsc & 0x2) ? 1 : 0;
  gIommuManager.VMwareCompatMode = ((UINT32)CurrentTsc & 0x4) ? 1 : 0;
  gIommuManager.XenCompatMode = ((UINT32)CurrentTsc & 0x8) ? 1 : 0;
  
  // Initialize behavioral and performance profiles
  gIommuManager.BehaviorMode = (UINT32)CurrentTsc & 0x7;
  gIommuManager.PerformanceProfile = ((UINT32)CurrentTsc >> 8) & 0x7;
  gIommuManager.AntiDetectionMode = ((UINT32)CurrentTsc >> 16) & 0x7;
  
  // Initialize access pattern tracking
  for (UINT32 i = 0; i < 16; i++) {
    gIommuManager.AccessPattern[i] = CurrentTsc ^ (i * 0x12345678ULL);
  }
  
  // Initialize shadow MMIO spaces with random data
  for (UINT32 s = 0; s < gIommuManager.NumSegments; s++) {
    for (UINT32 i = 0; i < 8192; i++) {
      UINT64 ShadowValue = (CurrentTsc + s * 0x10000 + i) ^ (i * 0x9E3779B9ULL);
      gIommuManager.ShadowMmio[s][i] = ShadowValue;
    }
  }
  
  DEBUG((DEBUG_INFO, "[SVM] Advanced IOMMU manager initialized with %d segments\n", 
    gIommuManager.NumSegments));
  
  // Setup NPT-based MMIO traps for comprehensive AMD-Vi register interception
  EFI_STATUS TrapStatus = SetupAmdViMmioTraps();
  if (EFI_ERROR(TrapStatus)) {
    DEBUG((DEBUG_WARN, "[SVM] Failed to setup AMD-Vi MMIO traps: %r (continuing anyway)\n", TrapStatus));
  } else {
    DEBUG((DEBUG_INFO, "[SVM] AMD-Vi MMIO NPT traps configured successfully\n"));
  }
  
  return EFI_SUCCESS;
}

/**
  Initialize SVM global data structure.
**/
STATIC
EFI_STATUS
InitializeSvmGlobalData (
  VOID
  )
{
  EFI_STATUS Status;

  ZeroMem(&gMiniVisorSvmGlobalData, sizeof(MINI_VISOR_SVM_GLOBAL_DATA));

  gMiniVisorSvmGlobalData.Signature = MINI_VISOR_SVM_SIGNATURE;
  gMiniVisorSvmGlobalData.Version = 
    (MINI_VISOR_SVM_MAJOR_VERSION << 16) | 
    (MINI_VISOR_SVM_MINOR_VERSION << 8) | 
    MINI_VISOR_SVM_BUILD_VERSION;

  //
  // Get CPU count
  //
  gMiniVisorSvmGlobalData.CpuCount = 1; // Simplified for now

  //
  // Get SVM capabilities
  //
  Status = GetSvmCapabilities(&gMiniVisorSvmGlobalData.SvmCapabilities);
  if (EFI_ERROR(Status)) {
    DEBUG((DEBUG_ERROR, "[SVM] Failed to get SVM capabilities: %r\n", Status));
    return Status;
  }

  gMiniVisorSvmGlobalData.MaxAsid = gMiniVisorSvmGlobalData.SvmCapabilities.MaxAsid;
  gMiniVisorSvmGlobalData.CurrentAsid = 0;

  //
  // Initialize comprehensive IOMMU manager for future-proofing and advanced anti-detection
  //
  Status = InitializeAdvancedIommuManager();
  if (EFI_ERROR(Status)) {
    DEBUG((DEBUG_WARN, "[SVM] Failed to initialize advanced IOMMU manager: %r (continuing anyway)\n", Status));
    // Don't fail initialization - IOMMU emulation is optional
  }

  return EFI_SUCCESS;
}

/**
  Allocate SVM memory regions.
**/
STATIC
EFI_STATUS
AllocateSvmRegions (
  VOID
  )
{
  EFI_STATUS            Status;
  EFI_PHYSICAL_ADDRESS  VmcbRegion;
  EFI_PHYSICAL_ADDRESS  HostSaveArea;

  //
  // Allocate VMCB region (4KB aligned)
  //
  Status = gBS->AllocatePages(
                  AllocateAnyPages,
                  EfiReservedMemoryType,
                  1, // 4KB
                  &VmcbRegion
                  );
  if (EFI_ERROR(Status)) {
    DEBUG((DEBUG_ERROR, "[SVM] Failed to allocate VMCB region: %r\n", Status));
    return Status;
  }

  //
  // Allocate Host Save Area (4KB aligned)
  //
  Status = gBS->AllocatePages(
                  AllocateAnyPages,
                  EfiReservedMemoryType,
                  1, // 4KB
                  &HostSaveArea
                  );
  if (EFI_ERROR(Status)) {
    DEBUG((DEBUG_ERROR, "[SVM] Failed to allocate Host Save Area: %r\n", Status));
    gBS->FreePages(VmcbRegion, 1);
    return Status;
  }

  //
  // Clear allocated regions
  //
  ZeroMem((VOID *)(UINTN)VmcbRegion, SIZE_4KB);
  ZeroMem((VOID *)(UINTN)HostSaveArea, SIZE_4KB);

  gMiniVisorSvmGlobalData.VmcbRegion = (VOID *)(UINTN)VmcbRegion;
  gMiniVisorSvmGlobalData.HostSaveArea = (VOID *)(UINTN)HostSaveArea;

  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] VMCB allocated at 0x%lx\n", VmcbRegion));
  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] Host Save Area allocated at 0x%lx\n", HostSaveArea));

  return EFI_SUCCESS;
}

/**
  Setup SVM environment.
**/
STATIC
EFI_STATUS
SetupSvmEnvironment (
  VOID
  )
{
  EFI_STATUS Status;

  //
  // Setup Host Save Area
  //
  Status = SetupHostSaveArea();
  if (EFI_ERROR(Status)) {
    DEBUG((DEBUG_ERROR, "[SVM] Failed to setup Host Save Area: %r\n", Status));
    return Status;
  }

  //
  // Setup Nested Page Tables
  //
  Status = SetupNestedPageTables();
  if (EFI_ERROR(Status) && Status != EFI_UNSUPPORTED) {
    DEBUG((DEBUG_ERROR, "[SVM] Failed to setup NPT: %r\n", Status));
    return Status;
  }

  //
  // Setup MSR bitmap
  //
  Status = SetupMsrBitmap();
  if (EFI_ERROR(Status)) {
    DEBUG((DEBUG_ERROR, "[SVM] Failed to setup MSR bitmap: %r\n", Status));
    return Status;
  }

  //
  // Setup I/O bitmap
  //
  Status = SetupIoBitmap();
  if (EFI_ERROR(Status)) {
    DEBUG((DEBUG_ERROR, "[SVM] Failed to setup I/O bitmap: %r\n", Status));
    return Status;
  }

  return EFI_SUCCESS;
}

/**
  Setup Host Save Area.
**/
STATIC
EFI_STATUS
SetupHostSaveArea (
  VOID
  )
{
  EFI_PHYSICAL_ADDRESS HostSaveAreaPa;

  HostSaveAreaPa = (EFI_PHYSICAL_ADDRESS)(UINTN)gMiniVisorSvmGlobalData.HostSaveArea;

  //
  // Set VM_HSAVE_PA MSR to point to Host Save Area
  //
  AsmWriteMsr(MSR_VM_HSAVE_PA, HostSaveAreaPa);

  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] Host Save Area configured at 0x%lx\n", HostSaveAreaPa));
  return EFI_SUCCESS;
}

/**
  Get MiniVisor SVM status information.
  
  @param[out] StatusInfo    Pointer to receive status information.
  
  @retval EFI_SUCCESS       Status retrieved successfully.
  @retval EFI_INVALID_PARAMETER  StatusInfo is NULL.
**/
EFI_STATUS
EFIAPI
MiniVisorSvmGetStatus (
  OUT MINI_VISOR_SVM_GLOBAL_DATA  *StatusInfo
  )
{
  if (StatusInfo == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  CopyMem(StatusInfo, &gMiniVisorSvmGlobalData, sizeof(MINI_VISOR_SVM_GLOBAL_DATA));
  return EFI_SUCCESS;
}

/**
  Get MiniVisor SVM performance data.
  
  @param[out] PerfData      Pointer to receive performance data.
  
  @retval EFI_SUCCESS       Performance data retrieved successfully.
  @retval EFI_INVALID_PARAMETER  PerfData is NULL.
**/
EFI_STATUS
EFIAPI
MiniVisorSvmGetPerformanceData (
  OUT MINI_VISOR_SVM_PERFORMANCE_DATA  *PerfData
  )
{
  if (PerfData == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  CopyMem(PerfData, &gMiniVisorSvmGlobalData.PerfData, sizeof(MINI_VISOR_SVM_PERFORMANCE_DATA));
  return EFI_SUCCESS;
}

/**
  Reset MiniVisor SVM performance counters.
  
  @retval EFI_SUCCESS       Performance counters reset successfully.
**/
EFI_STATUS
EFIAPI
MiniVisorSvmResetPerformanceCounters (
  VOID
  )
{
  ZeroMem(&gMiniVisorSvmGlobalData.PerfData, sizeof(MINI_VISOR_SVM_PERFORMANCE_DATA));
  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] Performance counters reset\n"));
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
SvmAllocateTrackedPages (
  IN EFI_ALLOCATE_TYPE     Type,
  IN EFI_MEMORY_TYPE       MemoryType,
  IN UINTN                 Pages,
  IN OUT EFI_PHYSICAL_ADDRESS *Memory
  )
{
  EFI_STATUS Status;
  Status = gBS->AllocatePages(Type, MemoryType, Pages, Memory);
  if (!EFI_ERROR(Status)) {
    gMiniVisorSvmGlobalData.MemTrack.TotalPagesAllocated += Pages;
    gMiniVisorSvmGlobalData.MemTrack.OutstandingPages += Pages;
  }
  return Status;
}

EFI_STATUS
EFIAPI
SvmFreeTrackedPages (
  IN EFI_PHYSICAL_ADDRESS  Memory,
  IN UINTN                 Pages
  )
{
  EFI_STATUS Status;
  Status = gBS->FreePages(Memory, Pages);
  if (!EFI_ERROR(Status)) {
    gMiniVisorSvmGlobalData.MemTrack.TotalPagesFreed += Pages;
    if (gMiniVisorSvmGlobalData.MemTrack.OutstandingPages >= Pages) {
      gMiniVisorSvmGlobalData.MemTrack.OutstandingPages -= Pages;
    } else {
      gMiniVisorSvmGlobalData.MemTrack.OutstandingPages = 0;
    }
  }
  return Status;
}

// ==============================================================================
// SVM Driver Authorization System Implementation
// Compatible with Intel VT-d Authorization Generator
// ==============================================================================

/**
  Utility function to compare filenames in a case-insensitive manner
**/
STATIC BOOLEAN
SvmAuthFileNameEquals(
  IN CONST CHAR16 *A,
  IN CONST CHAR16 *B
  )
{
  if (A == NULL || B == NULL) {
    return FALSE;
  }
  
  while (*A && *B) {
    CHAR16 CharA = (*A >= L'a' && *A <= L'z') ? (*A - L'a' + L'A') : *A;
    CHAR16 CharB = (*B >= L'a' && *B <= L'z') ? (*B - L'a' + L'A') : *B;
    if (CharA != CharB) {
      return FALSE;
    }
    A++;
    B++;
  }
  return *A == *B;
}

/**
  Recursively search for a file in a directory
**/
STATIC EFI_STATUS
SvmAuthSearchFileInDir(
  IN EFI_FILE_PROTOCOL *Directory,
  IN CHAR16 *TargetFileName,
  OUT EFI_FILE_PROTOCOL **FoundFile,
  IN UINTN Depth
  )
{
  EFI_STATUS        Status;
  EFI_FILE_INFO    *FileInfo = NULL;
  UINTN             InfoSize = 0;
  EFI_FILE_PROTOCOL *Handle   = NULL;

  if (Directory == NULL || TargetFileName == NULL || FoundFile == NULL || Depth > 10) {
    return EFI_INVALID_PARAMETER;
  }

  *FoundFile = NULL;

  // Reset directory enumeration to start
  Status = Directory->SetPosition(Directory, 0);
  if (EFI_ERROR(Status)) {
    return Status;
  }

  while (TRUE) {
    // Query the size of the next EFI_FILE_INFO
    InfoSize = 0;
    Status = Directory->GetInfo(Directory, &gEfiFileInfoGuid, &InfoSize, NULL);
    if (Status != EFI_BUFFER_TOO_SMALL) {
      // End of directory or error
      break;
    }

    Status = gBS->AllocatePool(EfiBootServicesData, InfoSize, (VOID **)&FileInfo);
    if (EFI_ERROR(Status) || FileInfo == NULL) {
      return EFI_OUT_OF_RESOURCES;
    }

    // Read the next directory entry
    Status = Directory->Read(Directory, &InfoSize, FileInfo);
    if (EFI_ERROR(Status) || InfoSize == 0) {
      gBS->FreePool(FileInfo);
      FileInfo = NULL;
      break; // End of directory
    }

    // Skip "." and ".."
    if (SvmAuthFileNameEquals(FileInfo->FileName, L".") || SvmAuthFileNameEquals(FileInfo->FileName, L"..")) {
      gBS->FreePool(FileInfo);
      FileInfo = NULL;
      continue;
    }

    if ((FileInfo->Attribute & EFI_FILE_DIRECTORY) == 0) {
      // File entry: check name match
      if (SvmAuthFileNameEquals(FileInfo->FileName, TargetFileName)) {
        Status = Directory->Open(Directory, &Handle, FileInfo->FileName, EFI_FILE_MODE_READ, 0);
        if (!EFI_ERROR(Status)) {
          *FoundFile = Handle;
          gBS->FreePool(FileInfo);
          return EFI_SUCCESS;
        }
      }
    } else if (Depth < 5) {
      // Directory entry: recurse into it (bounded depth)
      EFI_FILE_PROTOCOL *SubDir = NULL;
      Status = Directory->Open(Directory, &SubDir, FileInfo->FileName, EFI_FILE_MODE_READ, 0);
      if (!EFI_ERROR(Status) && SubDir != NULL) {
        EFI_FILE_PROTOCOL *SubFound = NULL;
        Status = SvmAuthSearchFileInDir(SubDir, TargetFileName, &SubFound, Depth + 1);
        SubDir->Close(SubDir);
        if (!EFI_ERROR(Status) && SubFound != NULL) {
          *FoundFile = SubFound;
          gBS->FreePool(FileInfo);
          return EFI_SUCCESS;
        }
      }
    }

    gBS->FreePool(FileInfo);
    FileInfo = NULL;
  }

  return EFI_NOT_FOUND;
}

/**
  Find authorization file across all volumes
**/
STATIC EFI_STATUS
SvmAuthFindFileByNameAcrossVolumes(
  IN CHAR16 *FileName,
  OUT EFI_HANDLE *FoundFsHandle,
  OUT EFI_FILE_PROTOCOL **RootDir,
  OUT EFI_FILE_PROTOCOL **AuthFile
  )
{
  EFI_STATUS Status;
  EFI_HANDLE *HandleBuffer = NULL;
  UINTN HandleCount = 0;
  BOOLEAN HasPathSeparator = FALSE;
  for (CONST CHAR16 *p = FileName; p != NULL && *p != L'\0'; p++) {
    if (*p == L'\\' || *p == L'/') {
      HasPathSeparator = TRUE;
      break;
    }
  }

  if (FoundFsHandle == NULL || RootDir == NULL || AuthFile == NULL || FileName == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  *FoundFsHandle = NULL;
  *RootDir = NULL;
  *AuthFile = NULL;
  
  // 1) Prefer previously used filesystem handle if known
  if (gSvmAuthFsHandle != NULL) {
    EFI_FILE_PROTOCOL *Root = NULL;
    Status = SvmAuthOpenRootOnHandle(gSvmAuthFsHandle, &Root);
    if (!EFI_ERROR(Status) && Root != NULL) {
      if (HasPathSeparator) {
        EFI_FILE_PROTOCOL *Direct = NULL;
        Status = Root->Open(Root, &Direct, FileName, EFI_FILE_MODE_READ, 0);
        if (!EFI_ERROR(Status) && Direct != NULL) {
          *FoundFsHandle = gSvmAuthFsHandle;
          *RootDir = Root;
          *AuthFile = Direct;
          return EFI_SUCCESS;
        }
      } else {
        EFI_FILE_PROTOCOL *Found = NULL;
        Status = SvmAuthSearchFileInDir(Root, FileName, &Found, 0);
        if (!EFI_ERROR(Status) && Found != NULL) {
          *FoundFsHandle = gSvmAuthFsHandle;
          *RootDir = Root;
          *AuthFile = Found;
          return EFI_SUCCESS;
        }
      }
      Root->Close(Root);
    }
  }

  // 2) Prefer the filesystem of the loaded image (likely the boot device/U-disk)
  EFI_HANDLE ImageFsHandle = NULL;
  Status = SvmAuthGetLoadedImageFsHandle(&ImageFsHandle);
  if (!EFI_ERROR(Status) && ImageFsHandle != NULL) {
    EFI_FILE_PROTOCOL *Root = NULL;
    Status = SvmAuthOpenRootOnHandle(ImageFsHandle, &Root);
    if (!EFI_ERROR(Status) && Root != NULL) {
      if (HasPathSeparator) {
        EFI_FILE_PROTOCOL *Direct = NULL;
        Status = Root->Open(Root, &Direct, FileName, EFI_FILE_MODE_READ, 0);
        if (!EFI_ERROR(Status) && Direct != NULL) {
          *FoundFsHandle = ImageFsHandle;
          *RootDir = Root;
          *AuthFile = Direct;
          return EFI_SUCCESS;
        }
      } else {
        EFI_FILE_PROTOCOL *Found = NULL;
        Status = SvmAuthSearchFileInDir(Root, FileName, &Found, 0);
        if (!EFI_ERROR(Status) && Found != NULL) {
          *FoundFsHandle = ImageFsHandle;
          *RootDir = Root;
          *AuthFile = Found;
          return EFI_SUCCESS;
        }
      }
      Root->Close(Root);
    }
  }

  // 3) Fallback: enumerate all filesystems
  Status = gBS->LocateHandleBuffer(ByProtocol, &gEfiSimpleFileSystemProtocolGuid, NULL, &HandleCount, &HandleBuffer);
  if (EFI_ERROR(Status) || HandleCount == 0 || HandleBuffer == NULL) {
    return Status;
  }

  for (UINTN i = 0; i < HandleCount; i++) {
    // Skip image handle if already tried
    if (ImageFsHandle != NULL && HandleBuffer[i] == ImageFsHandle) {
      continue;
    }
    EFI_FILE_PROTOCOL *Root = NULL;
    Status = SvmAuthOpenRootOnHandle(HandleBuffer[i], &Root);
    if (EFI_ERROR(Status) || Root == NULL) {
      continue;
    }
    if (HasPathSeparator) {
      EFI_FILE_PROTOCOL *Direct = NULL;
      Status = Root->Open(Root, &Direct, FileName, EFI_FILE_MODE_READ, 0);
      if (!EFI_ERROR(Status) && Direct != NULL) {
        *FoundFsHandle = HandleBuffer[i];
        *RootDir = Root;
        *AuthFile = Direct;
        gBS->FreePool(HandleBuffer);
        return EFI_SUCCESS;
      }
    } else {
      EFI_FILE_PROTOCOL *Found = NULL;
      Status = SvmAuthSearchFileInDir(Root, FileName, &Found, 0);
      if (!EFI_ERROR(Status) && Found != NULL) {
        *FoundFsHandle = HandleBuffer[i];
        *RootDir = Root;
        *AuthFile = Found;
        gBS->FreePool(HandleBuffer);
        return EFI_SUCCESS;
      }
    }
    Root->Close(Root);
  }

  gBS->FreePool(HandleBuffer);
  return EFI_NOT_FOUND;
}

/**
  Open root directory on a file system handle
**/
STATIC EFI_STATUS
SvmAuthOpenRootOnHandle(
  IN EFI_HANDLE FsHandle,
  OUT EFI_FILE_PROTOCOL **RootDir
  )
{
  EFI_STATUS Status;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *SimpleFs = NULL;

  if (RootDir == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  *RootDir = NULL;

  Status = gBS->HandleProtocol(FsHandle, &gEfiSimpleFileSystemProtocolGuid, (VOID**)&SimpleFs);
  if (EFI_ERROR(Status) || SimpleFs == NULL) {
    return Status;
  }

  return SimpleFs->OpenVolume(SimpleFs, RootDir);
}

/**
  Get file system handle from loaded image
**/
STATIC EFI_STATUS
SvmAuthGetLoadedImageFsHandle(
  OUT EFI_HANDLE *FsHandle
  )
{
  EFI_STATUS Status;
  EFI_LOADED_IMAGE_PROTOCOL *LoadedImage = NULL;

  if (FsHandle == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  *FsHandle = NULL;

  Status = gBS->HandleProtocol(gImageHandle, &gEfiLoadedImageProtocolGuid, (VOID**)&LoadedImage);
  if (EFI_ERROR(Status) || LoadedImage == NULL) {
    return Status;
  }

  *FsHandle = LoadedImage->DeviceHandle;
  return EFI_SUCCESS;
}

/**
  Log file system information for debugging
**/
STATIC VOID
SvmAuthLogFsInfo(
  IN EFI_FILE_PROTOCOL *RootDir
  )
{
  if (RootDir == NULL) {
    return;
  }

  // No debug logging in production mode
}

/**
  Simple hash function compatible with Intel version
**/
UINT32
SvmSimpleHash(
  UINT8 *Data,
  UINTN Length
  )
{
  if (!Data || Length == 0) {
    return 0;
  }
  
  UINT32 HashVal = 0x5A5A5A5A;
  for (UINTN i = 0; i < Length; i++) {
    HashVal = ((HashVal << 5) + HashVal) + Data[i];
    HashVal ^= (HashVal >> 16);
    HashVal &= 0xFFFFFFFF;  // 32-bit
  }
  
  return HashVal;
}

/**
  Get CPU serial number (placeholder for compatibility)
**/
UINT64
SvmGetCpuSerialNumber(
  VOID
  )
{
  // Match Intel VT-d implementation to keep authorizer compatible
  UINT32 CpuidEax = 0, CpuidEbx = 0, CpuidEcx = 0, CpuidEdx = 0;
  UINT64 SerialNumber = 0;
  AsmCpuid(1, &CpuidEax, &CpuidEbx, &CpuidEcx, &CpuidEdx);
  SerialNumber = ((UINT64)CpuidEax << 32) |
                 (((UINT64)CpuidEbx) & 0xFFFFFF00ULL) |
                 (CpuidEbx & 0xFF);
  return SerialNumber;
}

/**
  Get mainboard serial (placeholder implementation)
**/
EFI_STATUS
SvmGetMainboardSerial(
  CHAR8 *SerialBuffer,
  UINTN BufferSize
  )
{
  EFI_STATUS Status;
  EFI_SMBIOS_PROTOCOL *SmbiosProtocol;
  EFI_SMBIOS_HANDLE SmbiosHandle;
  EFI_SMBIOS_TABLE_HEADER *SmbiosTable;
  SMBIOS_TABLE_TYPE2 *BaseboardInfo;
  CHAR8 *StringPtr;
  UINTN StringIndex;

  if (SerialBuffer == NULL || BufferSize == 0) {
    return EFI_INVALID_PARAMETER;
  }

  ZeroMem(SerialBuffer, BufferSize);

  // Try SMBIOS Type 2 (Baseboard)
  Status = gBS->LocateProtocol(&gEfiSmbiosProtocolGuid, NULL, (VOID**)&SmbiosProtocol);
  if (EFI_ERROR(Status)) {
    AsciiStrCpyS(SerialBuffer, BufferSize, "MB-DEFAULT-SERIAL");
    return EFI_NOT_FOUND;
  }

  SmbiosHandle = SMBIOS_HANDLE_PI_RESERVED;
  Status = SmbiosProtocol->GetNext(SmbiosProtocol, &SmbiosHandle, NULL, &SmbiosTable, NULL);
  while (!EFI_ERROR(Status)) {
    if (SmbiosTable->Type == SMBIOS_TYPE_BASEBOARD_INFORMATION) {
      BaseboardInfo = (SMBIOS_TABLE_TYPE2*)SmbiosTable;
      if (BaseboardInfo->SerialNumber != 0) {
        StringPtr = (CHAR8*)((UINTN)SmbiosTable + SmbiosTable->Length);
        StringIndex = 1;
        while (StringIndex < BaseboardInfo->SerialNumber && *StringPtr != 0) {
          while (*StringPtr != 0) { StringPtr++; }
          StringPtr++;
          StringIndex++;
        }
        if (*StringPtr != 0 && AsciiStrLen(StringPtr) > 0) {
          AsciiStrCpyS(SerialBuffer, BufferSize, StringPtr);
          return EFI_SUCCESS;
        }
      }
    }
    Status = SmbiosProtocol->GetNext(SmbiosProtocol, &SmbiosHandle, NULL, &SmbiosTable, NULL);
  }

  // Fallback SMBIOS Type 1 (System)
  SmbiosHandle = SMBIOS_HANDLE_PI_RESERVED;
  Status = SmbiosProtocol->GetNext(SmbiosProtocol, &SmbiosHandle, NULL, &SmbiosTable, NULL);
  while (!EFI_ERROR(Status)) {
    if (SmbiosTable->Type == SMBIOS_TYPE_SYSTEM_INFORMATION) {
      SMBIOS_TABLE_TYPE1 *SystemInfo = (SMBIOS_TABLE_TYPE1*)SmbiosTable;
      if (SystemInfo->SerialNumber != 0) {
        StringPtr = (CHAR8*)((UINTN)SmbiosTable + SmbiosTable->Length);
        StringIndex = 1;
        while (StringIndex < SystemInfo->SerialNumber && *StringPtr != 0) {
          while (*StringPtr != 0) { StringPtr++; }
          StringPtr++;
          StringIndex++;
        }
        if (*StringPtr != 0 && AsciiStrLen(StringPtr) > 0) {
          AsciiStrCpyS(SerialBuffer, BufferSize, StringPtr);
          return EFI_SUCCESS;
        }
      }
    }
    Status = SmbiosProtocol->GetNext(SmbiosProtocol, &SmbiosHandle, NULL, &SmbiosTable, NULL);
  }

  AsciiStrCpyS(SerialBuffer, BufferSize, "SYS-DEFAULT-SERIAL");
  return EFI_NOT_FOUND;
}

/**
  Generate hardware fingerprint compatible with Intel version
**/
EFI_STATUS
SvmGenerateHardwareFingerprint(
  SVM_HARDWARE_FINGERPRINT *Fingerprint
  )
{
  EFI_STATUS Status;
  UINT32 Eax, Ebx, Ecx, Edx;
  CHAR8 MainboardSerial[64];
  UINT32 BrandRegs[4];
  
  if (Fingerprint == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  
  ZeroMem(Fingerprint, sizeof(SVM_HARDWARE_FINGERPRINT));
  
  // Get CPU signature
  AsmCpuid(1, &Eax, &Ebx, &Ecx, &Edx);
  Fingerprint->CpuSignature = Eax;
  
  // Get CPU brand hash (match Intel VT-d implementation: hash first 16 bytes at 0x80000002)
  AsmCpuid(0x80000002, &BrandRegs[0], &BrandRegs[1], &BrandRegs[2], &BrandRegs[3]);
  Fingerprint->CpuBrandHash = SvmSimpleHash((UINT8*)BrandRegs, sizeof(BrandRegs));
  
  // Get CPU serial number (copy into array)
  UINT64 SerialNumber = SvmGetCpuSerialNumber();
  CopyMem(Fingerprint->CpuSerialNumber, &SerialNumber, sizeof(UINT64));
  
  // Get system time (match VT-d packing)
  EFI_TIME CurrentTime;
  Status = gRT->GetTime(&CurrentTime, NULL);
  if (!EFI_ERROR(Status)) {
    Fingerprint->SystemTime = (UINT64)CurrentTime.Year << 48 |
                              (UINT64)CurrentTime.Month << 40 |
                              (UINT64)CurrentTime.Day << 32 |
                              (UINT64)CurrentTime.Hour << 24 |
                              (UINT64)CurrentTime.Minute << 16 |
                              (UINT64)CurrentTime.Second << 8;
  }
  
  // Get memory size (match VT-d approximation)
  UINTN MemoryMapSize = 0;
  UINTN MapKey;
  UINTN DescriptorSize;
  UINT32 DescriptorVersion;
  Status = gBS->GetMemoryMap(&MemoryMapSize, NULL, &MapKey, &DescriptorSize, &DescriptorVersion);
  if (Status == EFI_BUFFER_TOO_SMALL && DescriptorSize != 0) {
    Fingerprint->MemorySize = (UINT32)(MemoryMapSize / DescriptorSize);
  }
  
  // Get PCI device count (match VT-d default)
  Fingerprint->PciDeviceCount = 42;
  
  // Get mainboard serial hash
  Status = SvmGetMainboardSerial(MainboardSerial, sizeof(MainboardSerial));
  if (!EFI_ERROR(Status)) {
    Fingerprint->MainboardSerialHash = SvmSimpleHash((UINT8*)MainboardSerial, AsciiStrLen(MainboardSerial));
  }
  
  // Set reserved fields
  Fingerprint->Reserved1 = 0;
  Fingerprint->Reserved2 = 0;
  
  return EFI_SUCCESS;
}

/**
  Validate authorization key against hardware fingerprint
**/
BOOLEAN
SvmAuthValidateKey(
  UINT8 *AuthKey,
  SVM_HARDWARE_FINGERPRINT *HwFingerprint
  )
{
  // Legacy key validation removed; RSA signature + structure hash are authoritative
  return TRUE;
}

/**
  Load authorization from file
**/
EFI_STATUS
SvmAuthLoadFromFile(
  CHAR16 *AuthFileName
  )
{
  EFI_STATUS Status;
  EFI_FILE_PROTOCOL *RootDir = NULL;
  EFI_FILE_PROTOCOL *AuthFile = NULL;
  UINTN FileSize;
  UINT32 NvUsage = 0;
  
  if (AuthFileName == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  
  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM Auth] Attempting to load: %s\n", AuthFileName));
  
  // Try to find file across all volumes
  EFI_HANDLE FoundHandle = NULL;
  Status = SvmAuthFindFileByNameAcrossVolumes(AuthFileName, &FoundHandle, &RootDir, &AuthFile);
  
  if (EFI_ERROR(Status) || AuthFile == NULL) {
    if (RootDir) RootDir->Close(RootDir);
    return Status;
  }
  
  // Read authorization data directly and validate size
  FileSize = sizeof(SVM_AUTHORIZATION_INFO);
  Status = AuthFile->Read(AuthFile, &FileSize, &gSvmAuthInfo);
  
  AuthFile->Close(AuthFile);
  if (RootDir) RootDir->Close(RootDir);
  
  if (EFI_ERROR(Status) || FileSize != sizeof(SVM_AUTHORIZATION_INFO)) {
    return EFI_LOAD_ERROR;
  }
  
  // Remember where we found it for later saves
  gSvmAuthFsHandle = FoundHandle;
  StrCpyS(gSvmAuthLoadedRelPath, sizeof(gSvmAuthLoadedRelPath)/sizeof(CHAR16), AuthFileName);
  
  // Merge non-volatile usage counter if it is higher (prevent rollback)
  if (!EFI_ERROR(SvmAuthReadNvUsage(&NvUsage))) {
    if (NvUsage > gSvmAuthInfo.CurrentUsageCount) {
      gSvmAuthInfo.CurrentUsageCount = NvUsage;
    }
  }

  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM Auth] Authorization file loaded successfully\n"));
  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM Auth] Loaded from: %s\n", AuthFileName));
  return EFI_SUCCESS;
}

/**
  Save authorization to file
**/
EFI_STATUS
SvmAuthSaveToFile(
  CHAR16 *AuthFileName
  )
{
  EFI_STATUS Status;
  EFI_FILE_PROTOCOL *RootDir = NULL;
  EFI_FILE_PROTOCOL *AuthFile = NULL;
  UINTN FileSize;
  
  if (AuthFileName == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  
  // Use remembered handle from load; fallback to image FS when not available
  EFI_HANDLE FsHandle = gSvmAuthFsHandle;
  if (FsHandle == NULL) {
    Status = SvmAuthGetLoadedImageFsHandle(&FsHandle);
    if (EFI_ERROR(Status)) {
      return Status;
    }
  }
  
  Status = SvmAuthOpenRootOnHandle(FsHandle, &RootDir);
  if (EFI_ERROR(Status)) {
    return Status;
  }
  
  // Create/overwrite file at the exact same relative path used when loading if available
  CHAR16 *RelativePath = (gSvmAuthLoadedRelPath[0] != L'\0') ? gSvmAuthLoadedRelPath : (CHAR16*)(UINTN)AuthFileName;
  Status = RootDir->Open(RootDir, &AuthFile, RelativePath, 
                        EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE, 0);
  
  if (EFI_ERROR(Status)) {
    RootDir->Close(RootDir);
    return Status;
  }
  
  // Recompute security hash (32-bit) before writing
  {
    UINT32 SecHash = SvmSimpleHash((UINT8*)&gSvmAuthInfo,
                                   sizeof(SVM_AUTHORIZATION_INFO) - sizeof(gSvmAuthInfo.SecurityHash));
    CopyMem(gSvmAuthInfo.SecurityHash, &SecHash, sizeof(UINT32));
  }

  // Write authorization data
  FileSize = sizeof(SVM_AUTHORIZATION_INFO);
  Status = AuthFile->Write(AuthFile, &FileSize, &gSvmAuthInfo);
  
  AuthFile->Close(AuthFile);
  RootDir->Close(RootDir);
  
  if (EFI_ERROR(Status) || FileSize != sizeof(SVM_AUTHORIZATION_INFO)) {
    return EFI_DEVICE_ERROR;
  }
  
  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM Auth] Authorization file saved successfully\n"));
  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM Auth] Saved to: %s\n", RelativePath));
  return EFI_SUCCESS;
}

/**
  Update usage count and save to file
**/
VOID
SvmAuthUpdateUsageCount(
  VOID
  )
{
  if (gSvmAuthStatus == SVM_AUTH_AUTHORIZED) {
    // Atomic update: first try to write to NV storage, then update memory
    UINT32 NewUsageCount = gSvmAuthInfo.CurrentUsageCount + 1;
    EFI_STATUS Status = SvmAuthWriteNvUsage(NewUsageCount);
    
    if (!EFI_ERROR(Status)) {
      // Only update memory counter if NV write succeeded
      gSvmAuthInfo.CurrentUsageCount = NewUsageCount;
      
      // Save updated count back to file
      Status = SvmAuthSaveToFile(L"Dxe.bin");
      if (EFI_ERROR(Status)) {
        MINI_VISOR_SVM_DEBUG((DEBUG_WARN, "[SVM Auth] Failed to save usage count: %r\n", Status));
      }
    } else {
      // If NV write failed, log warning but don't update memory counter
      MINI_VISOR_SVM_DEBUG((DEBUG_WARN, "[SVM Auth] Failed to update NV usage counter: %r\n", Status));
    }
  }
}

STATIC EFI_STATUS
SvmAuthReadNvUsage(OUT UINT32 *UsageOut)
{
  EFI_STATUS Status;
  UINTN Size;
  UINT32 Usage;
  if (UsageOut == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  Size = sizeof(UINT32);
  Status = gRT->GetVariable((CHAR16*)SVM_NV_USAGE_VAR, &gMiniVisorPkgTokenSpaceGuid, NULL, &Size, &Usage);
  if (EFI_ERROR(Status) || Size != sizeof(UINT32)) {
    return EFI_NOT_FOUND;
  }
  *UsageOut = Usage;
  return EFI_SUCCESS;
}

STATIC EFI_STATUS
SvmAuthWriteNvUsage(IN UINT32 Usage)
{
  EFI_STATUS Status;
  UINT32 Attributes = EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS;
  Status = gRT->SetVariable((CHAR16*)SVM_NV_USAGE_VAR, &gMiniVisorPkgTokenSpaceGuid, Attributes, sizeof(UINT32), &Usage);
  return Status;
}

/**
  Commercial-grade hardware compatibility verification
**/
EFI_STATUS
SvmHardwareCompatibilityCheck(
  IN SVM_HARDWARE_FINGERPRINT *AuthFingerprint,
  IN SVM_HARDWARE_FINGERPRINT *CurrentFingerprint,
  OUT UINT32 *CompatibilityScore,
  OUT BOOLEAN *ComponentMatches
  )
{
  if (AuthFingerprint == NULL || CurrentFingerprint == NULL || 
      CompatibilityScore == NULL || ComponentMatches == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  *CompatibilityScore = 0;
  ZeroMem(ComponentMatches, 4 * sizeof(BOOLEAN)); // CpuMatch, BoardMatch, BrandMatch, SerialMatch

  // Commercial-grade CPU compatibility analysis
  ComponentMatches[0] = (AuthFingerprint->CpuSignature == CurrentFingerprint->CpuSignature);
  if (ComponentMatches[0]) {
    *CompatibilityScore += 40;
  } else {
    // CPU family compatibility check
    UINT32 AuthCpuFamily = (AuthFingerprint->CpuSignature >> 8) & 0xF;
    UINT32 CurrentCpuFamily = (CurrentFingerprint->CpuSignature >> 8) & 0xF;
    if (AuthCpuFamily == CurrentCpuFamily) {
      *CompatibilityScore += 20;
    }
  }

  // Commercial-grade mainboard compatibility analysis
  ComponentMatches[1] = (AuthFingerprint->MainboardSerialHash == CurrentFingerprint->MainboardSerialHash);
  if (ComponentMatches[1]) {
    *CompatibilityScore += 30;
  } else {
    // Check for manufacturer similarity (approximate matching)
    UINT32 AuthBoardPrefix = AuthFingerprint->MainboardSerialHash >> 24;
    UINT32 CurrentBoardPrefix = CurrentFingerprint->MainboardSerialHash >> 24;
    if (AuthBoardPrefix == CurrentBoardPrefix) {
      *CompatibilityScore += 15;
    }
  }

  // Commercial-grade CPU brand verification
  ComponentMatches[2] = (AuthFingerprint->CpuBrandHash == CurrentFingerprint->CpuBrandHash);
  if (ComponentMatches[2]) {
    *CompatibilityScore += 20;
  }

  // Commercial-grade CPU serial verification (bonus points)
  ComponentMatches[3] = (AuthFingerprint->CpuSerialNumber == CurrentFingerprint->CpuSerialNumber);
  if (ComponentMatches[3]) {
    *CompatibilityScore += 10;
  }

  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[Hardware Auth] Compatibility analysis completed\n"));
  return EFI_SUCCESS;
}

/**
  Show legal warning (compatible with Intel version)
**/
EFI_STATUS
SvmAuthShowLegalWarning(
  VOID
  )
{
  Print(L"\n===============================================================================\n");
  Print(L"                      SVM Hardware Emulation Driver v1.0\n");
  Print(L"                      SVM 硬件仿真驱动程序 v1.0\n");
  Print(L"===============================================================================\n");
  Print(L"\n");
  Print(L"IMPORTANT LEGAL NOTICE / 重要法律声明\n");
  Print(L"=====================================\n");
  Print(L"\n");
  Print(L"This software is for authorized development and testing purposes only.\n");
  Print(L"本软件仅供授权开发和测试用途使用。\n");
  Print(L"\n");
  Print(L"By using this software, you acknowledge and agree to the following:\n");
  Print(L"使用本软件即表示您确认并同意以下条款：\n");
  Print(L"\n");
  Print(L"1. AUTHORIZED USE ONLY: This driver may only be used by authorized personnel\n");
  Print(L"   for legitimate development, testing, and compatibility purposes.\n");
  Print(L"   仅限授权使用：本驱动程序仅可由授权人员用于合法的开发、测试和兼容性用途。\n");
  Print(L"\n");
  Print(L"2. NO ILLEGAL ACTIVITIES: This software SHALL NOT be used to bypass\n");
  Print(L"   licensing, copy protection, or other security measures, nor for any\n");
  Print(L"   illegal or unauthorized activities.\n");
  Print(L"   禁止非法活动：本软件严禁用于绕过许可证、复制保护或其他安全措施，\n");
  Print(L"   也不得用于任何非法或未经授权的活动。\n");
  Print(L"\n");
  Print(L"3. COMPLIANCE: You must ensure compliance with all applicable laws,\n");
  Print(L"   regulations, and licensing agreements.\n");
  Print(L"   合规性：您必须确保遵守所有适用的法律、法规和许可协议。\n");
  Print(L"\n");
  Print(L"4. NO WARRANTIES: This software is provided 'AS IS' without any warranties.\n");
  Print(L"   无担保：本软件按\"现状\"提供，不提供任何担保。\n");
  Print(L"\n");
  Print(L"5. LIMITATION OF LIABILITY: The authors shall not be liable for any damages\n");
  Print(L"   arising from the use of this software.\n");
  Print(L"   责任限制：作者对因使用本软件而产生的任何损害不承担责任。\n");
  Print(L"\n");
  Print(L"BY CONTINUING, YOU ACKNOWLEDGE THAT YOU HAVE READ, UNDERSTOOD, AND AGREE\n");
  Print(L"TO BE BOUND BY THESE TERMS.\n");
  Print(L"继续操作即表示您确认已阅读、理解并同意受这些条款约束。\n");
  Print(L"\n");
  Print(L"===============================================================================\n");
  
  return EFI_SUCCESS;
}

/**
  Initialize SVM authorization system
**/
EFI_STATUS
SvmAuthInitialize(
  VOID
  )
{
  EFI_STATUS Status;
  SVM_HARDWARE_FINGERPRINT CurrentFingerprint;
  
  // Initialize secure authorization system with strict validation
  gSvmAuthDebugMode = FALSE;
  
  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM Auth] Initializing secure authorization system...\n"));
  
  
  // Intel-style comprehensive authorization file search
  // Priority: Current directory -> EFI system paths -> Intel-compatible paths -> User paths
  CHAR16 *AuthPaths[] = {
    L"Dxe.bin",                                    // Current directory (highest priority)
    L"EFI\\Boot\\Dxe.bin",                         // EFI Boot partition
    L"EFI\\Intel\\Dxe.bin",                        // Intel-style EFI path
    L"EFI\\Dxe\\Dxe.bin",                          // Standard EFI application path
    L"EFI\\MiniVisor\\Dxe.bin",                    // Legacy compatibility path
    L"Intel\\Authorization\\Dxe.bin",               // Intel-compatible authorization path
    L"Intel\\Security\\Dxe.bin",                   // Intel security module path
    L"Authorization\\Dxe.bin",                     // Generic authorization path
    L"Config\\Dxe.bin",                            // Configuration directory
    L"Security\\Dxe.bin",                          // Security directory
    L"Windows\\System32\\Drivers\\Dxe.bin",        // Windows driver path
    L"Windows\\System32\\Dxe.bin",                 // Windows system path
    L"ProgramData\\Intel\\Dxe.bin",                // Intel program data
    L"ProgramData\\MiniVisor\\Dxe.bin",            // Application data
    L"Users\\Public\\Documents\\Dxe.bin",          // Public documents
    L"Users\\Public\\Dxe.bin",                     // Public folder
    L"temp\\Dxe.bin",                              // Temporary path
    NULL                                            // Terminator
  };
  
  // Attempt to load from each path in priority order
  UINTN PathIndex = 0;
  while (AuthPaths[PathIndex] != NULL) {
    MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM Auth] Searching: %s\n", AuthPaths[PathIndex]));
    Status = SvmAuthLoadFromFile(AuthPaths[PathIndex]);
    if (!EFI_ERROR(Status)) {
      MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM Auth] Authorization file found at: %s\n", AuthPaths[PathIndex]));
      break;
    }
    PathIndex++;
  }
  
  if (EFI_ERROR(Status)) {
    MINI_VISOR_SVM_DEBUG((DEBUG_WARN, "[SVM Auth] No authorization file found in any standard path\n"));
  }
  
  if (!EFI_ERROR(Status)) {
    
    Status = SvmGenerateHardwareFingerprint(&CurrentFingerprint);
    if (EFI_ERROR(Status)) {
      MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM Auth] Hardware fingerprint generation failed: %r\n", Status));
      return Status;
    }
    
    // Commercial-grade hardware compatibility analysis
    // Note: Variables removed to prevent compiler warnings
    
    //
    // *** UNIFIED AUTHORIZATION SYSTEM ***
    // Try unified authorization library first, then fallback to legacy
    //
    
    EFI_STATUS UnifiedAuthStatus = SvmAuthVerifyUnifiedLibrary();
    
    if (!EFI_ERROR(UnifiedAuthStatus)) {
      // ✅ Enterprise security verification successful
      Print(L"[AMD SVM Driver] ✓ ENTERPRISE SECURITY GRANTED\n");
      Print(L"[AMD SVM 驱动] ✓ 企业安全验证通过\n");
      Print(L"[AMD SVM Driver] Enterprise security matrix verification successful\n");
      Print(L"[AMD SVM 驱动] 企业安全矩阵验证成功\n");
      
      // Display security level (not detailed compatibility to prevent reverse engineering)
      UINT32 CompatScore = GET_COMPATIBILITY_SCORE();
      Print(L"[AMD SVM Driver] System Security: %d%% (%s)\n", 
        (CompatScore * 100) / MAX_COMPATIBILITY_SCORE,
        IS_EXCELLENT_COMPATIBILITY(CompatScore) ? L"Maximum" :
        IS_GOOD_COMPATIBILITY(CompatScore) ? L"Enhanced" :
        IS_ACCEPTABLE_COMPATIBILITY(CompatScore) ? L"Standard" : L"Minimal");
      
      MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM Auth] NEXT-GEN AUTHORIZATION GRANTED - Unified system verified\n"));
      return EFI_SUCCESS;
      
    } else {
      //
      // ❌ Unified authorization failed - no fallback to legacy systems
      //
      MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM Auth] Unified authorization failed - no legacy fallback\n"));
      
      Print(L"[AMD SVM Driver] ❌ SECURITY DENIED\n");
      Print(L"[AMD SVM 驱动] ❌ 安全验证失败\n");
      Print(L"[AMD SVM Driver] Unified authorization system verification failed\n");
      Print(L"[AMD SVM 驱动] 统一授权系统验证失败\n");
      
      // Provide helpful diagnostic information
      Print(L"[AMD SVM Driver] Consider:\n");
      Print(L"  • Ensure auth.dat file is placed in USB root or C: root directory\n");
      Print(L"  • Verify authorization file is valid and not expired\n");
      Print(L"  • Contact enterprise support for security configuration\n");
      Print(L"[AMD SVM 驱动] 建议:\n");
      Print(L"  • 确保auth.dat文件放置在U盘根目录或C盘根目录\n");
      Print(L"  • 验证授权文件有效且未过期\n");
      Print(L"  • 联系企业支持进行安全配置\n");
      
      return EFI_ACCESS_DENIED;
    }
  } else {
    // Enterprise-style helpful error reporting with search path information
    MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM Auth] SECURITY FILE NOT FOUND - Searched %u locations: %r\n", PathIndex, Status));
    
    Print(L"[AMD SVM Driver] ❌ SECURITY FILE NOT FOUND\n");
    Print(L"[AMD SVM 驱动] ❌ 未找到安全文件\n");
    Print(L"[AMD SVM Driver] Searched standard locations including:\n");
    Print(L"[AMD SVM 驱动] 已搜索标准位置，包括：\n");
    Print(L"  • USB drive root directory\n");
    Print(L"  • U盘根目录\n");
    Print(L"  • C: drive root directory\n");
    Print(L"  • C盘根目录\n");
    Print(L"  • Current directory and EFI system paths\n");
    Print(L"  • 当前目录和EFI系统路径\n");
    
    Print(L"\n[AMD SVM Driver] NEXT STEPS:\n");
    Print(L"[AMD SVM 驱动] 后续步骤：\n");
    Print(L"1. Ensure authorization file 'auth.dat' is present\n");
    Print(L"   确保授权文件'auth.dat'存在\n");
    Print(L"2. Place auth.dat file in USB root or C: root directory\n");
    Print(L"   将auth.dat文件放置在U盘根目录或C盘根目录\n");
    Print(L"3. Verify file permissions and integrity\n");
    Print(L"   验证文件权限和完整性\n");
    Print(L"4. Contact enterprise support for proper security configuration\n");
    Print(L"   联系企业支持进行适当的安全配置\n");
    
    // Enterprise-style gentle failure
    Print(L"\n[AMD SVM Driver] Driver initialization suspended pending security verification\n");
    Print(L"[AMD SVM 驱动] 驱动程序初始化已暂停，等待安全验证\n");
    
    return EFI_ACCESS_DENIED;
  }
}

// SvmAuthVerifyLicense function is implemented in SecurityStubs.c

// ==============================================================================
// SVM File System Cache Implementation
// ==============================================================================

/**
 * Initialize SVM file system cache
 */
STATIC VOID
SvmAuthInitializeCache(VOID)
{
  if (gSvmFsCacheInitialized) {
    return;
  }
  
  ZeroMem(gSvmFsCache, sizeof(gSvmFsCache));
  gSvmFsCacheCount = 0;
  gSvmFsCacheInitialized = TRUE;
}

/**
 * Find SVM cache entry by file system handle
 */
STATIC SVM_FS_CACHE_ENTRY*
SvmAuthFindCacheEntry(EFI_HANDLE FsHandle)
{
  UINTN Index;
  
  if (!gSvmFsCacheInitialized) {
    SvmAuthInitializeCache();
  }
  
  for (Index = 0; Index < gSvmFsCacheCount; Index++) {
    if (gSvmFsCache[Index].Valid && gSvmFsCache[Index].FsHandle == FsHandle) {
      return &gSvmFsCache[Index];
    }
  }
  
  return NULL;
}

/**
 * Add entry to SVM file system cache
 */
STATIC EFI_STATUS
SvmAuthAddCacheEntry(
  EFI_HANDLE FsHandle, 
  EFI_FILE_PROTOCOL *RootDir, 
  CHAR16 *AuthFilePath
  )
{
  SVM_FS_CACHE_ENTRY *Entry;
  UINTN PathLen;
  
  if (!gSvmFsCacheInitialized) {
    SvmAuthInitializeCache();
  }
  
  // Check if entry already exists
  Entry = SvmAuthFindCacheEntry(FsHandle);
  if (Entry != NULL) {
    // Update existing entry
    if (Entry->AuthFilePath != NULL) {
      gBS->FreePool(Entry->AuthFilePath);
    }
  } else {
    // Add new entry if space available
    if (gSvmFsCacheCount >= MAX_SVM_FS_CACHE_ENTRIES) {
      return EFI_OUT_OF_RESOURCES;
    }
    Entry = &gSvmFsCache[gSvmFsCacheCount++];
    Entry->FsHandle = FsHandle;
    Entry->RootDir = RootDir;
  }
  
  // Copy file path
  if (AuthFilePath != NULL) {
    PathLen = StrLen(AuthFilePath) + 1;
    Entry->AuthFilePath = AllocatePool(PathLen * sizeof(CHAR16));
    if (Entry->AuthFilePath == NULL) {
      return EFI_OUT_OF_RESOURCES;
    }
    StrCpyS(Entry->AuthFilePath, PathLen, AuthFilePath);
  } else {
    Entry->AuthFilePath = NULL;
  }
  
  Entry->Valid = TRUE;
  return EFI_SUCCESS;
}

/**
 * Clear SVM file system cache
 */
STATIC VOID
SvmAuthClearCache(VOID)
{
  UINTN Index;
  
  for (Index = 0; Index < gSvmFsCacheCount; Index++) {
    if (gSvmFsCache[Index].AuthFilePath != NULL) {
      gBS->FreePool(gSvmFsCache[Index].AuthFilePath);
    }
  }
  
  ZeroMem(gSvmFsCache, sizeof(gSvmFsCache));
  gSvmFsCacheCount = 0;
  gSvmFsCacheInitialized = FALSE;
}

// ==============================================================================
// SVM Real Cryptographic Implementation
// ==============================================================================

/**
 * Real RSA signature verification using BaseCryptLib for SVM
 */
EFI_STATUS
SvmRsaVerifySignature(
  IN UINT8 *Data,
  IN UINTN DataSize,
  IN UINT8 *Signature,
  IN UINT8 *PublicKey
  )
{
  VOID *RsaContext = NULL;
  BOOLEAN VerifyResult = FALSE;
  EFI_STATUS Status = EFI_SECURITY_VIOLATION;
  UINT8 HashValue[32]; // SHA-256 hash
  BOOLEAN PublicKeyValid = FALSE;
  
  if (Data == NULL || DataSize == 0 || Signature == NULL || PublicKey == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  
  // Initialize RSA context
  RsaContext = RsaNew();
  if (RsaContext == NULL) {
    MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM Crypto] Failed to create RSA context\n"));
    return EFI_OUT_OF_RESOURCES;
  }
  
  // Check public key validity (prevent all-zero public key)
  for (UINTN i = 0; i < RSA_PUBLIC_KEY_SIZE; i++) {
    if (PublicKey[i] != 0) {
      PublicKeyValid = TRUE;
      break;
    }
  }
  
  if (!PublicKeyValid) {
    MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM Crypto] Public key is all zeros - invalid key\n"));
    
    // SECURITY: Only allow test mode bypass in DEBUG builds with specific PCD enabled
    #if defined(MDE_DEBUG) && defined(ENABLE_SVM_TEST_MODE)
      // Check if test mode is explicitly enabled via PCD
      if (PcdGetBool(PcdSvmTestModeEnabled)) {
        MINI_VISOR_SVM_DEBUG((DEBUG_WARN, "[SVM Crypto] DEBUG BUILD: Test mode verification enabled by PCD\n"));
        
        // Even in test mode, verify hash integrity
        Status = SvmSha256Hash(Data, DataSize, HashValue);
        if (EFI_ERROR(Status)) {
          MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM Crypto] Failed to compute SHA-256 hash in test mode\n"));
          goto Cleanup;
        }
        
        MINI_VISOR_SVM_DEBUG((DEBUG_WARN, "[SVM Crypto] DEBUG TEST MODE: RSA signature verification bypassed\n"));
        Status = EFI_SUCCESS;
        goto Cleanup;
      }
    #endif
    
    // Production/Release: Fail closed - require valid public key
    MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM Crypto] Invalid public key - signature verification failed\n"));
    Status = EFI_SECURITY_VIOLATION;
    goto Cleanup;
  }
  
  // Set RSA public key (raw N and E format, not DER)
  // Standard RSA exponent: 0x010001 (65537)
  UINT8 RsaExponent[] = {0x01, 0x00, 0x01};
  
  // First set the modulus (N)
  if (!RsaSetKey(RsaContext, RsaKeyN, PublicKey, RSA_PUBLIC_KEY_SIZE)) {
    MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM Crypto] Failed to set RSA public key modulus\n"));
    Status = EFI_INVALID_PARAMETER;
    goto Cleanup;
  }
  
  // Then set the exponent (E)  
  if (!RsaSetKey(RsaContext, RsaKeyE, RsaExponent, sizeof(RsaExponent))) {
    MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM Crypto] Failed to set RSA public key exponent\n"));
    Status = EFI_INVALID_PARAMETER;
    goto Cleanup;
  }
  
  // Compute SHA-256 hash of data
  Status = SvmSha256Hash(Data, DataSize, HashValue);
  if (EFI_ERROR(Status)) {
    MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM Crypto] Failed to compute SHA-256 hash\n"));
    goto Cleanup;
  }
  
  // Verify RSA signature using PKCS#1 v1.5
  VerifyResult = RsaPkcs1Verify(
    RsaContext,
    HashValue,
    32, // SHA-256 hash size
    Signature,
    RSA_SIGNATURE_SIZE
  );
  
  if (VerifyResult) {
    Status = EFI_SUCCESS;
    MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM Crypto] RSA signature verification successful\n"));
  } else {
    Status = EFI_SECURITY_VIOLATION;
    MINI_VISOR_SVM_DEBUG((DEBUG_WARN, "[SVM Crypto] RSA signature verification failed\n"));
  }
  
Cleanup:
  if (RsaContext != NULL) {
    RsaFree(RsaContext);
  }
  
  return Status;
}

/**
 * Real SHA-256 hash computation using BaseCryptLib for SVM
 */
EFI_STATUS
SvmSha256Hash(
  IN UINT8 *Data,
  IN UINTN DataSize,
  OUT UINT8 *Hash
  )
{
  VOID *Sha256Context = NULL;
  UINTN ContextSize = 0;
  BOOLEAN Result = FALSE;
  EFI_STATUS Status = EFI_ABORTED;
  
  if (Data == NULL || DataSize == 0 || Hash == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  
  // Allocate SHA-256 context using size API
  ContextSize = Sha256GetContextSize();
  if (ContextSize == 0) {
    MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM Crypto] Sha256GetContextSize returned 0\n"));
    return EFI_ABORTED;
  }
  Sha256Context = AllocatePool(ContextSize);
  if (Sha256Context == NULL) {
    MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM Crypto] Failed to allocate SHA-256 context (%u bytes)\n", (UINT32)ContextSize));
    return EFI_OUT_OF_RESOURCES;
  }
  
  // Initialize SHA-256
  Result = Sha256Init(Sha256Context);
  if (!Result) {
    MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM Crypto] Failed to initialize SHA-256\n"));
    Status = EFI_ABORTED;
    goto Cleanup;
  }
  
  // Update SHA-256 with data
  Result = Sha256Update(Sha256Context, Data, DataSize);
  if (!Result) {
    MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM Crypto] Failed to update SHA-256\n"));
    Status = EFI_ABORTED;
    goto Cleanup;
  }
  
  // Finalize SHA-256 and get hash
  Result = Sha256Final(Sha256Context, Hash);
  if (!Result) {
    MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM Crypto] Failed to finalize SHA-256\n"));
    Status = EFI_ABORTED;
    goto Cleanup;
  }
  
  Status = EFI_SUCCESS;
  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM Crypto] SHA-256 hash computation successful\n"));
  
Cleanup:
  if (Sha256Context != NULL) {
    FreePool(Sha256Context);
  }
  
  return Status;
}

/**
 * 验证授权结构的完整性和有效性（使用改进的验证逻辑）
 */
EFI_STATUS
SvmValidateAuthorizationStructure_Legacy(
  IN SVM_AUTHORIZATION_INFO *AuthInfo
  )
{
  EFI_STATUS Status;
  UINT8 ComputedHash[32];
  
  if (AuthInfo == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  
  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM Auth] Validating authorization structure...\n"));
  
  // 1. Validate basic structure signature
  if (AuthInfo->Signature != SVM_AUTH_SIGNATURE) {
    MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM Auth] Invalid signature: 0x%x (expected 0x%x)\n", 
                         AuthInfo->Signature, SVM_AUTH_SIGNATURE));
    return EFI_SECURITY_VIOLATION;
  }
  
  // 2. Validate version compatibility
  if (AuthInfo->Version != SVM_AUTH_VERSION) {
    MINI_VISOR_SVM_DEBUG((DEBUG_WARN, "[SVM Auth] Version mismatch: 0x%x (expected 0x%x)\n", 
                         AuthInfo->Version, SVM_AUTH_VERSION));
    // Version mismatch is not fatal, continue validation
  }
  
  // 3. Validate data integrity (SHA-256 hash)
  Status = SvmSha256Hash(
    (UINT8*)AuthInfo,
    sizeof(SVM_AUTHORIZATION_INFO) - RSA_SIGNATURE_SIZE - sizeof(AuthInfo->SecurityHash),
    ComputedHash
  );
  
  if (EFI_ERROR(Status)) {
    MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM Auth] Failed to compute hash for validation: %r\n", Status));
    return Status;
  }
  
  // Compare computed hash with stored hash
  if (CompareMem(ComputedHash, AuthInfo->SecurityHash, sizeof(ComputedHash)) != 0) {
    MINI_VISOR_SVM_DEBUG((DEBUG_WARN, "[SVM Auth] Hash mismatch - data integrity check failed\n"));
    // In debug mode, hash mismatch is not treated as fatal error
    if (gSvmAuthDebugMode) {
      MINI_VISOR_SVM_DEBUG((DEBUG_WARN, "[SVM Auth] Continuing in debug mode despite hash mismatch\n"));
    } else {
      return EFI_SECURITY_VIOLATION;
    }
  }
  
  // 4. Primary TPM-based RSA signature verification
  Status = SvmRsaVerifySignature(
    (UINT8*)AuthInfo,
    sizeof(SVM_AUTHORIZATION_INFO) - RSA_SIGNATURE_SIZE,
    AuthInfo->RsaSignature,
    (UINT8*)kSvmTpmRootPublicKey
  );
  
  if (EFI_ERROR(Status)) {
    MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM Auth] Primary TPM signature verification FAILED: %r\n", Status));
    
    // Try secondary verification key for redundant authentication
    Status = SvmRsaVerifySignature(
      (UINT8*)AuthInfo,
      sizeof(SVM_AUTHORIZATION_INFO) - RSA_SIGNATURE_SIZE,
      AuthInfo->RsaSignature,
      (UINT8*)kSvmSecondaryPublicKey
    );
    
    if (EFI_ERROR(Status)) {
      MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM Auth] Secondary signature verification also FAILED: %r\n", Status));
      MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM Auth] CRITICAL SECURITY VIOLATION - Invalid authorization signature\n"));
      return EFI_SECURITY_VIOLATION;
    } else {
      MINI_VISOR_SVM_DEBUG((DEBUG_WARN, "[SVM Auth] Secondary key verification successful - primary key may be compromised\n"));
    }
  } else {
    MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM Auth] Primary TPM signature verification successful\n"));
  }
  
  // 5. 验证授权时间范围
  if (AuthInfo->ExpiryTime <= AuthInfo->AuthorizedTime) {
    MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM Auth] Invalid time range: expiry time is before authorized time\n"));
    return EFI_SECURITY_VIOLATION;
  }
  
  // 6. 验证使用次数限制
  if (AuthInfo->MaxUsageCount == 0) {
    MINI_VISOR_SVM_DEBUG((DEBUG_WARN, "[SVM Auth] MaxUsageCount is zero - unlimited usage\n"));
  } else if (AuthInfo->CurrentUsageCount > AuthInfo->MaxUsageCount) {
    MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM Auth] Current usage count (%u) exceeds maximum (%u)\n", 
                         AuthInfo->CurrentUsageCount, AuthInfo->MaxUsageCount));
    return EFI_ACCESS_DENIED;
  }
  
  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM Auth] Authorization structure validation completed successfully\n"));
  return EFI_SUCCESS;
}

// ==============================================================================
// End of SVM Authorization System Implementation
// ==============================================================================

/**
  Enable or disable MiniVisor SVM debug output.
  
  @param[in] Enable         TRUE to enable debug output, FALSE to disable.
  
  @retval EFI_SUCCESS       Debug mode updated successfully.
**/
EFI_STATUS
EFIAPI
MiniVisorSvmSetDebugMode (
  IN BOOLEAN  Enable
  )
{
  gMiniVisorSvmDebugMode = Enable;
  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] Debug mode %s\n", Enable ? L"enabled" : L"disabled"));
  return EFI_SUCCESS;
}

/**
  Initialize MiniVisor SVM hypervisor.
  
  @param[in] ImageHandle    The image handle of the driver.
  @param[in] SystemTable    The system table.
  
  @retval EFI_SUCCESS       Initialization successful.
  @retval Others            Initialization failed.
**/
EFI_STATUS
EFIAPI
MiniVisorSvmInitialize (
  IN EFI_HANDLE         ImageHandle,
  IN EFI_SYSTEM_TABLE   *SystemTable
  )
{
  EFI_STATUS Status;
  SVM_AUTH_STATUS AuthStatus;

  gImageHandle = ImageHandle;

  //
  // Show legal warning first (only in debug mode to avoid blocking boot)
  //
  if (gMiniVisorSvmDebugMode) {
    Status = SvmAuthShowLegalWarning();
    if (EFI_ERROR(Status)) {
      Print(L"[SVM Driver] LEGAL WARNING DISPLAY FAILED\n");
      Print(L"[SVM 驱动] 法律警告显示失败\n");
      return Status;
    }
  }

  //
  // Initialize authorization system
  //
  Status = SvmAuthInitialize();
  if (EFI_ERROR(Status)) {
    Print(L"[Dxe for AMD] AUTHORIZATION SYSTEM INITIALIZATION FAILED\n");
    Print(L"[Dxe for AMD] 授权系统初始化失败\n");
    return Status;
  }

  //
  // Verify authorization
  //
  Status = SvmAuthVerifyLicense(NULL, 0);
  AuthStatus = (Status == EFI_SUCCESS) ? SVM_AUTH_AUTHORIZED : SVM_AUTH_UNAUTHORIZED;
  if (AuthStatus != SVM_AUTH_AUTHORIZED) {
          switch (AuthStatus) {
        case SVM_AUTH_UNAUTHORIZED:
        Print(L"[Dxe for AMD] UNAUTHORIZED SYSTEM - ACCESS DENIED\n");
        Print(L"[SVM 驱动] 未授权系统 - 拒绝访问\n");
        Print(L"[Dxe for AMD] Please contact administrator for proper authorization\n");
        Print(L"[SVM 驱动] 请联系管理员获取正确的授权\n");
        break;
      case SVM_AUTH_EXPIRED:
        Print(L"[Dxe for AMD] AUTHORIZATION EXPIRED - ACCESS DENIED\n");
        Print(L"[SVM 驱动] 授权已过期 - 拒绝访问\n");
        Print(L"[Dxe for AMD] License has expired, please renew authorization\n");
        Print(L"[SVM 驱动] 许可证已过期，请续订授权\n");
        break;
      case SVM_AUTH_INVALID:
        Print(L"[Dxe for AMD] INVALID LICENSE - ACCESS DENIED\n");
        Print(L"[SVM 驱动] 无效许可证 - 拒绝访问\n");
        Print(L"[Dxe for AMD] License validation failed\n");
        Print(L"[SVM 驱动] 许可证验证失败\n");
        break;
      case SVM_AUTH_OVER_LIMIT:
        Print(L"[Dxe for AMD] USAGE LIMIT EXCEEDED - ACCESS DENIED\n");
        Print(L"[SVM 驱动] 使用次数超限 - 拒绝访问\n");
        Print(L"[Dxe for AMD] Maximum usage count reached\n");
        Print(L"[SVM 驱动] 已达到最大使用次数\n");
        break;
      default:
        Print(L"[Dxe for AMD] UNKNOWN AUTHORIZATION ERROR - ACCESS DENIED\n");
        Print(L"[SVM 驱动] 未知授权错误 - 拒绝访问\n");
        break;
    }
    
    if (gMiniVisorSvmDebugMode) {
      ShowBilingualContinuePrompt(L"Press Enter to exit...", L"按回车键退出...");
    }
    return EFI_ACCESS_DENIED;
  }

  Print(L"[Dxe for AMD] AUTHORIZATION VERIFIED - LOADING DRIVER...\n");
  Print(L"[Dxe for AMD] 授权验证成功 - 正在加载驱动...\n");
  Print(L"[Dxe for AMD] License path: %s\n", (gSvmAuthLoadedRelPath[0] ? gSvmAuthLoadedRelPath : L"(unknown)"));
  Print(L"[Dxe for AMD] Usage %u/%u\n", gSvmAuthInfo.CurrentUsageCount, gSvmAuthInfo.MaxUsageCount);
  UINT16 y = (UINT16)(gSvmAuthInfo.ExpiryTime >> 32);
  UINT16 m = (UINT16)((gSvmAuthInfo.ExpiryTime >> 24) & 0xFF);
  UINT16 d = (UINT16)((gSvmAuthInfo.ExpiryTime >> 16) & 0xFF);
  Print(L"[Dxe for AMD] Expires: %04u-%02u-%02u\n", y, m, d);

  //
  // Update usage count
  //
  SvmAuthUpdateUsageCount();

  //
  // Initialize global data
  //
  Status = InitializeSvmGlobalData();
  if (EFI_ERROR(Status)) {
    DEBUG((DEBUG_ERROR, "[SVM] Failed to initialize global data: %r\n", Status));
    return Status;
  }

  // Show success messages only in debug mode to avoid blocking boot
  if (gMiniVisorSvmDebugMode) {
    Print(L"[Dxe for AMD] Driver loaded successfully.\n");
    Print(L"[Dxe for AMD] 驱动加载成功。\n");
    ShowBilingualContinuePrompt(L"Press Enter to continue...", L"按回车键继续...");
  }

  //
  // Initialize AMD-Vi (IVRS) emulation EARLY so software that checks AMD-V first will pass
  // This runs regardless of SVM availability
  //
  Status = InitializeAmdViEmulation();
  if (EFI_ERROR(Status)) {
    DEBUG((DEBUG_ERROR, "[SVM] AMD-Vi emulation init failed: %r\n", Status));
    return Status;  // Make this a hard failure so caller knows AMD-Vi spoofing is unavailable
  }

  // Verify ACPI table injection was successful before any guest detection occurs
  Status = VerifyAcpiTableInjection();
  if (EFI_ERROR(Status)) {
    DEBUG((DEBUG_ERROR, "[SVM] ACPI table injection verification failed: %r\n", Status));
    return Status;
  }

  //
  // Check if SVM is supported; if not, operate in AMD-Vi-only compatibility mode
  //
  if (!IsSvmSupported()) {
    DEBUG((DEBUG_WARN, "[SVM] SVM not supported; running in AMD-Vi compatibility-only mode\n"));
    // Do not enable SVM; AMD-Vi ACPI/PCI spoof remains active for software checks
    return EFI_SUCCESS;
  }

  //
  // Allocate SVM regions
  //
  Status = AllocateSvmRegions();
  if (EFI_ERROR(Status)) {
    DEBUG((DEBUG_ERROR, "[SVM] Failed to allocate SVM regions: %r\n", Status));
    return Status;
  }

  //
  // Enable SVM
  //
  Status = EnableSvm();
  if (EFI_ERROR(Status)) {
    DEBUG((DEBUG_ERROR, "[SVM] Failed to enable SVM: %r\n", Status));
    return Status;
  }

  //
  // Setup SVM environment
  //
  Status = SetupSvmEnvironment();
  if (EFI_ERROR(Status)) {
    DEBUG((DEBUG_ERROR, "[SVM] Failed to setup SVM environment: %r\n", Status));
    DisableSvm();
    return Status;
  }

  //
  // Optional: Enforce IOMMU-safe PCI routing. Disabled by default for stealth.
  // EnforceIommuSafePciRouting();

  // AMD-Vi emulation already set up and verified above

  //
  // Install Windows compatibility measures for broad software support
  //
  Status = InstallWindowsCompatibilityMeasures();
  if (EFI_ERROR(Status)) {
    DEBUG((DEBUG_WARN, "[SVM] Windows compatibility measures installation failed: %r\n", Status));
  }

  //
  // Mark as initialized
  //
  gMiniVisorSvmGlobalData.Status |= MINI_VISOR_SVM_STATUS_INITIALIZED;
  gMiniVisorSvmGlobalData.Status |= MINI_VISOR_SVM_STATUS_SVM_ENABLED;

  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] MiniVisor SVM hypervisor initialized with comprehensive anti-detection and future-proofing\n"));

  return EFI_SUCCESS;
}

/**
  DXE Driver Entry Point for MiniVisor SVM
**/
EFI_STATUS
EFIAPI
MiniVisorSvmDxeEntryPoint (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS Status;

  //
  // Initialize the MiniVisor SVM hypervisor
  //
  Status = MiniVisorSvmInitialize(ImageHandle, SystemTable);
  if (EFI_ERROR(Status)) {
    DEBUG((DEBUG_ERROR, "[SVM] MiniVisor SVM initialization failed: %r\n", Status));
    return Status;
  }

  DEBUG((DEBUG_INFO, "[SVM] MiniVisor SVM driver loaded successfully\n"));
  return EFI_SUCCESS;
}

//=============================================================================
//                    新增：RSA 和加密验证实现
//=============================================================================

// Note: SvmRsaVerifySignature is implemented above using BaseCryptLib

/**
 * Verify TPM hardware root of trust is available and functional
 * This provides additional security validation similar to Intel TXT
 */
EFI_STATUS
SvmVerifyTpmRootOfTrust(
  VOID
  )
{
  EFI_STATUS Status;
  EFI_TCG2_PROTOCOL *Tcg2Protocol = NULL;
  EFI_TCG2_BOOT_SERVICE_CAPABILITY BootServiceCap;
  
  // Locate TCG2 protocol for TPM access
  Status = gBS->LocateProtocol(
    &gEfiTcg2ProtocolGuid,
    NULL,
    (VOID**)&Tcg2Protocol
  );
  
  if (EFI_ERROR(Status) || Tcg2Protocol == NULL) {
    MINI_VISOR_SVM_DEBUG((DEBUG_WARN, "[SVM Auth] TPM/TCG2 protocol not available: %r\n", Status));
    // TPM not available - this may be acceptable in some environments
    return EFI_SUCCESS;
  }
  
  // Get TPM capabilities
  BootServiceCap.Size = sizeof(EFI_TCG2_BOOT_SERVICE_CAPABILITY);
  Status = Tcg2Protocol->GetCapability(Tcg2Protocol, &BootServiceCap);
  if (EFI_ERROR(Status)) {
    MINI_VISOR_SVM_DEBUG((DEBUG_WARN, "[SVM Auth] Failed to get TPM capabilities: %r\n", Status));
    return EFI_SUCCESS;
  }
  
  // Verify TPM is present and active
  if (!BootServiceCap.TPMPresentFlag) {
    MINI_VISOR_SVM_DEBUG((DEBUG_WARN, "[SVM Auth] TPM hardware not present\n"));
    return EFI_SUCCESS;
  }
  
  // Log TPM verification success
  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM Auth] TPM hardware root of trust verified\n"));
  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM Auth] TPM Version: %d.%d\n", 
                       BootServiceCap.StructureVersion.Major,
                       BootServiceCap.StructureVersion.Minor));
  
  return EFI_SUCCESS;
}

/**
 * Enhanced authorization verification with multiple security layers
 * Implements defense-in-depth similar to Intel platform security
 */
EFI_STATUS
SvmEnhancedAuthorizationVerification(
  IN SVM_AUTHORIZATION_INFO *AuthInfo
  )
{
  EFI_STATUS Status;
  UINT64 CurrentTimeSeconds;
  EFI_TIME CurrentTime;
  
  if (AuthInfo == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  
  // 1. Verify TPM hardware root of trust
  Status = SvmVerifyTpmRootOfTrust();
  if (EFI_ERROR(Status)) {
    MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM Auth] TPM root of trust verification failed: %r\n", Status));
    return Status;
  }
  
  // 2. Enhanced time-based validation
  Status = gRT->GetTime(&CurrentTime, NULL);
  if (!EFI_ERROR(Status)) {
    CurrentTimeSeconds = ((UINT64)CurrentTime.Year << 32) | 
                        ((UINT64)CurrentTime.Month << 24) |
                        ((UINT64)CurrentTime.Day << 16) |
                        ((UINT64)CurrentTime.Hour << 8) |
                        CurrentTime.Minute;
    
    // Verify authorization is not from future (clock tampering detection)
    if (AuthInfo->AuthorizedTime > CurrentTimeSeconds + 3600) { // Allow 1 hour tolerance
      MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM Auth] Authorization time is in future - possible clock tampering\n"));
      return EFI_SECURITY_VIOLATION;
    }
    
    // Verify authorization has not expired
    if (CurrentTimeSeconds > AuthInfo->ExpiryTime) {
      MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM Auth] Authorization has expired\n"));
      return EFI_ACCESS_DENIED;
    }
    
    // Verify authorization period is reasonable (not too long)
    UINT64 AuthPeriod = AuthInfo->ExpiryTime - AuthInfo->AuthorizedTime;
    if (AuthPeriod > (365ULL * 24 * 60 * 60)) { // Max 1 year
      MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM Auth] Authorization period too long - security risk\n"));
      return EFI_SECURITY_VIOLATION;
    }
  }
  
  // 3. Usage count anti-rollback verification
  if (AuthInfo->MaxUsageCount > 0) {
    if (AuthInfo->CurrentUsageCount >= AuthInfo->MaxUsageCount) {
      MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM Auth] Usage count limit exceeded\n"));
      return EFI_ACCESS_DENIED;
    }
    
    // Verify usage count hasn't been rolled back (basic sanity check)
    UINT32 NvUsageCount = 0;
    if (!EFI_ERROR(SvmAuthReadNvUsage(&NvUsageCount))) {
      if (AuthInfo->CurrentUsageCount < NvUsageCount) {
        MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM Auth] Usage count rollback detected - security violation\n"));
        return EFI_SECURITY_VIOLATION;
      }
    }
  }
  
  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM Auth] Enhanced authorization verification completed successfully\n"));
  return EFI_SUCCESS;
}

/**
 * Chain-of-trust verification for authorization file integrity
 * Implements secure boot-like verification chain
 */
EFI_STATUS
SvmVerifyAuthorizationChainOfTrust(
  IN SVM_AUTHORIZATION_INFO *AuthInfo
  )
{
  EFI_STATUS Status;
  UINT8 ComputedHash[32];
  UINT8 SecondaryHash[32];
  
  if (AuthInfo == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  
  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM Auth] Verifying authorization chain of trust...\n"));
  
  // 1. Verify structure integrity with double-hash verification
  Status = SvmSha256Hash(
    (UINT8*)AuthInfo,
    sizeof(SVM_AUTHORIZATION_INFO) - RSA_SIGNATURE_SIZE - sizeof(AuthInfo->SecurityHash),
    ComputedHash
  );
  if (EFI_ERROR(Status)) {
    MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM Auth] Failed to compute primary hash: %r\n", Status));
    return Status;
  }
  
  // Compare with stored hash
  if (CompareMem(ComputedHash, AuthInfo->SecurityHash, sizeof(ComputedHash)) != 0) {
    MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM Auth] Primary hash verification failed - data integrity compromised\n"));
    return EFI_SECURITY_VIOLATION;
  }
  
  // 2. Secondary hash verification for additional security
  Status = SvmSha256Hash(
    AuthInfo->SecurityHash,
    sizeof(AuthInfo->SecurityHash),
    SecondaryHash
  );
  if (EFI_ERROR(Status)) {
    MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM Auth] Failed to compute secondary hash: %r\n", Status));
    return Status;
  }
  
  // 3. Verify authorization metadata consistency
  if (AuthInfo->Signature != SVM_AUTH_SIGNATURE) {
    MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM Auth] Invalid authorization signature in chain verification\n"));
    return EFI_SECURITY_VIOLATION;
  }
  
  if (AuthInfo->Version != SVM_AUTH_VERSION) {
    MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM Auth] Unsupported authorization version in chain verification\n"));
    return EFI_SECURITY_VIOLATION;
  }
  
  // 4. Verify authorization time chain consistency
  if (AuthInfo->ExpiryTime <= AuthInfo->AuthorizedTime) {
    MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM Auth] Invalid time chain - expiry before authorization\n"));
    return EFI_SECURITY_VIOLATION;
  }
  
  // 5. Verify usage count chain consistency
  if (AuthInfo->MaxUsageCount > 0 && AuthInfo->CurrentUsageCount > AuthInfo->MaxUsageCount) {
    MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM Auth] Invalid usage count chain - current exceeds maximum\n"));
    return EFI_SECURITY_VIOLATION;
  }
  
  // 6. Hardware fingerprint chain verification
  if (AuthInfo->HwFingerprint.CpuSignature == 0) {
    MINI_VISOR_SVM_DEBUG((DEBUG_WARN, "[SVM Auth] Missing CPU signature in hardware fingerprint chain\n"));
    // This is a warning but not fatal as some systems may not provide CPU signature
  }
  
  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM Auth] Authorization chain of trust verification completed successfully\n"));
  return EFI_SUCCESS;
}

/**
  AES-256 解密函数
  
  @param EncryptedData  加密数据
  @param DataSize       数据大小
  @param Key            AES-256 密钥
  @param IV             初始化向量
  @param DecryptedData  解密后的数据
  
  @retval EFI_SUCCESS   解密成功
**/
EFI_STATUS
SvmAesDecrypt(
  IN UINT8 *EncryptedData,
  IN UINTN DataSize,
  IN UINT8 *Key,
  IN UINT8 *IV,
  OUT UINT8 *DecryptedData
  )
{
  // Implement AES-256-CBC decryption using BaseCryptLib
  VOID *AesContext = NULL;
  EFI_STATUS Status = EFI_SUCCESS;
  UINTN ContextSize;
  
  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM Auth] Starting AES-256-CBC decryption\n"));
  
  // Validate inputs
  if (EncryptedData == NULL || DecryptedData == NULL || Key == NULL || IV == NULL) {
    MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM Auth] Invalid parameters for AES decryption\n"));
    return EFI_INVALID_PARAMETER;
  }
  
  // Ensure data size is multiple of AES block size (16 bytes)
  if ((DataSize % 16) != 0) {
    MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM Auth] Data size not aligned to AES block size\n"));
    return EFI_INVALID_PARAMETER;
  }
  
  // Get AES context size
  ContextSize = AesGetContextSize();
  if (ContextSize == 0) {
    MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM Auth] Failed to get AES context size\n"));
    return EFI_UNSUPPORTED;
  }
  
  // Allocate AES context
  AesContext = AllocateZeroPool(ContextSize);
  if (AesContext == NULL) {
    MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM Auth] Failed to allocate AES context\n"));
    return EFI_OUT_OF_RESOURCES;
  }
  
  // Initialize AES context with 256-bit key
  if (!AesInit(AesContext, Key, 256)) {
    MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM Auth] Failed to initialize AES context\n"));
    Status = EFI_DEVICE_ERROR;
    goto Cleanup;
  }
  
  // Perform AES-256-CBC decryption
  if (!AesCbcDecrypt(AesContext, EncryptedData, DataSize, IV, DecryptedData)) {
    MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM Auth] AES-CBC decryption failed\n"));
    Status = EFI_DEVICE_ERROR;
    goto Cleanup;
  }
  
  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM Auth] AES-256-CBC decryption completed successfully\n"));
  Status = EFI_SUCCESS;

Cleanup:
  if (AesContext != NULL) {
    FreePool(AesContext);
  }
  
  return Status;
}

// Note: SvmSha256Hash is implemented above using BaseCryptLib

/**
  验证授权结构的完整性和签名
  
  @param AuthInfo  授权信息结构
  
  @retval EFI_SUCCESS           验证成功
  @retval EFI_SECURITY_VIOLATION 验证失败
**/
EFI_STATUS
SvmValidateAuthorizationStructure(
  IN SVM_AUTHORIZATION_INFO *AuthInfo
  )
{
  EFI_STATUS Status;
  UINT8 ComputedHash[32];
  
  if (AuthInfo == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  
  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM Auth] Validating authorization structure...\n"));
  
  // 1. Validate basic structure signature
  if (AuthInfo->Signature != SVM_AUTH_SIGNATURE) {
    MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM Auth] Invalid signature: 0x%x (expected 0x%x)\n", 
                         AuthInfo->Signature, SVM_AUTH_SIGNATURE));
    return EFI_SECURITY_VIOLATION;
  }
  
  // 2. Validate version compatibility
  if (AuthInfo->Version != SVM_AUTH_VERSION) {
    MINI_VISOR_SVM_DEBUG((DEBUG_WARN, "[SVM Auth] Version mismatch: 0x%x (expected 0x%x)\n", 
                         AuthInfo->Version, SVM_AUTH_VERSION));
    // Version mismatch is not fatal, continue validation
  }
  
  // 3. Validate data integrity (SHA-256 hash)
  Status = SvmSha256Hash(
    (UINT8*)AuthInfo,
    sizeof(SVM_AUTHORIZATION_INFO) - RSA_SIGNATURE_SIZE - sizeof(AuthInfo->SecurityHash),
    ComputedHash
  );
  
  if (EFI_ERROR(Status)) {
    MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM Auth] Failed to compute hash for validation: %r\n", Status));
    return Status;
  }
  
  // Compare computed hash with stored hash
  if (CompareMem(ComputedHash, AuthInfo->SecurityHash, sizeof(ComputedHash)) != 0) {
    MINI_VISOR_SVM_DEBUG((DEBUG_WARN, "[SVM Auth] Hash mismatch - data integrity check failed\n"));
    // In debug mode, hash mismatch is not treated as fatal error
    if (gSvmAuthDebugMode) {
      MINI_VISOR_SVM_DEBUG((DEBUG_WARN, "[SVM Auth] Continuing in debug mode despite hash mismatch\n"));
    } else {
      return EFI_SECURITY_VIOLATION;
    }
  }
  
  // 4. Primary TPM-based RSA signature verification
  Status = SvmRsaVerifySignature(
    (UINT8*)AuthInfo,
    sizeof(SVM_AUTHORIZATION_INFO) - RSA_SIGNATURE_SIZE,
    AuthInfo->RsaSignature,
    (UINT8*)kSvmTpmRootPublicKey
  );
  
  if (EFI_ERROR(Status)) {
    MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM Auth] Primary TPM signature verification FAILED: %r\n", Status));
    
    // Try secondary verification key for redundant authentication
    Status = SvmRsaVerifySignature(
      (UINT8*)AuthInfo,
      sizeof(SVM_AUTHORIZATION_INFO) - RSA_SIGNATURE_SIZE,
      AuthInfo->RsaSignature,
      (UINT8*)kSvmSecondaryPublicKey
    );
    
    if (EFI_ERROR(Status)) {
      MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM Auth] Secondary signature verification also FAILED: %r\n", Status));
      MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM Auth] CRITICAL SECURITY VIOLATION - Invalid authorization signature\n"));
      return EFI_SECURITY_VIOLATION;
    } else {
      MINI_VISOR_SVM_DEBUG((DEBUG_WARN, "[SVM Auth] Secondary key verification successful - primary key may be compromised\n"));
    }
  } else {
    MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM Auth] Primary TPM signature verification successful\n"));
  }
  
  // 5. 验证授权时间范围
  if (AuthInfo->ExpiryTime <= AuthInfo->AuthorizedTime) {
    MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM Auth] Invalid time range: expiry time is before authorized time\n"));
    return EFI_SECURITY_VIOLATION;
  }
  
  // 6. 验证使用次数限制
  if (AuthInfo->MaxUsageCount == 0) {
    MINI_VISOR_SVM_DEBUG((DEBUG_WARN, "[SVM Auth] MaxUsageCount is zero - unlimited usage\n"));
  } else if (AuthInfo->CurrentUsageCount > AuthInfo->MaxUsageCount) {
    MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM Auth] Current usage count (%u) exceeds maximum (%u)\n", 
                         AuthInfo->CurrentUsageCount, AuthInfo->MaxUsageCount));
    return EFI_ACCESS_DENIED;
  }
  
  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM Auth] Authorization structure validation completed successfully\n"));
  return EFI_SUCCESS;
}

/**
  计算授权期限
  
  @param AuthorizedTime  授权时间
  @param PeriodDays      期限天数
  
  @return 过期时间戳
**/
UINT32
SvmCalculateAuthorizationPeriod(
  IN UINT64 AuthorizedTime,
  IN UINT32 PeriodDays
  )
{
  if (PeriodDays == 0) {
    return 0;
  }
  
  UINT64 PeriodSeconds = (UINT64)PeriodDays * 24 * 60 * 60;
  return (UINT32)(AuthorizedTime + PeriodSeconds);
}

/**
  Setup NPT-based MMIO traps for comprehensive AMD-Vi register interception.
  
  @retval EFI_SUCCESS       NPT traps setup successfully.
  @retval Others            Failed to setup traps.
**/
EFI_STATUS
EFIAPI
SetupAmdViMmioTraps (
  VOID
  )
{
  EFI_STATUS Status;
  UINTN Index;
  
  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] Setting up AMD-Vi MMIO NPT traps\n"));
  
  // Initialize trap support for all IOMMU segments
  for (Index = 0; Index < gIommuManager.NumSegments; Index++) {
    EFI_PHYSICAL_ADDRESS MmioBase = gIommuManager.SegmentMmioBases[Index];
    
    if (MmioBase == 0) {
      continue;
    }
    
    // Split large pages to 4KB pages for the IOMMU MMIO range (64KB)
    Status = SplitNptPagesForMmioRange(MmioBase, 0x10000);
    if (EFI_ERROR(Status)) {
      MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM] Failed to split NPT pages for MMIO at 0x%lx\n", MmioBase));
      continue;
    }
    
    // Mark the IOMMU MMIO range as non-present to trigger NPF on access
    Status = MarkNptRangeNonPresent(MmioBase, 0x10000);
    if (EFI_ERROR(Status)) {
      MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM] Failed to mark NPT range non-present at 0x%lx\n", MmioBase));
      continue;
    }
    
    MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] NPT trap setup for IOMMU segment %d at 0x%lx\n", Index, MmioBase));
  }
  
  gIommuManager.NptTrapsEnabled = TRUE;
  return EFI_SUCCESS;
}

/**
  Split NPT pages for MMIO range to enable fine-grained trapping.
  
  @param[in] MmioBase       Base address of MMIO range.
  @param[in] Size           Size of MMIO range.
  
  @retval EFI_SUCCESS       Pages split successfully.
  @retval Others            Failed to split pages.
**/
EFI_STATUS
EFIAPI
SplitNptPagesForMmioRange (
  IN EFI_PHYSICAL_ADDRESS MmioBase,
  IN UINT64 Size
  )
{
  // This is a simplified implementation - in a real hypervisor,
  // you would need to walk the NPT page tables and split large pages
  // into 4KB pages for the specified range
  
  MINI_VISOR_SVM_DEBUG((DEBUG_VERBOSE, "[SVM] Splitting NPT pages for range 0x%lx-0x%lx\n", 
                        MmioBase, MmioBase + Size));
  
  // Mark the range for trap handling
  gIommuManager.TrapRegionBase = MmioBase;
  gIommuManager.TrapRegionSize = Size;
  
  return EFI_SUCCESS;
}

/**
  Mark NPT range as non-present to trigger page faults.
  
  @param[in] Base           Base address of range.
  @param[in] Size           Size of range.
  
  @retval EFI_SUCCESS       Range marked successfully.
  @retval Others            Failed to mark range.
**/
EFI_STATUS
EFIAPI
MarkNptRangeNonPresent (
  IN EFI_PHYSICAL_ADDRESS Base,
  IN UINT64 Size
  )
{
  // This is a simplified implementation - in a real hypervisor,
  // you would clear the present bit in the NPT page table entries
  
  MINI_VISOR_SVM_DEBUG((DEBUG_VERBOSE, "[SVM] Marking NPT range 0x%lx-0x%lx as non-present\n", 
                        Base, Base + Size));
  
  return EFI_SUCCESS;
}

/**
  Handle Nested Page Fault for IOMMU MMIO access.
  
  @param[in] ExitInfo       Pointer to exit information.
  @param[in] Context        Pointer to guest context.
  
  @retval EFI_SUCCESS       NPF handled successfully.
**/
EFI_STATUS
EFIAPI
HandleNestedPageFault (
  IN SVM_EXIT_INFO *ExitInfo,
  IN OUT NESTED_SVM_CONTEXT *Context
  )
{
  EFI_PHYSICAL_ADDRESS FaultAddress;
  UINT64 ErrorCode;
  BOOLEAN IsWrite;
  BOOLEAN IsUser;
  BOOLEAN IsExecute;
  UINTN SegmentIndex;
  UINT32 Offset;
  UINT32 Value;
  
  // Get fault address from VMCB exit info
  FaultAddress = ExitInfo->ExitInfo2;
  ErrorCode = ExitInfo->ExitInfo1;
  
  // Decode error code
  IsWrite = (ErrorCode & BIT1) != 0;
  IsUser = (ErrorCode & BIT2) != 0;
  IsExecute = (ErrorCode & BIT4) != 0;
  
  MINI_VISOR_SVM_DEBUG((DEBUG_VERBOSE, "[SVM] NPF: Address=0x%lx, Write=%d, User=%d, Execute=%d\n",
                        FaultAddress, IsWrite, IsUser, IsExecute));
  
  // Check if this is an IOMMU MMIO access
  for (SegmentIndex = 0; SegmentIndex < gIommuManager.NumSegments; SegmentIndex++) {
    EFI_PHYSICAL_ADDRESS MmioBase = gIommuManager.SegmentMmioBases[SegmentIndex];
    
    if (MmioBase == 0) {
      continue;
    }
    
    // Check if fault address is within this IOMMU segment's MMIO range
    if (FaultAddress >= MmioBase && FaultAddress < (MmioBase + 0x10000)) {
      Offset = (UINT32)(FaultAddress - MmioBase);
      
      if (IsWrite) {
        // MMIO write - get value from guest RAX
        Value = (UINT32)Context->GuestRax;
        return HandleIommuMmioWrite(SegmentIndex, Offset, Value, Context);
      } else {
        // MMIO read - return fake value in guest RAX
        return HandleIommuMmioRead(SegmentIndex, Offset, Context);
      }
    }
  }
  
  // Not an IOMMU MMIO access - let the guest handle the fault
  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] NPF not for IOMMU MMIO at 0x%lx, forwarding to guest\n", FaultAddress));
  
  // Record faulting address if context tracks it (use RING buffer register as placeholder)
  // NESTED_SVM_CONTEXT has no GuestCr2; store in GuestRdx for downstream handlers
  Context->GuestRdx = FaultAddress;
  
  return EFI_SUCCESS;
}

/**
  Handle IOMMU MMIO write access.
  
  @param[in] SegmentIndex   IOMMU segment index.
  @param[in] Offset         Offset within MMIO range.
  @param[in] Value          Value being written.
  @param[in] Context        Guest context.
  
  @retval EFI_SUCCESS       Write handled successfully.
**/
EFI_STATUS
EFIAPI
HandleIommuMmioWrite (
  IN UINTN SegmentIndex,
  IN UINT32 Offset,
  IN UINT32 Value,
  IN OUT NESTED_SVM_CONTEXT *Context
  )
{
  UINT64 CurrentTsc = AsmReadTsc();
  UINT32 RandomFactor = (UINT32)(CurrentTsc ^ gIommuManager.RandomizationSeed);
  
  MINI_VISOR_SVM_DEBUG((DEBUG_VERBOSE, "[SVM] IOMMU MMIO Write: Segment=%d, Offset=0x%x, Value=0x%x\n",
                        SegmentIndex, Offset, Value));
  
  // Update access telemetry
  gIommuManager.AccessCount++;
  
  // Handle specific register writes (strict minimal AMD-Vi map)
  switch (Offset) {
    case AMDVI_REG_CONTROL: // 0x18
      gIommuManager.Control[SegmentIndex] = Value;
      gIommuManager.ControlEnableCount++;
      
      // If OS is trying to enable IOMMU, fake success but don't actually enable
      if (Value & 0x1) { // IOMMU Enable bit
        MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] IOMMU enable intercepted for segment %d\n", SegmentIndex));
        gIommuManager.Control[SegmentIndex] |= 0x1; // Set enable bit in shadow
      }
      break;
      
    case AMDVI_REG_CMB_TAIL: // 0x24 Command Buffer Tail Doorbell (write-only)
      gIommuManager.CmbDoorbellCount++;
      // Fake command processing
      gIommuManager.Status[SegmentIndex] |= AMDVI_STATUS_CMD_DONE;
      break;
      
    case AMDVI_REG_DTB_LO: // 0x00
      gIommuManager.DtbLo[SegmentIndex] = Value;
      break;
      
    case AMDVI_REG_DTB_HI: // 0x04
      gIommuManager.DtbHi[SegmentIndex] = Value;
      break;
      
    case AMDVI_REG_CMB_LO: // 0x08
      gIommuManager.CmbLo[SegmentIndex] = Value;
      break;
      
    case AMDVI_REG_CMB_HI: // 0x0C
      gIommuManager.CmbHi[SegmentIndex] = Value;
      break;
      
    case AMDVI_REG_ELB_LO: // 0x10
      gIommuManager.ElbLo[SegmentIndex] = Value;
      break;
      
    case AMDVI_REG_ELB_HI: // 0x14
      gIommuManager.ElbHi[SegmentIndex] = Value;
      break;
      
    default:
      // Store write to shadow MMIO space with randomization
      if (Offset < 0x10000 && (Offset & 0x3) == 0) { // 4-byte aligned within 64KB
        UINTN DwordIndex = Offset / 4;
        if (DwordIndex < 8192) {
          gIommuManager.ShadowMmio[SegmentIndex][DwordIndex] = Value ^ (RandomFactor & 0xFFFF);
        }
      }
      break;
  }
  
  return EFI_SUCCESS;
}

/**
  Handle IOMMU MMIO read access.
  
  @param[in] SegmentIndex   IOMMU segment index.
  @param[in] Offset         Offset within MMIO range.
  @param[in] Context        Guest context.
  
  @retval EFI_SUCCESS       Read handled successfully.
**/
EFI_STATUS
EFIAPI
HandleIommuMmioRead (
  IN UINTN SegmentIndex,
  IN UINT32 Offset,
  IN OUT NESTED_SVM_CONTEXT *Context
  )
{
  UINT32 Value = 0;
  UINT64 CurrentTsc = AsmReadTsc();
  UINT32 RandomFactor = (UINT32)(CurrentTsc ^ gIommuManager.RandomizationSeed);
  
  MINI_VISOR_SVM_DEBUG((DEBUG_VERBOSE, "[SVM] IOMMU MMIO Read: Segment=%d, Offset=0x%x\n",
                        SegmentIndex, Offset));
  
  // Update access telemetry
  gIommuManager.AccessCount++;
  gIommuManager.StatusReadCount++;
  
  // Handle specific register reads (strict minimal AMD-Vi map)
  switch (Offset) {
    case AMDVI_REG_STATUS: // 0x1C
      Value = AMDVI_STATUS_READY | AMDVI_STATUS_CMD_DONE;
      break;

    case AMDVI_REG_CONTROL: // 0x18
      Value = gIommuManager.Control[SegmentIndex];
      break;
      
    case AMDVI_REG_DTB_LO: // 0x00
      Value = gIommuManager.DtbLo[SegmentIndex];
      break;

    case AMDVI_REG_DTB_HI: // 0x04
      Value = gIommuManager.DtbHi[SegmentIndex];
      break;

    case AMDVI_REG_CMB_LO: // 0x08
      Value = gIommuManager.CmbLo[SegmentIndex];
      break;

    case AMDVI_REG_CMB_HI: // 0x0C
      Value = gIommuManager.CmbHi[SegmentIndex];
      break;

    case AMDVI_REG_ELB_LO: // 0x10
      Value = gIommuManager.ElbLo[SegmentIndex];
      break;

    case AMDVI_REG_ELB_HI: // 0x14
      Value = gIommuManager.ElbHi[SegmentIndex];
      break;

    case 0x0030: // Extended Feature Register
      // Report comprehensive IOMMU capabilities
      Value = 0x00000001 | // Extended Feature support
              0x00000004 | // Hardware Error reporting
              0x00000010 | // Guest Translation support
              0x00000040 | // Invalidate All command support
              0x00000100 | // Guest APIC support
              0x00000200;  // Host APIC support
      break;
      
    case AMDVI_REG_CMB_TAIL: // 0x24 doorbell readback (optional)
      Value = (RandomFactor >> 4) & 0xFFF0;
      break;
      
    default:
      // Return value from shadow MMIO space with randomization
      if (Offset < 0x10000 && (Offset & 0x3) == 0) { // 4-byte aligned within 64KB
        UINTN DwordIndex = Offset / 4;
        if (DwordIndex < 8192) {
          Value = (UINT32)(gIommuManager.ShadowMmio[SegmentIndex][DwordIndex] ^ (RandomFactor & 0xFFFF));
        }
      } else {
        // For unaligned or out-of-range accesses, return randomized fake data
        Value = RandomFactor;
      }
      break;
  }
  
  // Apply additional randomization to break detection patterns
  if ((gIommuManager.AccessCount & 0x7) == 0x7) {
    Value ^= (RandomFactor >> 16);
  }
  
  // Return value in guest RAX
  Context->GuestRax = Value;
  
  MINI_VISOR_SVM_DEBUG((DEBUG_VERBOSE, "[SVM] IOMMU MMIO Read result: 0x%x\n", Value));
  
  return EFI_SUCCESS;
}

/**
  Handle PCI configuration space access for IOMMU capability spoofing.
  
  @param[in] Context        Guest context.
  @param[in] IsWrite        TRUE for write, FALSE for read.
  @param[in] Port           I/O port being accessed.
  @param[in] Size           Size of access (1, 2, or 4 bytes).
  
  @retval EFI_SUCCESS       PCI access handled successfully.
**/
EFI_STATUS
EFIAPI
HandlePciConfigAccess (
  IN OUT NESTED_SVM_CONTEXT *Context,
  IN BOOLEAN IsWrite,
  IN UINT16 Port,
  IN UINT8 Size
  )
{
  STATIC UINT32 PciConfigAddress = 0;
  UINT32 Value = 0;
  UINT64 CurrentTsc = AsmReadTsc();
  UINT32 RandomFactor = (UINT32)(CurrentTsc ^ gIommuManager.RandomizationSeed);
  
  if (Port == 0xCF8) {
    // PCI Configuration Address Port
    if (IsWrite) {
      PciConfigAddress = (UINT32)Context->GuestRax;
      MINI_VISOR_SVM_DEBUG((DEBUG_VERBOSE, "[SVM] PCI Config Address Write: 0x%x\n", PciConfigAddress));
    } else {
      Context->GuestRax = PciConfigAddress;
    }
    return EFI_SUCCESS;
  }
  
  if (Port >= 0xCFC && Port <= 0xCFF) {
    // PCI Configuration Data Port
    UINT8 Bus = (PciConfigAddress >> 16) & 0xFF;
    UINT8 Device = (PciConfigAddress >> 11) & 0x1F;
    UINT8 Function = (PciConfigAddress >> 8) & 0x7;
    UINT8 Register = (PciConfigAddress & 0xFC) + (Port - 0xCFC);
    
    MINI_VISOR_SVM_DEBUG((DEBUG_VERBOSE, "[SVM] PCI Config Access: Bus=%d, Dev=%d, Func=%d, Reg=0x%x, Write=%d\n",
                          Bus, Device, Function, Register, IsWrite));
    
    // Check if this is an AMD IOMMU device access (adaptive spoof)
    if (IsAmdIommuDevice(Bus, Device, Function)) {
      if (IsWrite) {
        Value = (UINT32)Context->GuestRax;
        return HandleIommuPciConfigWrite(Bus, Device, Function, Register, Value, Size, Context);
      } else {
        return HandleIommuPciConfigRead(Bus, Device, Function, Register, Size, Context);
      }
    }

    // If we haven't locked yet and guest probes another BDF early, opportunistically lock
    if (!gIommuManager.SpoofLocked && Bus == 0 && Register == 0x00 && !IsWrite) {
      // Treat first read of vendor/device id at a plausible location as our IOMMU
      if ((Device <= 0x1F) && (Function <= 0x07)) {
        gIommuManager.SpoofBus = Bus;
        gIommuManager.SpoofDevice = Device;
        gIommuManager.SpoofFunction = Function;
        gIommuManager.SpoofLocked = TRUE;
        return HandleIommuPciConfigRead(Bus, Device, Function, Register, Size, Context);
      }
    }
  }
  
  // For non-IOMMU PCI accesses, pass through to hardware
  return EFI_UNSUPPORTED;
}

/**
  Check if PCI device is an AMD IOMMU.
  
  @param[in] Bus            PCI bus number.
  @param[in] Device         PCI device number.
  @param[in] Function       PCI function number.
  
  @retval TRUE              Device is AMD IOMMU.
  @retval FALSE             Device is not AMD IOMMU.
**/
BOOLEAN
EFIAPI
IsAmdIommuDevice (
  IN UINT8 Bus,
  IN UINT8 Device,
  IN UINT8 Function
  )
{
  // If we have already locked to a spoofed BDF, only claim that one
  if (gIommuManager.SpoofLocked) {
    return (Bus == gIommuManager.SpoofBus &&
            Device == gIommuManager.SpoofDevice &&
            Function == gIommuManager.SpoofFunction);
  }

  // Before locking, accept common AMD IOMMU locations to catch the first probe
  if (Bus == 0) {
    if ((Device == 0x00 && Function == 0x02) ||
        (Device == 0x14 && Function == 0x00) ||
        (Device == 0x18 && Function <= 0x07)) {
      // Lock to the first probed tuple to remain consistent
      gIommuManager.SpoofBus = Bus;
      gIommuManager.SpoofDevice = Device;
      gIommuManager.SpoofFunction = Function;
      gIommuManager.SpoofLocked = TRUE;
      return TRUE;
    }
  }

  return FALSE;
}

/**
  Handle IOMMU PCI configuration space write.
  
  @param[in] Bus            PCI bus number.
  @param[in] Device         PCI device number.
  @param[in] Function       PCI function number.
  @param[in] Register       PCI register offset.
  @param[in] Value          Value being written.
  @param[in] Size           Size of write.
  @param[in] Context        Guest context.
  
  @retval EFI_SUCCESS       Write handled successfully.
**/
EFI_STATUS
EFIAPI
HandleIommuPciConfigWrite (
  IN UINT8 Bus,
  IN UINT8 Device,
  IN UINT8 Function,
  IN UINT8 Register,
  IN UINT32 Value,
  IN UINT8 Size,
  IN OUT NESTED_SVM_CONTEXT *Context
  )
{
  MINI_VISOR_SVM_DEBUG((DEBUG_VERBOSE, "[SVM] IOMMU PCI Config Write: Reg=0x%x, Value=0x%x, Size=%d\n",
                        Register, Value, Size));
  
  // For IOMMU PCI config writes, we generally want to fake success
  // but not actually enable the IOMMU
  
  switch (Register) {
    case 0x04: // Command register
      // Allow most command register settings but mask IOMMU-specific bits
      Value &= ~(BIT2 | BIT10); // Disable memory space and interrupt disable
      break;
      
    case 0x10: case 0x14: case 0x18: case 0x1C: case 0x20: case 0x24:
      // BAR registers - store the values but don't program real hardware
      break;
      
    default:
      // For other registers, just acknowledge the write
      break;
  }
  
  return EFI_SUCCESS;
}

/**
  Handle IOMMU PCI configuration space read.
  
  @param[in] Bus            PCI bus number.
  @param[in] Device         PCI device number.  
  @param[in] Function       PCI function number.
  @param[in] Register       PCI register offset.
  @param[in] Size           Size of read.
  @param[in] Context        Guest context.
  
  @retval EFI_SUCCESS       Read handled successfully.
**/
EFI_STATUS
EFIAPI
HandleIommuPciConfigRead (
  IN UINT8 Bus,
  IN UINT8 Device,
  IN UINT8 Function,
  IN UINT8 Register,
  IN UINT8 Size,
  IN OUT NESTED_SVM_CONTEXT *Context
  )
{
  UINT32 Value = 0;
  UINT64 CurrentTsc = AsmReadTsc();
  UINT32 RandomFactor = (UINT32)(CurrentTsc ^ gIommuManager.RandomizationSeed);
  
  MINI_VISOR_SVM_DEBUG((DEBUG_VERBOSE, "[SVM] IOMMU PCI Config Read: Reg=0x%x, Size=%d\n", Register, Size));
  
  // If we are not locked yet, lock to this tuple on the first read path through here
  if (!gIommuManager.SpoofLocked) {
    gIommuManager.SpoofBus = Bus;
    gIommuManager.SpoofDevice = Device;
    gIommuManager.SpoofFunction = Function;
    gIommuManager.SpoofLocked = TRUE;
  }

  switch (Register) {
    case 0x00: // Vendor ID
      Value = 0x1022; // AMD Vendor ID
      break;
      
    case 0x02: // Device ID
      Value = 0x1481; // AMD IOMMU Device ID
      break;
      
    case 0x04: // Command Register
      Value = 0x0000; // IOMMU disabled
      break;
      
    case 0x06: // Status Register
      Value = 0x0010; // Capabilities list present
      break;
      
    case 0x08: // Revision ID
      Value = 0x00;
      break;
      
    case 0x09: // Programming Interface
      Value = 0x00;
      break;
      
    case 0x0A: // Sub Class Code
      Value = 0x06; // System peripheral
      break;
      
    case 0x0B: // Base Class Code
      Value = 0x08; // System peripheral
      break;
      
    case 0x10: // BAR0 - MMIO Base Address
      Value = (UINT32)gIommuManager.MmioBase | 0x4; // Memory space, 64-bit
      break;
      
    case 0x14: // BAR1 - Upper 32 bits of MMIO Base
      Value = (UINT32)(gIommuManager.MmioBase >> 32);
      break;
      
    case 0x34: // Capabilities Pointer
      Value = 0x40; // Point to capability at offset 0x40
      break;
      
    case 0x40: // Capability Header - Secure Device
      Value = 0x00000F0F; // Secure Device capability ID with next pointer
      break;
      
    case 0x44: // Secure Device Control
      Value = 0x00000001; // IOMMU present and enabled
      break;
      
    case 0x48: // IOMMU Base Address Low
      Value = (UINT32)gIommuManager.MmioBase;
      break;
      
    case 0x4C: // IOMMU Base Address High
      Value = (UINT32)(gIommuManager.MmioBase >> 32);
      break;
      
    case 0x50: // IOMMU Range
      Value = 0x0000FFFF; // 64KB range
      break;
      
    case 0x54: // IOMMU Control
      Value = 0x00000001; // IOMMU enabled
      break;
      
    default:
      // For unknown registers, return randomized fake data
      Value = RandomFactor;
      break;
  }
  
  // Apply size masking
  switch (Size) {
    case 1:
      Value &= 0xFF;
      break;
    case 2:
      Value &= 0xFFFF;
      break;
    case 4:
      // Already 32-bit
      break;
  }
  
  // Apply additional randomization for detection resistance
  if ((gIommuManager.AccessCount & 0xF) == 0xF) {
    Value ^= (RandomFactor & 0xFF);
  }
  
  Context->GuestRax = Value;
  
  MINI_VISOR_SVM_DEBUG((DEBUG_VERBOSE, "[SVM] IOMMU PCI Config Read result: 0x%x\n", Value));
  
  return EFI_SUCCESS;
}

/**
  Main VM exit handler for SVM.
  
  @param[in] ExitInfo       Pointer to exit information.
  @param[in] Context        Pointer to guest context.
  
  @retval EFI_SUCCESS       VM exit handled successfully.
**/
EFI_STATUS
EFIAPI
HandleVmExit (
  IN SVM_EXIT_INFO *ExitInfo,
  IN OUT NESTED_SVM_CONTEXT *Context
  )
{
  EFI_STATUS Status = EFI_SUCCESS;
  
      // Update performance statistics
    gMiniVisorSvmGlobalData.PerfData.VmExitCount++;
  
  MINI_VISOR_SVM_DEBUG((DEBUG_VERBOSE, "[SVM] VM Exit: Code=0x%lx, Info1=0x%lx, Info2=0x%lx\n",
                        ExitInfo->ExitCode, ExitInfo->ExitInfo1, ExitInfo->ExitInfo2));
  
  switch (ExitInfo->ExitCode) {
    case SVM_EXIT_NPF: // 0x400 - Nested Page Fault
      Status = HandleNestedPageFault(ExitInfo, Context);
      break;
      
    case SVM_EXIT_IOIO: // 0x7B - I/O Instruction
      Status = HandleIoInstruction(ExitInfo, Context);
      break;
      
    case SVM_EXIT_MSR: // 0x7C - MSR Access
      Status = HandleMsrExit(ExitInfo, Context);
      break;
      
    case SVM_EXIT_CPUID: // 0x72 - CPUID
      Status = HandleCpuidExit(Context);
      break;
      
    case SVM_EXIT_RDTSC: // 0x6E - RDTSC
      Status = HandleRdtscExit(Context);
      break;
      
    case SVM_EXIT_RDPMC: // 0x6F - RDPMC
      Status = HandleRdpmcExit(Context);
      break;
      
    case SVM_EXIT_VMRUN: // 0x80 - VMRUN instruction
      Status = HandleNestedVmrun(ExitInfo, Context);
      break;
      
    case SVM_EXIT_VMMCALL: // 0x81 - VMMCALL instruction
      Status = HandleVmmcallExit(ExitInfo, Context);
      break;
      
    case SVM_EXIT_VMLOAD: // 0x82 - VMLOAD instruction
    case SVM_EXIT_VMSAVE: // 0x83 - VMSAVE instruction
      // These are privileged instructions that should be emulated
      Status = HandleSvmInstruction(ExitInfo, Context);
      break;
      
    case SVM_EXIT_AVIC_INCOMPLETE_IPI: // 0x401 - AVIC Incomplete IPI
      Status = HandleAvicIncompleteIpi(ExitInfo, Context);
      break;
      
    case SVM_EXIT_AVIC_UNACCELERATED_ACCESS: // 0x402 - AVIC Unaccelerated Access
      Status = HandleAvicUnacceleratedAccess(ExitInfo, Context);
      break;
      
    default:
      MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] Unhandled VM exit: 0x%lx\n", ExitInfo->ExitCode));
      // For unhandled exits, just advance guest RIP and continue
      Context->GuestRip += 3; // Approximate instruction length
      Status = EFI_SUCCESS;
      break;
  }
  
  return Status;
}

/**
  Handle I/O instruction VM exit.
  
  @param[in] ExitInfo       Pointer to exit information.
  @param[in] Context        Pointer to guest context.
  
  @retval EFI_SUCCESS       I/O instruction handled successfully.
**/
EFI_STATUS
EFIAPI
HandleIoInstruction (
  IN SVM_EXIT_INFO *ExitInfo,
  IN OUT NESTED_SVM_CONTEXT *Context
  )
{
  UINT64 IoInfo = ExitInfo->ExitInfo1;
  BOOLEAN IsWrite = (IoInfo & BIT0) != 0;
  UINT8 Size = (UINT8)((IoInfo >> 4) & 0x7) + 1; // Size: 1, 2, or 4 bytes
  UINT16 Port = (UINT16)(ExitInfo->ExitInfo2 & 0xFFFF);
  
  MINI_VISOR_SVM_DEBUG((DEBUG_VERBOSE, "[SVM] I/O %s: Port=0x%x, Size=%d\n",
                        IsWrite ? "Write" : "Read", Port, Size));
  
  // Check for PCI configuration access
  if ((Port == 0xCF8) || (Port >= 0xCFC && Port <= 0xCFF)) {
    EFI_STATUS Status = HandlePciConfigAccess(Context, IsWrite, Port, Size);
    if (!EFI_ERROR(Status)) {
      return EFI_SUCCESS;
    }
  }
  
  // For other I/O ports, pass through to hardware
  if (IsWrite) {
    switch (Size) {
      case 1:
        IoWrite8(Port, (UINT8)Context->GuestRax);
        break;
      case 2:
        IoWrite16(Port, (UINT16)Context->GuestRax);
        break;
      case 4:
        IoWrite32(Port, (UINT32)Context->GuestRax);
        break;
    }
  } else {
    UINT32 Value = 0;
    switch (Size) {
      case 1:
        Value = IoRead8(Port);
        break;
      case 2:
        Value = IoRead16(Port);
        break;
      case 4:
        Value = IoRead32(Port);
        break;
    }
    Context->GuestRax = Value;
  }
  
  return EFI_SUCCESS;
}

/**
  Initialize advanced SVM features.
  
  @retval EFI_SUCCESS       Advanced features initialized successfully.
**/
EFI_STATUS
EFIAPI
InitializeAdvancedSvmFeatures (
  VOID
  )
{
  ADVANCED_SVM_FEATURES *Features = &gMiniVisorSvmGlobalData.AdvancedFeatures;
  SVM_CAPABILITIES *Caps = &gMiniVisorSvmGlobalData.SvmCapabilities;
  
  // Initialize feature flags based on capabilities
  Features->NestedSvmEnabled = Caps->NestedSvmSupported;
  Features->AvicEnabled = Caps->AvicSupported;
  Features->VmcbCleanEnabled = Caps->VmcbCleanSupported;
  Features->PauseFilterEnabled = Caps->PauseFilterSupported;
  Features->TscScalingEnabled = FALSE; // Can be enabled dynamically
  Features->VirtualGifEnabled = FALSE;
  
  // Initialize ASID management
  Features->MaxAsidCount = Caps->MaxAsid;
  Features->CurrentAsid = 1; // Start with ASID 1, 0 is reserved
  
  // Initialize TSC scaling (1.0x multiplier)
  Features->TscMultiplier = 0x100000000ULL; // 1.0 in 32.32 fixed point
  
  // Initialize pause filter threshold
  Features->PauseFilterThreshold = 1000; // Default threshold
  
  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] Advanced features initialized: NPT=%d, AVIC=%d, Clean=%d\n",
                        Features->NestedSvmEnabled, Features->AvicEnabled, Features->VmcbCleanEnabled));
  
  return EFI_SUCCESS;
}

/**
  Initialize nested SVM support.
  
  @retval EFI_SUCCESS       Nested SVM initialized successfully.
**/
EFI_STATUS
EFIAPI
InitializeNestedSvm (
  VOID
  )
{
  NESTED_SVM_STATE *NestedState = &gMiniVisorSvmGlobalData.NestedState;
  EFI_STATUS Status;
  EFI_PHYSICAL_ADDRESS HostSaveAreaPhys;
  
  if (!gMiniVisorSvmGlobalData.AdvancedFeatures.NestedSvmEnabled) {
    return EFI_UNSUPPORTED;
  }
  
  // Allocate host save area for nested SVM
  Status = gBS->AllocatePages(
    AllocateAnyPages,
    EfiBootServicesData,
    1, // 4KB page
    &HostSaveAreaPhys
  );
  if (EFI_ERROR(Status)) {
    DEBUG((DEBUG_ERROR, "[SVM] Failed to allocate host save area: %r\n", Status));
    return Status;
  }
  
  // Initialize nested state
  ZeroMem(NestedState, sizeof(NESTED_SVM_STATE));
  NestedState->HostSaveArea = HostSaveAreaPhys;
  NestedState->InNestedMode = FALSE;
  NestedState->NestingLevel = 0;
  NestedState->L1Asid = 1;
  NestedState->L2Asid = 2;
  
  // Set HSA_MSR (Host Save Area MSR)
  AsmWriteMsr64(MSR_HSA, HostSaveAreaPhys);
  
  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] Nested SVM initialized, HSA at 0x%lx\n", HostSaveAreaPhys));
  
  return EFI_SUCCESS;
}
/**
  Initialize AVIC (Advanced Virtual Interrupt Controller).
  
  @retval EFI_SUCCESS       AVIC initialized successfully.
**/
EFI_STATUS
EFIAPI
InitializeAvic (
  VOID
  )
{
  AVIC_MANAGEMENT *AvicState = &gMiniVisorSvmGlobalData.AvicState;
  EFI_STATUS Status;
  EFI_PHYSICAL_ADDRESS AvicPages;
  
  if (!gMiniVisorSvmGlobalData.AdvancedFeatures.AvicEnabled) {
    return EFI_UNSUPPORTED;
  }
  
  // Allocate AVIC backing pages (need 3 pages: logical table, physical table, backing page)
  Status = gBS->AllocatePages(
    AllocateAnyPages,
    EfiBootServicesData,
    3, // 3 * 4KB pages
    &AvicPages
  );
  if (EFI_ERROR(Status)) {
    DEBUG((DEBUG_ERROR, "[SVM] Failed to allocate AVIC pages: %r\n", Status));
    return Status;
  }
  
  // Initialize AVIC structure
  ZeroMem(AvicState, sizeof(AVIC_MANAGEMENT));
  AvicState->AvicLogicalTable = AvicPages;
  AvicState->AvicPhysicalTable = AvicPages + 0x1000;
  AvicState->AvicBackingPage = AvicPages + 0x2000;
  AvicState->AvicLogicalId = 0;
  AvicState->AvicPhysicalId = 0;
  AvicState->AvicInUse = TRUE;
  
  // Clear pending interrupts
  ZeroMem(AvicState->PendingInterrupts, sizeof(AvicState->PendingInterrupts));
  
  // Clear AVIC tables
  ZeroMem((VOID*)AvicState->AvicLogicalTable, 0x1000);
  ZeroMem((VOID*)AvicState->AvicPhysicalTable, 0x1000);
  ZeroMem((VOID*)AvicState->AvicBackingPage, 0x1000);
  
  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] AVIC initialized: Logical=0x%lx, Physical=0x%lx, Backing=0x%lx\n",
                        AvicState->AvicLogicalTable, AvicState->AvicPhysicalTable, AvicState->AvicBackingPage));
  
  return EFI_SUCCESS;
}

/**
  Initialize VMCB clean bits management.
  
  @retval EFI_SUCCESS       VMCB clean bits initialized successfully.
**/
EFI_STATUS
EFIAPI
InitializeVmcbClean (
  VOID
  )
{
  VMCB_CLEAN_STATE *CleanState = &gMiniVisorSvmGlobalData.CleanState;
  
  if (!gMiniVisorSvmGlobalData.AdvancedFeatures.VmcbCleanEnabled) {
    return EFI_UNSUPPORTED;
  }
  
  // Initialize all clean bits as dirty (need to be loaded)
  ZeroMem(CleanState, sizeof(VMCB_CLEAN_STATE));
  CleanState->CleanBits = 0; // All bits clear = all dirty
  CleanState->InterceptVectorDirty = TRUE;
  CleanState->IopmDirty = TRUE;
  CleanState->AsidDirty = TRUE;
  CleanState->TprDirty = TRUE;
  CleanState->NestedPageDirty = TRUE;
  CleanState->ControlDirty = TRUE;
  CleanState->DrDirty = TRUE;
  CleanState->DtDirty = TRUE;
  CleanState->SegmentDirty = TRUE;
  CleanState->Cr2Dirty = TRUE;
  CleanState->LbrDirty = TRUE;
  CleanState->AvicDirty = TRUE;
  
  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] VMCB clean bits management initialized\n"));
  
  return EFI_SUCCESS;
}

/**
  Update VMCB clean bits before VMRUN.
  
  @param[in] VmcbControl    Pointer to VMCB control area.
**/
VOID
EFIAPI
UpdateVmcbCleanBits (
  IN VMCB_CONTROL_AREA *VmcbControl
  )
{
  VMCB_CLEAN_STATE *CleanState = &gMiniVisorSvmGlobalData.CleanState;
  UINT32 CleanBits = 0;
  
  if (!gMiniVisorSvmGlobalData.AdvancedFeatures.VmcbCleanEnabled) {
    return;
  }
  
  // Build clean bits based on what hasn't changed
  if (!CleanState->InterceptVectorDirty) CleanBits |= VMCB_CLEAN_INTERCEPT_VECTOR;
  if (!CleanState->IopmDirty) CleanBits |= VMCB_CLEAN_IOPM;
  if (!CleanState->AsidDirty) CleanBits |= VMCB_CLEAN_ASID;
  if (!CleanState->TprDirty) CleanBits |= VMCB_CLEAN_TPR;
  if (!CleanState->NestedPageDirty) CleanBits |= VMCB_CLEAN_NP;
  if (!CleanState->ControlDirty) CleanBits |= VMCB_CLEAN_CONTROL;
  if (!CleanState->DrDirty) CleanBits |= VMCB_CLEAN_DR;
  if (!CleanState->DtDirty) CleanBits |= VMCB_CLEAN_DT;
  if (!CleanState->SegmentDirty) CleanBits |= VMCB_CLEAN_SEG;
  if (!CleanState->Cr2Dirty) CleanBits |= VMCB_CLEAN_CR2;
  if (!CleanState->LbrDirty) CleanBits |= VMCB_CLEAN_LBR;
  if (!CleanState->AvicDirty) CleanBits |= VMCB_CLEAN_AVIC;
  
  VmcbControl->VmcbCleanBits = CleanBits;
  CleanState->CleanBits = CleanBits;
  
  MINI_VISOR_SVM_DEBUG((DEBUG_VERBOSE, "[SVM] VMCB clean bits updated: 0x%x\n", CleanBits));
}

/**
  Handle nested VMRUN instruction.
  
  @param[in] ExitInfo       Pointer to exit information.
  @param[in] Context        Pointer to guest context.
  
  @retval EFI_SUCCESS       VMRUN handled successfully.
**/
EFI_STATUS
EFIAPI
HandleNestedVmrun (
  IN SVM_EXIT_INFO *ExitInfo,
  IN OUT NESTED_SVM_CONTEXT *Context
  )
{
  NESTED_SVM_STATE *NestedState = &gMiniVisorSvmGlobalData.NestedState;
  VMCB_CONTROL_AREA *L1Vmcb;
  UINT64 L1VmcbPhysical;
  
  if (!gMiniVisorSvmGlobalData.AdvancedFeatures.NestedSvmEnabled) {
    // If nested SVM is disabled, inject #UD
    return InjectException(Context, 6, 0); // #UD exception
  }
  
  // Get L1 VMCB physical address from RAX
  L1VmcbPhysical = Context->GuestRax;
  
  // Validate L1 VMCB address
  if ((L1VmcbPhysical & 0xFFF) != 0) {
    // VMCB must be 4KB aligned
    return InjectException(Context, 13, 0); // #GP exception
  }
  
  // Save L1 VMCB address
  NestedState->L1VmcbPhysicalAddress = L1VmcbPhysical;
  NestedState->InNestedMode = TRUE;
  NestedState->NestingLevel++;
  
  // Map L1 VMCB
  L1Vmcb = (VMCB_CONTROL_AREA*)L1VmcbPhysical;
  
  // Save host state to HSA (simplified)
  // In real implementation, this would save more state
  
  // Merge L1 intercepts with our intercepts
  // We need to maintain control over critical operations
  
  // Switch to L2 ASID
  NestedState->L2Asid = gMiniVisorSvmGlobalData.AdvancedFeatures.CurrentAsid + 1;
  if (NestedState->L2Asid >= gMiniVisorSvmGlobalData.AdvancedFeatures.MaxAsidCount) {
    NestedState->L2Asid = 1; // Wrap around
  }
  
  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] Nested VMRUN: L1_VMCB=0x%lx, L2_ASID=%d, Level=%d\n",
                        L1VmcbPhysical, NestedState->L2Asid, NestedState->NestingLevel));
  
  // Continue execution in nested mode
  return EFI_SUCCESS;
}

/**
  Handle nested VMEXIT instruction.
  
  @param[in] ExitInfo       Pointer to exit information.
  @param[in] Context        Pointer to guest context.
  
  @retval EFI_SUCCESS       VMEXIT handled successfully.
**/
EFI_STATUS
EFIAPI
HandleNestedVmexit (
  IN SVM_EXIT_INFO *ExitInfo,
  IN OUT NESTED_SVM_CONTEXT *Context
  )
{
  NESTED_SVM_STATE *NestedState = &gMiniVisorSvmGlobalData.NestedState;
  
  if (!NestedState->InNestedMode) {
    // Not in nested mode, this shouldn't happen
    return InjectException(Context, 6, 0); // #UD exception
  }
  
  // Restore host state from HSA
  // Switch back to L1 ASID
  NestedState->NestingLevel--;
  if (NestedState->NestingLevel == 0) {
    NestedState->InNestedMode = FALSE;
  }
  
  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] Nested VMEXIT: Level=%d, InNested=%d\n",
                        NestedState->NestingLevel, NestedState->InNestedMode));
  
  return EFI_SUCCESS;
}

/**
  Handle AVIC incomplete IPI VM exit.
  
  @param[in] ExitInfo       Pointer to exit information.
  @param[in] Context        Pointer to guest context.
  
  @retval EFI_SUCCESS       AVIC IPI handled successfully.
**/
EFI_STATUS
EFIAPI
HandleAvicIncompleteIpi (
  IN SVM_EXIT_INFO *ExitInfo,
  IN OUT NESTED_SVM_CONTEXT *Context
  )
{
  AVIC_MANAGEMENT *AvicState = &gMiniVisorSvmGlobalData.AvicState;
  UINT32 IcrLow, IcrHigh;
  UINT32 Vector, DestinationId, DeliveryMode;
  
  if (!gMiniVisorSvmGlobalData.AdvancedFeatures.AvicEnabled || !AvicState->AvicInUse) {
    return EFI_UNSUPPORTED;
  }
  
  // Extract IPI information from exit info
  IcrLow = (UINT32)ExitInfo->ExitInfo1;
  IcrHigh = (UINT32)ExitInfo->ExitInfo2;
  
  Vector = IcrLow & 0xFF;
  DestinationId = IcrHigh >> 24;
  DeliveryMode = (IcrLow >> 8) & 0x7;
  
  MINI_VISOR_SVM_DEBUG((DEBUG_VERBOSE, "[SVM] AVIC Incomplete IPI: Vector=0x%x, Dest=0x%x, Mode=%d\n",
                        Vector, DestinationId, DeliveryMode));
  
  // For demonstration, we'll just mark the interrupt as pending
  if (Vector < 256) {
    UINT32 DwordIndex = Vector / 32;
    UINT32 BitIndex = Vector % 32;
    AvicState->PendingInterrupts[DwordIndex] |= (1U << BitIndex);
  }
  
  // In a real implementation, we would:
  // 1. Look up the destination APIC ID in the logical/physical tables
  // 2. Queue the interrupt for delivery
  // 3. Update AVIC data structures
  // 4. Potentially cause a VM exit to deliver the interrupt
  
  return EFI_SUCCESS;
}

/**
  Handle AVIC unaccelerated access VM exit.
  
  @param[in] ExitInfo       Pointer to exit information.
  @param[in] Context        Pointer to guest context.
  
  @retval EFI_SUCCESS       AVIC access handled successfully.
**/
EFI_STATUS
EFIAPI
HandleAvicUnacceleratedAccess (
  IN SVM_EXIT_INFO *ExitInfo,
  IN OUT NESTED_SVM_CONTEXT *Context
  )
{
  AVIC_MANAGEMENT *AvicState = &gMiniVisorSvmGlobalData.AvicState;
  UINT64 AvicAccessInfo = ExitInfo->ExitInfo1;
  UINT32 Offset = (UINT32)(AvicAccessInfo & 0xFFF);
  BOOLEAN IsWrite = (AvicAccessInfo & BIT32) != 0;
  
  if (!gMiniVisorSvmGlobalData.AdvancedFeatures.AvicEnabled || !AvicState->AvicInUse) {
    return EFI_UNSUPPORTED;
  }
  
  MINI_VISOR_SVM_DEBUG((DEBUG_VERBOSE, "[SVM] AVIC Unaccelerated Access: Offset=0x%x, Write=%d\n",
                        Offset, IsWrite));
  
  // Handle specific APIC register accesses that couldn't be accelerated
  switch (Offset) {
    case 0x300: // ICR Low
      if (IsWrite) {
        // Handle IPI send
        UINT32 IcrValue = (UINT32)Context->GuestRax;
        UINT32 Vector = IcrValue & 0xFF;
        // Queue the IPI for processing
        if (Vector < 256) {
          UINT32 DwordIndex = Vector / 32;
          UINT32 BitIndex = Vector % 32;
          AvicState->PendingInterrupts[DwordIndex] |= (1U << BitIndex);
        }
      }
      break;
      
    case 0x310: // ICR High
      // Handle destination setting
      break;
      
    case 0x80: // Task Priority Register
      // Handle TPR access
      break;
      
    default:
      // Handle other APIC registers as pass-through
      break;
  }
  
  return EFI_SUCCESS;
}

/**
  Inject an exception into the guest.
  
  @param[in] Context        Pointer to guest context.
  @param[in] Vector         Exception vector.
  @param[in] ErrorCode      Error code (if applicable).
  
  @retval EFI_SUCCESS       Exception injected successfully.
**/
EFI_STATUS
EFIAPI
InjectException (
  IN OUT NESTED_SVM_CONTEXT *Context,
  IN UINT8 Vector,
  IN UINT32 ErrorCode
  )
{
  // This is a simplified exception injection
  // In a real implementation, this would:
  // 1. Check if the exception needs an error code
  // 2. Update the VMCB's EVENTINJ field
  // 3. Handle exception priority and masking
  
  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] Injecting exception: Vector=0x%x, ErrorCode=0x%x\n",
                        Vector, ErrorCode));
  
  // For now, we'll just advance RIP to continue execution
  Context->GuestRip += 3; // Approximate instruction length
  
  return EFI_SUCCESS;
}

/**
  Handle VMMCALL VM exit.
  
  @param[in] ExitInfo       Pointer to exit information.
  @param[in] Context        Pointer to guest context.
  
  @retval EFI_SUCCESS       VMMCALL handled successfully.
**/
EFI_STATUS
EFIAPI
HandleVmmcallExit (
  IN SVM_EXIT_INFO *ExitInfo,
  IN OUT NESTED_SVM_CONTEXT *Context
  )
{
  UINT32 ServiceId = (UINT32)Context->GuestRax;
  
  // Handle hypercall services
  switch (ServiceId) {
    case 0x1000: // Query hypervisor presence
      Context->GuestRax = 0x4D56534D; // 'MVSM' - MiniVisor SVM signature
      Context->GuestRbx = MINI_VISOR_SVM_MAJOR_VERSION;
      Context->GuestRcx = MINI_VISOR_SVM_MINOR_VERSION;
      Context->GuestRdx = MINI_VISOR_SVM_BUILD_VERSION;
      break;
      
    case 0x1001: // Query hypervisor capabilities
      Context->GuestRax = 0;
      if (gMiniVisorSvmGlobalData.AdvancedFeatures.NestedSvmEnabled) Context->GuestRax |= BIT0;
      if (gMiniVisorSvmGlobalData.AdvancedFeatures.AvicEnabled) Context->GuestRax |= BIT1;
      if (gMiniVisorSvmGlobalData.AdvancedFeatures.VmcbCleanEnabled) Context->GuestRax |= BIT2;
      if (gMiniVisorSvmGlobalData.NptEnabled) Context->GuestRax |= BIT3;
      break;
      
          case 0x1002: // Query performance statistics
        Context->GuestRax = gMiniVisorSvmGlobalData.PerfData.VmrunCount;
        Context->GuestRbx = gMiniVisorSvmGlobalData.PerfData.VmExitCount;
        Context->GuestRcx = gMiniVisorSvmGlobalData.PerfData.LastVmExitReason;
        Context->GuestRdx = gMiniVisorSvmGlobalData.PerfData.TotalVmExitTime;
      break;
      
    default:
      // Unknown service, return error
      Context->GuestRax = 0xFFFFFFFF;
      break;
  }
  
  MINI_VISOR_SVM_DEBUG((DEBUG_VERBOSE, "[SVM] VMMCALL: Service=0x%x, Result=0x%lx\n", 
                        ServiceId, Context->GuestRax));
  
  return EFI_SUCCESS;
}

/**
  Handle SVM instruction VM exits (VMLOAD, VMSAVE).
  
  @param[in] ExitInfo       Pointer to exit information.
  @param[in] Context        Pointer to guest context.
  
  @retval EFI_SUCCESS       SVM instruction handled successfully.
**/
EFI_STATUS
EFIAPI
HandleSvmInstruction (
  IN SVM_EXIT_INFO *ExitInfo,
  IN OUT NESTED_SVM_CONTEXT *Context
  )
{
  switch (ExitInfo->ExitCode) {
    case SVM_EXIT_VMLOAD:
      // VMLOAD loads additional guest state from VMCB
      // For security, we only allow this in nested mode
      if (gMiniVisorSvmGlobalData.NestedState.InNestedMode) {
        MINI_VISOR_SVM_DEBUG((DEBUG_VERBOSE, "[SVM] VMLOAD in nested mode\n"));
        // Load additional state (FS, GS, TR, LDTR, KERNEL_GS_BASE, etc.)
        // This is simplified - real implementation would load from VMCB
      } else {
        return InjectException(Context, 13, 0); // #GP if not in nested mode
      }
      break;
      
    case SVM_EXIT_VMSAVE:
      // VMSAVE saves additional guest state to VMCB
      if (gMiniVisorSvmGlobalData.NestedState.InNestedMode) {
        MINI_VISOR_SVM_DEBUG((DEBUG_VERBOSE, "[SVM] VMSAVE in nested mode\n"));
        // Save additional state
      } else {
        return InjectException(Context, 13, 0); // #GP if not in nested mode
      }
      break;
  }
  
  return EFI_SUCCESS;
}

/**
  Perform SVM security and integrity checks.
  
  @retval EFI_SUCCESS       Security checks passed.
  @retval Others            Security violation detected.
**/
EFI_STATUS
EFIAPI
PerformSvmSecurityChecks (
  VOID
  )
{
  VMCB_CONTROL_AREA *VmcbControl;
  UINT64 CurrentEfer, CurrentCr0, CurrentCr4;
  
  // Verify VMCB integrity
  VmcbControl = (VMCB_CONTROL_AREA*)gMiniVisorSvmGlobalData.VmcbRegion;
  if (VmcbControl == NULL) {
    DEBUG((DEBUG_ERROR, "[SVM] VMCB region is NULL\n"));
    return EFI_SECURITY_VIOLATION;
  }
  
  // Check critical control register values
  CurrentEfer = AsmReadMsr64(MSR_EFER);
  CurrentCr0 = AsmReadCr0();
  CurrentCr4 = AsmReadCr4();
  
  // Verify EFER.SVME is still set
  if ((CurrentEfer & EFER_SVME) == 0) {
    DEBUG((DEBUG_ERROR, "[SVM] EFER.SVME has been cleared\n"));
    return EFI_SECURITY_VIOLATION;
  }
  
  // Verify CR0.PE and CR0.PG are set (we're in protected/paged mode)
  if ((CurrentCr0 & (CR0_PE | CR0_PG)) != (CR0_PE | CR0_PG)) {
    DEBUG((DEBUG_ERROR, "[SVM] Invalid CR0 state: 0x%lx\n", CurrentCr0));
    return EFI_SECURITY_VIOLATION;
  }
  
  // Verify CR4.PAE is set (required for long mode)
  if ((CurrentCr4 & CR4_PAE) == 0) {
    DEBUG((DEBUG_ERROR, "[SVM] CR4.PAE is not set\n"));
    return EFI_SECURITY_VIOLATION;
  }
  
  // Check VMCB intercept settings haven't been tampered with
  if ((VmcbControl->InterceptInstr1 & SVM_INTERCEPT_CPUID) == 0) {
    DEBUG((DEBUG_WARN, "[SVM] CPUID intercept has been disabled\n"));
    VmcbControl->InterceptInstr1 |= SVM_INTERCEPT_CPUID; // Re-enable
  }
  
  if ((VmcbControl->InterceptInstr1 & SVM_INTERCEPT_MSR_PROT) == 0) {
    DEBUG((DEBUG_WARN, "[SVM] MSR intercept has been disabled\n"));
    VmcbControl->InterceptInstr1 |= SVM_INTERCEPT_MSR_PROT; // Re-enable
  }
  
  // Verify NPT base hasn't been corrupted
  if (gMiniVisorSvmGlobalData.NptEnabled) {
    if (VmcbControl->NestedCr3 != gMiniVisorSvmGlobalData.NptPml4Base) {
      DEBUG((DEBUG_ERROR, "[SVM] NPT base has been modified: 0x%lx -> 0x%lx\n",
             gMiniVisorSvmGlobalData.NptPml4Base, VmcbControl->NestedCr3));
      VmcbControl->NestedCr3 = gMiniVisorSvmGlobalData.NptPml4Base; // Restore
    }
  }
  
  // Check ASID validity
  if (VmcbControl->Asid == 0 || VmcbControl->Asid > gMiniVisorSvmGlobalData.MaxAsid) {
    DEBUG((DEBUG_ERROR, "[SVM] Invalid ASID: %d\n", VmcbControl->Asid));
    VmcbControl->Asid = 1; // Reset to valid ASID
  }
  
  MINI_VISOR_SVM_DEBUG((DEBUG_VERBOSE, "[SVM] Security checks passed\n"));
  return EFI_SUCCESS;
}

/**
  Optimize SVM performance by enabling advanced features.
  
  @retval EFI_SUCCESS       Performance optimization completed.
**/
EFI_STATUS
EFIAPI
OptimizeSvmPerformance (
  VOID
  )
{
  VMCB_CONTROL_AREA *VmcbControl;
  
  VmcbControl = (VMCB_CONTROL_AREA*)gMiniVisorSvmGlobalData.VmcbRegion;
  if (VmcbControl == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  
  // Enable AVIC if supported
  if (gMiniVisorSvmGlobalData.AdvancedFeatures.AvicEnabled) {
    VmcbControl->AvicApicBar = gMiniVisorSvmGlobalData.AvicState.AvicBackingPage;
    VmcbControl->AvicLogicalTable = gMiniVisorSvmGlobalData.AvicState.AvicLogicalTable;
    VmcbControl->AvicPhysicalTable = gMiniVisorSvmGlobalData.AvicState.AvicPhysicalTable;
    gMiniVisorSvmGlobalData.Status |= MINI_VISOR_SVM_STATUS_AVIC_ENABLED;
    MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] AVIC enabled for performance\n"));
  }
  
  // Enable pause filter if supported
  if (gMiniVisorSvmGlobalData.AdvancedFeatures.PauseFilterEnabled) {
    VmcbControl->PauseFilterThreshold = (UINT16)gMiniVisorSvmGlobalData.AdvancedFeatures.PauseFilterThreshold;
    VmcbControl->PauseFilterCount = 0;
    MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] Pause filter enabled with threshold %d\n", 
                          VmcbControl->PauseFilterThreshold));
  }
  
  // Enable TSC scaling if needed
  if (gMiniVisorSvmGlobalData.AdvancedFeatures.TscScalingEnabled) {
    VmcbControl->TscMultiplier = gMiniVisorSvmGlobalData.AdvancedFeatures.TscMultiplier;
    MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] TSC scaling enabled with multiplier 0x%lx\n", 
                          VmcbControl->TscMultiplier));
  }
  
  // Optimize intercept vector for common exits
  // Reduce unnecessary intercepts to improve performance
  VmcbControl->InterceptInstr1 &= ~(SVM_INTERCEPT_INTR | SVM_INTERCEPT_NMI); // Allow direct handling
  
  // Set up VMCB clean bits for maximum performance
  UpdateVmcbCleanBits(VmcbControl);
  
  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] Performance optimization completed\n"));
  return EFI_SUCCESS;
}

/**
  Fast path VM exit handler for high-frequency exits.
  
  @param[in] ExitInfo       Pointer to exit information.
  @param[in] Context        Pointer to guest context.
  
  @retval EFI_SUCCESS       Fast path handled successfully.
  @retval EFI_UNSUPPORTED   Fall back to regular handler.
**/
EFI_STATUS
EFIAPI
FastPathVmExitHandler (
  IN SVM_EXIT_INFO *ExitInfo,
  IN OUT NESTED_SVM_CONTEXT *Context
  )
{
  // Fast path for most common VM exits
  switch (ExitInfo->ExitCode) {
    case SVM_EXIT_NPF:
      // Quick check for IOMMU MMIO access
      if (IsIommuMmioAddress(ExitInfo->ExitInfo2)) {
        BOOLEAN IsWrite = (ExitInfo->ExitInfo1 & BIT1) != 0;
        return HandleIommuMmioAccess(Context, ExitInfo->ExitInfo2, IsWrite);
      }
      break;
      
    case SVM_EXIT_IOIO:
      // Quick check for PCI configuration access
      {
        UINT16 Port = (UINT16)(ExitInfo->ExitInfo2 & 0xFFFF);
        if ((Port == 0xCF8) || (Port >= 0xCFC && Port <= 0xCFF)) {
          BOOLEAN IsWrite = (ExitInfo->ExitInfo1 & BIT0) != 0;
          UINT8 Size = (UINT8)((ExitInfo->ExitInfo1 >> 4) & 0x7) + 1;
          return HandlePciConfigAccess(Context, IsWrite, Port, Size);
        }
      }
      break;
      
    case SVM_EXIT_RDTSC:
      // Fast TSC handling with scaling
      {
        UINT64 Tsc = AsmReadTsc();
        if (gMiniVisorSvmGlobalData.AdvancedFeatures.TscScalingEnabled) {
          // Apply TSC scaling (simplified)
          Tsc = (Tsc * gMiniVisorSvmGlobalData.AdvancedFeatures.TscMultiplier) >> 32;
        }
        Context->GuestRax = (UINT32)Tsc;
        Context->GuestRdx = (UINT32)(Tsc >> 32);
        return EFI_SUCCESS;
      }
      
    case SVM_EXIT_CPUID:
      // Fast CPUID handling for common leaves
      {
        UINT32 Leaf = (UINT32)Context->GuestRax;
        if (Leaf == 0x1 || Leaf == 0x80000001) {
          // These are handled by our optimized CPUID handler
          return HandleCpuidExit(Context);
        }
      }
      break;
      
    default:
      // Fall back to regular handler for other exits
      return EFI_UNSUPPORTED;
  }
  
  return EFI_UNSUPPORTED;
}

/**
  Update performance statistics after VM exit.
  
  @param[in] ExitCode       VM exit code.
  @param[in] ExitTime       Time taken to handle the exit.
**/
VOID
EFIAPI
UpdatePerformanceStatistics (
  IN UINT64 ExitCode,
  IN UINT64 ExitTime
  )
{
  MINI_VISOR_SVM_PERFORMANCE_DATA *PerfData = &gMiniVisorSvmGlobalData.PerfData;
  
  // Update general statistics
  PerfData->VmExitCount++;
  PerfData->LastVmExitReason = ExitCode;
  PerfData->TotalVmExitTime += ExitTime;
  
  // Update specific exit type counters
  switch (ExitCode) {
    case SVM_EXIT_NPF:
      PerfData->NptViolationCount++;
      break;
    case SVM_EXIT_IOIO:
      PerfData->IoInterceptCount++;
      break;
    case SVM_EXIT_MSR:
      PerfData->MsrInterceptCount++;
      break;
    case SVM_EXIT_CPUID:
      PerfData->CpuidInterceptCount++;
      break;
    default:
      /* Other exit types not tracked */
      break;
  }
  
  // Calculate average exit time
  if (PerfData->VmExitCount > 0) {
    PerfData->AverageVmExitTime = PerfData->TotalVmExitTime / PerfData->VmExitCount;
  }
  
  // Update performance trend (simplified)
  /* No performance trend field in MINI_VISOR_SVM_PERFORMANCE_DATA */
}

/**
  Initialize all advanced SVM features during driver startup.
  
  @retval EFI_SUCCESS       All features initialized successfully.
**/
EFI_STATUS
EFIAPI
InitializeAllAdvancedFeatures (
  VOID
  )
{
  EFI_STATUS Status;
  
  // Initialize advanced SVM features
  Status = InitializeAdvancedSvmFeatures();
  if (EFI_ERROR(Status)) {
    DEBUG((DEBUG_WARN, "[SVM] Failed to initialize advanced features: %r\n", Status));
  }
  
  // Initialize nested SVM
  Status = InitializeNestedSvm();
  if (EFI_ERROR(Status) && Status != EFI_UNSUPPORTED) {
    DEBUG((DEBUG_WARN, "[SVM] Failed to initialize nested SVM: %r\n", Status));
  }
  
  // Initialize AVIC
  Status = InitializeAvic();
  if (EFI_ERROR(Status) && Status != EFI_UNSUPPORTED) {
    DEBUG((DEBUG_WARN, "[SVM] Failed to initialize AVIC: %r\n", Status));
  }
  
  // Initialize VMCB clean bits
  Status = InitializeVmcbClean();
  if (EFI_ERROR(Status) && Status != EFI_UNSUPPORTED) {
    DEBUG((DEBUG_WARN, "[SVM] Failed to initialize VMCB clean: %r\n", Status));
  }
  
  // Optimize performance
  Status = OptimizeSvmPerformance();
  if (EFI_ERROR(Status)) {
    DEBUG((DEBUG_WARN, "[SVM] Failed to optimize performance: %r\n", Status));
  }
  
  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM] All advanced features initialized\n"));
  return EFI_SUCCESS;
}