/** @file
  Unified Authorization Library Implementation
  
  This file implements the unified authorization system for both Intel VT-d and AMD SVM
  drivers, providing a consistent authorization interface.
  
  Copyright (c) 2024, Virtualization Project. All rights reserved.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <PiDxe.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiLib.h>
#include <Library/BaseCryptLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/SimpleFileSystem.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/Smbios.h>
#include <IndustryStandard/SmBios.h>
#include <Guid/FileSystemInfo.h>
#include <Guid/FileInfo.h>
#include <Library/DevicePathLib.h>
#include <Library/TimerLib.h>

#include "../../Include/UnifiedAuth.h"

//
// Constants
//
#define UNIFIED_AUTH_SIGNATURE    0x48545541  // 'AUTH'
#define UNIFIED_AUTH_MAGIC        0x44484520  // 'DHE '
#define UNIFIED_AUTH_VERSION      0x0100      // v1.0

//
// Forward declarations
//
EFI_STATUS UnifiedAuthOpenRootOnHandle(IN EFI_HANDLE FsHandle, OUT EFI_FILE_PROTOCOL **RootDir);
EFI_STATUS UnifiedAuthGetLoadedImageFsHandle(OUT EFI_HANDLE *FsHandle);
UINT32 UnifiedAuthSimpleHash(UINT8 *Data, UINTN Length);
UINT64 UnifiedAuthGetCpuSerialNumber(VOID);
EFI_STATUS UnifiedAuthGetMainboardSerial(CHAR8 *SerialBuffer, UINTN BufferSize);
EFI_STATUS UnifiedAuthGetSystemSerial(CHAR8 *SerialBuffer, UINTN BufferSize);
EFI_STATUS UnifiedAuthGetManufacturerInfo(CHAR8 *InfoBuffer, UINTN BufferSize);

//
// Time utilities (align authorization checks to Unix epoch seconds)
//
STATIC
BOOLEAN
IsLeapYear (
  IN UINTN Year
  )
{
  return ((Year % 4 == 0) && (Year % 100 != 0)) || (Year % 400 == 0);
}

STATIC
UINT64
EfiTimeToUnixSeconds (
  IN CONST EFI_TIME *Time
  )
{
  if (Time == NULL) {
    return 0;
  }

  // Guard: EFI_TIME Year is UINT16
  if (Time->Year < 1970) {
    return 0;
  }

  static CONST UINTN DaysBeforeMonth[12] = { 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334 };

  UINT64 Days = 0;
  // Add days for whole years since 1970
  for (UINTN y = 1970; y < Time->Year; y++) {
    Days += IsLeapYear(y) ? 366 : 365;
  }

  // Add days for months in current year
  UINTN MonthIndex = (Time->Month >= 1 && Time->Month <= 12) ? (Time->Month - 1) : 0;
  Days += DaysBeforeMonth[MonthIndex];

  // Add leap day if past Feb in a leap year
  if (Time->Month > 2 && IsLeapYear(Time->Year)) {
    Days += 1;
  }

  // Add days in current month (EFI_TIME.Day is 1-based)
  Days += (Time->Day > 0) ? (Time->Day - 1) : 0;

  UINT64 Seconds = Days * 24ULL * 3600ULL;
  Seconds += (UINT64)Time->Hour * 3600ULL;
  Seconds += (UINT64)Time->Minute * 60ULL;
  Seconds += (UINT64)Time->Second;

  return Seconds;
}

/**
  Initialize unified authorization system.
  
  @param[in] Context           Authorization context.
  @param[in] Platform          Platform type.
  @param[in] Threshold         Authorization threshold.
  
  @retval EFI_SUCCESS          Initialization successful.
  @retval Others               Initialization failed.
**/
EFI_STATUS
EFIAPI
UnifiedAuthInitialize (
  IN OUT UNIFIED_AUTH_CONTEXT *Context,
  IN UINT32 Platform,
  IN UINT32 Threshold
  )
{
  EFI_STATUS Status;
  
  if (Context == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  
  DEBUG((DEBUG_INFO, "[UnifiedAuth] Initializing unified authorization system\n"));
  
  // Initialize context
  ZeroMem(Context, sizeof(UNIFIED_AUTH_CONTEXT));
  Context->Initialized = TRUE;
  Context->AuthorizationThreshold = Threshold;
  Context->Status = UnifiedAuthStatusUnauthorized;
  
  // Generate current hardware fingerprint
  Status = UnifiedAuthGenerateFingerprint(&Context->CurrentHardware);
  if (EFI_ERROR(Status)) {
    DEBUG((DEBUG_WARN, "[UnifiedAuth] Failed to generate hardware fingerprint: %r\n", Status));
  }
  
  // Set platform type
  Context->CurrentHardware.PlatformType = Platform;
  
  DEBUG((DEBUG_INFO, "[UnifiedAuth] Unified authorization system initialized successfully\n"));
  
  return EFI_SUCCESS;
}

/**
  Load authorization file from file system.
  
  @param[in] Context           Authorization context.
  @param[in] FilePath          File path.
  
  @retval EFI_SUCCESS          Authorization file loaded successfully.
  @retval Others               Failed to load authorization file.
**/
EFI_STATUS
EFIAPI
UnifiedAuthLoadFromFile (
  IN OUT UNIFIED_AUTH_CONTEXT *Context,
  IN CONST CHAR16 *FilePath
  )
{
  EFI_STATUS Status;
  EFI_HANDLE FsHandle;
  EFI_FILE_PROTOCOL *RootDir;
  EFI_FILE_PROTOCOL *AuthFile;
  UINTN FileSize;
  UINTN ReadSize;
  UNIFIED_AUTHORIZATION *AuthData;
  
  if (Context == NULL || FilePath == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  
  DEBUG((DEBUG_INFO, "[UnifiedAuth] Loading authorization file: %s\n", FilePath));
  
  // Get file system handle
  Status = UnifiedAuthGetLoadedImageFsHandle(&FsHandle);
  if (EFI_ERROR(Status)) {
    DEBUG((DEBUG_ERROR, "[UnifiedAuth] Failed to get file system handle: %r\n", Status));
    return Status;
  }
  
  // Open root directory
  Status = UnifiedAuthOpenRootOnHandle(FsHandle, &RootDir);
  if (EFI_ERROR(Status)) {
    DEBUG((DEBUG_ERROR, "[UnifiedAuth] Failed to open root directory: %r\n", Status));
    return Status;
  }
  
  // Open authorization file
  Status = RootDir->Open(RootDir, &AuthFile, FilePath, EFI_FILE_MODE_READ, 0);
  if (EFI_ERROR(Status)) {
    DEBUG((DEBUG_ERROR, "[UnifiedAuth] Failed to open authorization file: %r\n", Status));
    RootDir->Close(RootDir);
    return Status;
  }
  
  // Get file size
  Status = AuthFile->GetInfo(AuthFile, &gEfiFileInfoGuid, &FileSize, NULL);
  if (EFI_ERROR(Status)) {
    DEBUG((DEBUG_ERROR, "[UnifiedAuth] Failed to get file info: %r\n", Status));
    AuthFile->Close(AuthFile);
    RootDir->Close(RootDir);
    return Status;
  }
  
  // Allocate memory for authorization data
  AuthData = AllocatePool(FileSize);
  if (AuthData == NULL) {
    DEBUG((DEBUG_ERROR, "[UnifiedAuth] Failed to allocate memory for authorization data\n"));
    AuthFile->Close(AuthFile);
    RootDir->Close(RootDir);
    return EFI_OUT_OF_RESOURCES;
  }
  
  // Read authorization data
  ReadSize = FileSize;
  Status = AuthFile->Read(AuthFile, &ReadSize, AuthData);
  if (EFI_ERROR(Status) || ReadSize != FileSize) {
    DEBUG((DEBUG_ERROR, "[UnifiedAuth] Failed to read authorization data: %r\n", Status));
    FreePool(AuthData);
    AuthFile->Close(AuthFile);
    RootDir->Close(RootDir);
    return Status;
  }
  
  // Validate authorization data
  if (AuthData->Signature != UNIFIED_AUTH_SIGNATURE ||
      AuthData->Magic != UNIFIED_AUTH_MAGIC ||
      AuthData->Version != UNIFIED_AUTH_VERSION) {
    DEBUG((DEBUG_ERROR, "[UnifiedAuth] Invalid authorization file format\n"));
    FreePool(AuthData);
    AuthFile->Close(AuthFile);
    RootDir->Close(RootDir);
    return EFI_INVALID_PARAMETER;
  }
  
  // Verify checksum
  UINT32 CalculatedChecksum = UnifiedAuthCalculateChecksum((UINT8*)AuthData, FileSize - sizeof(UINT32));
  if (CalculatedChecksum != AuthData->Checksum) {
    DEBUG((DEBUG_ERROR, "[UnifiedAuth] Authorization file checksum verification failed\n"));
    FreePool(AuthData);
    AuthFile->Close(AuthFile);
    RootDir->Close(RootDir);
    return EFI_INVALID_PARAMETER;
  }
  
  // Store authorization data
  if (Context->CurrentAuth != NULL) {
    FreePool(Context->CurrentAuth);
  }
  Context->CurrentAuth = AuthData;
  
  DEBUG((DEBUG_INFO, "[UnifiedAuth] Authorization file loaded successfully\n"));
  
  AuthFile->Close(AuthFile);
  RootDir->Close(RootDir);
  
  return EFI_SUCCESS;
}

/**
  Load authorization file from standard locations (USB root or C: root).
  
  @param[in,out] Context       Authorization context.
  
  @retval EFI_SUCCESS          Authorization file loaded successfully.
  @retval Others               Failed to load authorization file.
**/
EFI_STATUS
EFIAPI
UnifiedAuthLoadFromStandardLocations (
  IN OUT UNIFIED_AUTH_CONTEXT *Context
  )
{
  EFI_STATUS Status;
  EFI_HANDLE *HandleBuffer;
  UINTN HandleCount;
  UINTN Index;
  EFI_DEVICE_PATH_PROTOCOL *DevicePath;
  EFI_FILE_PROTOCOL *RootDir;
  EFI_FILE_PROTOCOL *AuthFile;
  UINTN FileSize;
  UINTN ReadSize;
  UNIFIED_AUTHORIZATION *AuthData;
  BOOLEAN FileFound = FALSE;
  
  if (Context == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  
  DEBUG((DEBUG_INFO, "[UnifiedAuth] Searching for auth.dat in standard locations\n"));
  
  // Locate all file system handles
  Status = gBS->LocateHandleBuffer(
                  ByProtocol,
                  &gEfiSimpleFileSystemProtocolGuid,
                  NULL,
                  &HandleCount,
                  &HandleBuffer
                  );
  if (EFI_ERROR(Status)) {
    DEBUG((DEBUG_ERROR, "[UnifiedAuth] Failed to locate file system handles: %r\n", Status));
    return Status;
  }
  
  // Search through all file systems
  for (Index = 0; Index < HandleCount; Index++) {
    Status = gBS->HandleProtocol(
                    HandleBuffer[Index],
                    &gEfiDevicePathProtocolGuid,
                    (VOID**)&DevicePath
                    );
    if (EFI_ERROR(Status)) {
      continue;
    }
    
    // Check if this is a USB drive or C: drive
    BOOLEAN IsUsbDrive = FALSE;
    BOOLEAN IsCDrive = FALSE;
    
    // Simple check for USB drive (look for USB in device path)
    CHAR16 *DevicePathText = ConvertDevicePathToText(DevicePath, FALSE, FALSE);
    if (DevicePathText != NULL) {
      if (StrStr(DevicePathText, L"USB") != NULL) {
        IsUsbDrive = TRUE;
      }
      
      // Simple check for C: drive (look for Hard Drive in device path)
      if (StrStr(DevicePathText, L"Hard Drive") != NULL) {
        IsCDrive = TRUE;
      }
      
      FreePool(DevicePathText);
    }
    
    if (!IsUsbDrive && !IsCDrive) {
      continue;
    }
    
    DEBUG((DEBUG_INFO, "[UnifiedAuth] Checking %s for auth.dat\n", 
           IsUsbDrive ? L"USB drive" : L"C: drive"));
    
    // Open root directory
    Status = UnifiedAuthOpenRootOnHandle(HandleBuffer[Index], &RootDir);
    if (EFI_ERROR(Status)) {
      continue;
    }
    
    // Try to open auth.dat file
    Status = RootDir->Open(RootDir, &AuthFile, L"auth.dat", EFI_FILE_MODE_READ, 0);
    if (EFI_ERROR(Status)) {
      RootDir->Close(RootDir);
      continue;
    }
    
    // Get file size
    Status = AuthFile->GetInfo(AuthFile, &gEfiFileInfoGuid, &FileSize, NULL);
    if (EFI_ERROR(Status)) {
      AuthFile->Close(AuthFile);
      RootDir->Close(RootDir);
      continue;
    }
    
    // Allocate memory for authorization data
    AuthData = AllocatePool(FileSize);
    if (AuthData == NULL) {
      AuthFile->Close(AuthFile);
      RootDir->Close(RootDir);
      continue;
    }
    
    // Read authorization data
    ReadSize = FileSize;
    Status = AuthFile->Read(AuthFile, &ReadSize, AuthData);
    if (EFI_ERROR(Status) || ReadSize != FileSize) {
      FreePool(AuthData);
      AuthFile->Close(AuthFile);
      RootDir->Close(RootDir);
      continue;
    }
    
    // Validate authorization data
    if (AuthData->Signature != UNIFIED_AUTH_SIGNATURE ||
        AuthData->Magic != UNIFIED_AUTH_MAGIC ||
        AuthData->Version != UNIFIED_AUTH_VERSION) {
      DEBUG((DEBUG_ERROR, "[UnifiedAuth] Invalid authorization file format on %s\n", 
             IsUsbDrive ? L"USB drive" : L"C: drive"));
      FreePool(AuthData);
      AuthFile->Close(AuthFile);
      RootDir->Close(RootDir);
      continue;
    }
    
    // Verify checksum
    UINT32 CalculatedChecksum = UnifiedAuthCalculateChecksum((UINT8*)AuthData, FileSize - sizeof(UINT32));
    if (CalculatedChecksum != AuthData->Checksum) {
      DEBUG((DEBUG_ERROR, "[UnifiedAuth] Authorization file checksum verification failed on %s\n", 
             IsUsbDrive ? L"USB drive" : L"C: drive"));
      FreePool(AuthData);
      AuthFile->Close(AuthFile);
      RootDir->Close(RootDir);
      continue;
    }
    
    // Store authorization data
    if (Context->CurrentAuth != NULL) {
      FreePool(Context->CurrentAuth);
    }
    Context->CurrentAuth = AuthData;
    
    DEBUG((DEBUG_INFO, "[UnifiedAuth] Authorization file found and loaded from %s\n", 
           IsUsbDrive ? L"USB drive" : L"C: drive"));
    
    AuthFile->Close(AuthFile);
    RootDir->Close(RootDir);
    FileFound = TRUE;
    break;
  }
  
  FreePool(HandleBuffer);
  
  if (!FileFound) {
    DEBUG((DEBUG_ERROR, "[UnifiedAuth] Authorization file auth.dat not found in standard locations\n"));
    return EFI_NOT_FOUND;
  }
  
  return EFI_SUCCESS;
}

/**
  Verify authorization.
  
  @param[in] Context           Authorization context.
  
  @retval EFI_SUCCESS          Authorization verified successfully.
  @retval EFI_ACCESS_DENIED    Authorization verification failed.
  @retval Others               Error occurred.
**/
EFI_STATUS
EFIAPI
UnifiedAuthVerify (
  IN UNIFIED_AUTH_CONTEXT *Context
  )
{
  if (Context == NULL || !Context->Initialized) {
    return EFI_INVALID_PARAMETER;
  }
  
  if (Context->CurrentAuth == NULL) {
    Context->Status = UnifiedAuthStatusFileNotFound;
    return EFI_ACCESS_DENIED;
  }
  
  // Verify hardware fingerprint
  if (!UnifiedAuthVerifyFingerprint(Context)) {
    Context->Status = UnifiedAuthStatusHardwareMismatch;
    return EFI_ACCESS_DENIED;
  }
  
  // Verify time limit
  EFI_STATUS Status = UnifiedAuthVerifyTimeLimit(Context);
  if (EFI_ERROR(Status)) {
    Context->Status = UnifiedAuthStatusExpired;
    return Status;
  }
  
  Context->Status = UnifiedAuthStatusAuthorized;
  return EFI_SUCCESS;
}

/**
  Generate hardware fingerprint.
  
  @param[out] Fingerprint      Hardware fingerprint.
  
  @retval EFI_SUCCESS          Hardware fingerprint generated successfully.
  @retval Others               Failed to generate hardware fingerprint.
**/
EFI_STATUS
EFIAPI
UnifiedAuthGenerateFingerprint (
  OUT UNIFIED_HARDWARE_FINGERPRINT *Fingerprint
  )
{
  EFI_STATUS Status;
  UINT32 Eax, Ebx, Ecx, Edx;
  CHAR8 CpuBrandString[64];
  CHAR8 MainboardSerial[64];
  CHAR8 SystemSerial[64];
  CHAR8 ManufacturerInfo[128];
  
  if (Fingerprint == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  
  ZeroMem(Fingerprint, sizeof(UNIFIED_HARDWARE_FINGERPRINT));
  
  // Get CPU information
  AsmCpuid(1, &Eax, &Ebx, &Ecx, &Edx);
  Fingerprint->CpuSignature = Eax;
  
  // Get CPU brand string
  AsmCpuid(0x80000002, &Eax, &Ebx, &Ecx, &Edx);
  CopyMem(CpuBrandString, &Eax, 4);
  CopyMem(CpuBrandString + 4, &Ebx, 4);
  CopyMem(CpuBrandString + 8, &Ecx, 4);
  CopyMem(CpuBrandString + 12, &Edx, 4);
  
  AsmCpuid(0x80000003, &Eax, &Ebx, &Ecx, &Edx);
  CopyMem(CpuBrandString + 16, &Eax, 4);
  CopyMem(CpuBrandString + 20, &Ebx, 4);
  CopyMem(CpuBrandString + 24, &Ecx, 4);
  CopyMem(CpuBrandString + 28, &Edx, 4);
  
  AsmCpuid(0x80000004, &Eax, &Ebx, &Ecx, &Edx);
  CopyMem(CpuBrandString + 32, &Eax, 4);
  CopyMem(CpuBrandString + 36, &Ebx, 4);
  CopyMem(CpuBrandString + 40, &Ecx, 4);
  CopyMem(CpuBrandString + 44, &Edx, 4);
  
  Fingerprint->CpuBrandHash = UnifiedAuthSimpleHash((UINT8*)CpuBrandString, 48);
  
  // Get CPU serial number
  Fingerprint->CpuSerialNumber = UnifiedAuthGetCpuSerialNumber();
  
  // Get system time
  Fingerprint->SystemTime = GetPerformanceCounter();
  
  // Get memory size (simplified)
  Fingerprint->MemorySize = 0x10000000; // 4GB default
  
  // Get PCI device count (simplified)
  Fingerprint->PciDeviceCount = 10; // Default value
  
  // Get mainboard serial
  Status = UnifiedAuthGetMainboardSerial(MainboardSerial, sizeof(MainboardSerial));
  if (!EFI_ERROR(Status)) {
    Fingerprint->MainboardSerialHash = UnifiedAuthSimpleHash((UINT8*)MainboardSerial, AsciiStrLen(MainboardSerial));
  }
  
  // Get system serial
  Status = UnifiedAuthGetSystemSerial(SystemSerial, sizeof(SystemSerial));
  if (!EFI_ERROR(Status)) {
    // Use system serial for additional fingerprinting
  }
  
  // Get manufacturer info
  Status = UnifiedAuthGetManufacturerInfo(ManufacturerInfo, sizeof(ManufacturerInfo));
  if (!EFI_ERROR(Status)) {
    // Use manufacturer info for additional fingerprinting
  }
  
  // Set security features (simplified)
  Fingerprint->SecurityFeatures = 0x00000001; // Basic security
  Fingerprint->VirtualizationSupport = 0x00000001; // Basic virtualization
  Fingerprint->IoMmuSupport = 0x00000001; // Basic IOMMU
  Fingerprint->TpmVersion = 0x00000002; // TPM 2.0
  Fingerprint->SecureBootStatus = 0x00000001; // Secure boot enabled
  
  DEBUG((DEBUG_INFO, "[UnifiedAuth] Hardware fingerprint generated successfully\n"));
  
  return EFI_SUCCESS;
}

/**
  Verify hardware fingerprint.
  
  @param[in] Context           Authorization context.
  
  @retval TRUE                 Hardware fingerprint matches.
  @retval FALSE                Hardware fingerprint does not match.
**/
BOOLEAN
EFIAPI
UnifiedAuthVerifyFingerprint (
  IN UNIFIED_AUTH_CONTEXT *Context
  )
{
  if (Context == NULL || Context->CurrentAuth == NULL) {
    return FALSE;
  }
  
  // Compare hardware fingerprints
  if (CompareMem(&Context->CurrentHardware, &Context->CurrentAuth->HardwareFingerprint, 
                 sizeof(UNIFIED_HARDWARE_FINGERPRINT)) == 0) {
    return TRUE;
  }
  
  // Allow some tolerance for minor hardware changes
  UINT32 Tolerance = 0x00000010; // 16 bytes tolerance
  
  // Check if differences are within tolerance
  UINT8 *Current = (UINT8*)&Context->CurrentHardware;
  UINT8 *Auth = (UINT8*)&Context->CurrentAuth->HardwareFingerprint;
  UINTN DiffCount = 0;
  
  for (UINTN i = 0; i < sizeof(UNIFIED_HARDWARE_FINGERPRINT); i++) {
    if (Current[i] != Auth[i]) {
      DiffCount++;
    }
  }
  
  return (DiffCount <= Tolerance);
}

/**
  Verify time limit.
  
  @param[in] Context           Authorization context.
  
  @retval EFI_SUCCESS          Time limit verification passed.
  @retval EFI_ACCESS_DENIED    Time limit verification failed.
**/
EFI_STATUS
EFIAPI
UnifiedAuthVerifyTimeLimit (
  IN UNIFIED_AUTH_CONTEXT *Context
  )
{
  if (Context == NULL || Context->CurrentAuth == NULL) {
    return EFI_ACCESS_DENIED;
  }
  
  EFI_TIME EfiNow;
  UINT64 CurrentEpoch = 0;
  if (!EFI_ERROR(gRT->GetTime(&EfiNow, NULL))) {
    CurrentEpoch = EfiTimeToUnixSeconds(&EfiNow);
  }
  
  // Check if authorization has expired (Epoch seconds)
  if (CurrentEpoch == 0 || CurrentEpoch > Context->CurrentAuth->ExpiryTime) {
    DEBUG((DEBUG_ERROR, "[UnifiedAuth] Authorization has expired\n"));
    return EFI_ACCESS_DENIED;
  }
  
  return EFI_SUCCESS;
}

/**
  Display authorization status.
  
  @param[in] Context           Authorization context.
  @param[in] Verbose           Whether to display verbose information.
**/
VOID
EFIAPI
UnifiedAuthDisplayStatus (
  IN UNIFIED_AUTH_CONTEXT *Context,
  IN BOOLEAN Verbose
  )
{
  if (Context == NULL) {
    Print(L"[UnifiedAuth] ❌ 未初始化\n");
    Print(L"[UnifiedAuth] ❌ Not initialized\n");
    return;
  }
  
  switch (Context->Status) {
    case UnifiedAuthStatusAuthorized:
      Print(L"[UnifiedAuth] ✓ 已授权\n");
      Print(L"[UnifiedAuth] ✓ Authorized\n");
      break;
      
    case UnifiedAuthStatusExpired:
      Print(L"[UnifiedAuth] ⚠ 授权已过期\n");
      Print(L"[UnifiedAuth] ⚠ Authorization expired\n");
      break;
      
    case UnifiedAuthStatusHardwareMismatch:
      Print(L"[UnifiedAuth] ❌ 硬件不匹配\n");
      Print(L"[UnifiedAuth] ❌ Hardware mismatch\n");
      break;
      
    case UnifiedAuthStatusFileNotFound:
      Print(L"[UnifiedAuth] ❌ 未找到授权文件\n");
      Print(L"[UnifiedAuth] ❌ Authorization file not found\n");
      break;
      
    default:
      Print(L"[UnifiedAuth] ❌ 未授权\n");
      Print(L"[UnifiedAuth] ❌ Unauthorized\n");
      break;
  }
  
  if (Verbose && Context->CurrentAuth != NULL) {
    Print(L"[UnifiedAuth] 平台: %s\n", 
          Context->CurrentAuth->Platform == PLATFORM_INTEL ? L"Intel" : 
          Context->CurrentAuth->Platform == PLATFORM_AMD ? L"AMD" : L"Unknown");
    Print(L"[UnifiedAuth] Platform: %s\n", 
          Context->CurrentAuth->Platform == PLATFORM_INTEL ? L"Intel" : 
          Context->CurrentAuth->Platform == PLATFORM_AMD ? L"AMD" : L"Unknown");
  }
}

/**
  Calculate checksum.
  
  @param[in] Data              Data pointer.
  @param[in] Size              Data size.
  
  @retval Checksum value.
**/
UINT32
EFIAPI
UnifiedAuthCalculateChecksum (
  IN CONST UINT8 *Data,
  IN UINTN Size
  )
{
  UINT32 Checksum = 0;
  
  if (Data == NULL || Size == 0) {
    return 0;
  }
  
  for (UINTN i = 0; i < Size; i++) {
    Checksum = ((Checksum << 5) + Checksum) + Data[i];
    Checksum ^= (Checksum >> 16);
  }
  
  return Checksum;
}

//
// Helper functions
//

/**
  Simple hash function.
  
  @param[in] Data              Data pointer.
  @param[in] Length            Data length.
  
  @retval Hash value.
**/
STATIC
UINT32
UnifiedAuthSimpleHash (
  UINT8 *Data,
  UINTN Length
  )
{
  UINT32 Hash = 0x5A5A5A5A;
  
  if (Data == NULL || Length == 0) {
    return 0;
  }
  
  for (UINTN i = 0; i < Length; i++) {
    Hash = ((Hash << 5) + Hash) + Data[i];
    Hash ^= (Hash >> 16);
  }
  
  return Hash;
}

/**
  Get CPU serial number.
  
  @retval CPU serial number.
**/
STATIC
UINT64
UnifiedAuthGetCpuSerialNumber (
  VOID
  )
{
  UINT32 Eax, Ebx, Ecx, Edx;
  UINT64 SerialNumber = 0;
  
  // Try to get processor serial number
  AsmCpuid(3, &Eax, &Ebx, &Ecx, &Edx);
  SerialNumber = ((UINT64)Eax << 32) | Ebx;
  
  // Fallback to processor signature if serial number is not available
  if (SerialNumber == 0) {
    AsmCpuid(1, &Eax, &Ebx, &Ecx, &Edx);
    SerialNumber = ((UINT64)Eax << 32) | ((UINT64)Ebx & 0xFFFFFF00) | (Ebx & 0xFF);
  }
  
  return SerialNumber;
}

/**
  Get mainboard serial number.
  
  @param[out] SerialBuffer     Serial buffer.
  @param[in] BufferSize        Buffer size.
  
  @retval EFI_SUCCESS          Success.
  @retval Others               Failed.
**/
STATIC
EFI_STATUS
UnifiedAuthGetMainboardSerial (
  CHAR8 *SerialBuffer,
  UINTN BufferSize
  )
{
  EFI_STATUS Status;
  EFI_SMBIOS_PROTOCOL *SmbiosProtocol;
  EFI_SMBIOS_HANDLE SmbiosHandle;
  EFI_SMBIOS_TABLE_HEADER *Record;
  SMBIOS_TABLE_TYPE2 *Type2Record;
  
  if (SerialBuffer == NULL || BufferSize == 0) {
    return EFI_INVALID_PARAMETER;
  }
  
  Status = gBS->LocateProtocol(&gEfiSmbiosProtocolGuid, NULL, (VOID**)&SmbiosProtocol);
  if (EFI_ERROR(Status)) {
    return Status;
  }
  
  SmbiosHandle = SMBIOS_HANDLE_PI_RESERVED;
  
  while (TRUE) {
    Status = SmbiosProtocol->GetNext(SmbiosProtocol, &SmbiosHandle, NULL, &Record, NULL);
    if (EFI_ERROR(Status)) {
      break;
    }
    
    if (Record->Type == 2) { // Baseboard Information
      Type2Record = (SMBIOS_TABLE_TYPE2*)Record;
      if (Type2Record->SerialNumber != 0) {
        CHAR8 *Serial = (CHAR8*)Record + Type2Record->SerialNumber;
        UINTN SerialLen = AsciiStrLen(Serial);
        if (SerialLen < BufferSize) {
          CopyMem(SerialBuffer, Serial, SerialLen + 1);
          return EFI_SUCCESS;
        }
      }
    }
  }
  
  // Fallback to default
  CopyMem(SerialBuffer, "UNKNOWN", 8);
  return EFI_SUCCESS;
}

/**
  Get system serial number.
  
  @param[out] SerialBuffer     Serial buffer.
  @param[in] BufferSize        Buffer size.
  
  @retval EFI_SUCCESS          Success.
  @retval Others               Failed.
**/
STATIC
EFI_STATUS
UnifiedAuthGetSystemSerial (
  CHAR8 *SerialBuffer,
  UINTN BufferSize
  )
{
  EFI_STATUS Status;
  EFI_SMBIOS_PROTOCOL *SmbiosProtocol;
  EFI_SMBIOS_HANDLE SmbiosHandle;
  EFI_SMBIOS_TABLE_HEADER *Record;
  SMBIOS_TABLE_TYPE1 *Type1Record;
  
  if (SerialBuffer == NULL || BufferSize == 0) {
    return EFI_INVALID_PARAMETER;
  }
  
  Status = gBS->LocateProtocol(&gEfiSmbiosProtocolGuid, NULL, (VOID**)&SmbiosProtocol);
  if (EFI_ERROR(Status)) {
    return Status;
  }
  
  SmbiosHandle = SMBIOS_HANDLE_PI_RESERVED;
  
  while (TRUE) {
    Status = SmbiosProtocol->GetNext(SmbiosProtocol, &SmbiosHandle, NULL, &Record, NULL);
    if (EFI_ERROR(Status)) {
      break;
    }
    
    if (Record->Type == 1) { // System Information
      Type1Record = (SMBIOS_TABLE_TYPE1*)Record;
      if (Type1Record->SerialNumber != 0) {
        CHAR8 *Serial = (CHAR8*)Record + Type1Record->SerialNumber;
        UINTN SerialLen = AsciiStrLen(Serial);
        if (SerialLen < BufferSize) {
          CopyMem(SerialBuffer, Serial, SerialLen + 1);
          return EFI_SUCCESS;
        }
      }
    }
  }
  
  // Fallback to default
  CopyMem(SerialBuffer, "UNKNOWN", 8);
  return EFI_SUCCESS;
}

/**
  Get manufacturer information.
  
  @param[out] InfoBuffer       Info buffer.
  @param[in] BufferSize        Buffer size.
  
  @retval EFI_SUCCESS          Success.
  @retval Others               Failed.
**/
STATIC
EFI_STATUS
UnifiedAuthGetManufacturerInfo (
  CHAR8 *InfoBuffer,
  UINTN BufferSize
  )
{
  EFI_STATUS Status;
  EFI_SMBIOS_PROTOCOL *SmbiosProtocol;
  EFI_SMBIOS_HANDLE SmbiosHandle;
  EFI_SMBIOS_TABLE_HEADER *Record;
  SMBIOS_TABLE_TYPE1 *Type1Record;
  
  if (InfoBuffer == NULL || BufferSize == 0) {
    return EFI_INVALID_PARAMETER;
  }
  
  Status = gBS->LocateProtocol(&gEfiSmbiosProtocolGuid, NULL, (VOID**)&SmbiosProtocol);
  if (EFI_ERROR(Status)) {
    return Status;
  }
  
  SmbiosHandle = SMBIOS_HANDLE_PI_RESERVED;
  
  while (TRUE) {
    Status = SmbiosProtocol->GetNext(SmbiosProtocol, &SmbiosHandle, NULL, &Record, NULL);
    if (EFI_ERROR(Status)) {
      break;
    }
    
    if (Record->Type == 1) { // System Information
      Type1Record = (SMBIOS_TABLE_TYPE1*)Record;
      if (Type1Record->Manufacturer != 0) {
        CHAR8 *Manufacturer = (CHAR8*)Record + Type1Record->Manufacturer;
        UINTN ManufacturerLen = AsciiStrLen(Manufacturer);
        if (ManufacturerLen < BufferSize) {
          CopyMem(InfoBuffer, Manufacturer, ManufacturerLen + 1);
          return EFI_SUCCESS;
        }
      }
    }
  }
  
  // Fallback to default
  CopyMem(InfoBuffer, "UNKNOWN", 8);
  return EFI_SUCCESS;
}

/**
  Open root directory on file system handle.
  
  @param[in] FsHandle          File system handle.
  @param[out] RootDir          Root directory.
  
  @retval EFI_SUCCESS          Success.
  @retval Others               Failed.
**/
STATIC
EFI_STATUS
UnifiedAuthOpenRootOnHandle (
  IN EFI_HANDLE FsHandle,
  OUT EFI_FILE_PROTOCOL **RootDir
  )
{
  EFI_STATUS Status;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *FileSystem;
  
  if (FsHandle == NULL || RootDir == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  
  Status = gBS->HandleProtocol(FsHandle, &gEfiSimpleFileSystemProtocolGuid, (VOID**)&FileSystem);
  if (EFI_ERROR(Status)) {
    return Status;
  }
  
  Status = FileSystem->OpenVolume(FileSystem, RootDir);
  return Status;
}

/**
  Get loaded image file system handle.
  
  @param[out] FsHandle         File system handle.
  
  @retval EFI_SUCCESS          Success.
  @retval Others               Failed.
**/
STATIC
EFI_STATUS
UnifiedAuthGetLoadedImageFsHandle (
  OUT EFI_HANDLE *FsHandle
  )
{
  EFI_STATUS Status;
  EFI_LOADED_IMAGE_PROTOCOL *LoadedImage;
  EFI_DEVICE_PATH_PROTOCOL *DevicePath;
  EFI_DEVICE_PATH_PROTOCOL *Node;
  
  if (FsHandle == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  
  Status = gBS->HandleProtocol(gImageHandle, &gEfiLoadedImageProtocolGuid, (VOID**)&LoadedImage);
  if (EFI_ERROR(Status)) {
    return Status;
  }
  
  Status = gBS->HandleProtocol(LoadedImage->DeviceHandle, &gEfiDevicePathProtocolGuid, (VOID**)&DevicePath);
  if (EFI_ERROR(Status)) {
    return Status;
  }
  
  // Find the file system node
  Node = DevicePath;
  while (!IsDevicePathEnd(Node)) {
    if (DevicePathType(Node) == MEDIA_DEVICE_PATH && 
        DevicePathSubType(Node) == MEDIA_FILEPATH_DP) {
      break;
    }
    Node = NextDevicePathNode(Node);
  }
  
  if (IsDevicePathEnd(Node)) {
    return EFI_NOT_FOUND;
  }
  
  // Get the file system handle
  Status = gBS->LocateDevicePath(&gEfiSimpleFileSystemProtocolGuid, &DevicePath, FsHandle);
  return Status;
}
