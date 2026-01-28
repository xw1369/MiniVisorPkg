/** @file
  Unified Authorization System Header
  
  This file defines the unified authorization system for both Intel VT-d and AMD SVM
  drivers, providing a consistent authorization interface.
  
  Copyright (c) 2024, Virtualization Project. All rights reserved.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef UNIFIED_AUTH_H_
#define UNIFIED_AUTH_H_

#include <PiDxe.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiLib.h>
#include <Library/BaseCryptLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>

//
// Platform types
//
#define PLATFORM_UNKNOWN    0
#define PLATFORM_INTEL      1
#define PLATFORM_AMD        2
#define PLATFORM_UNIVERSAL  3

//
// Authorization types
//
#define AUTH_TYPE_BASIC        1
#define AUTH_TYPE_PROFESSIONAL 2
#define AUTH_TYPE_ENTERPRISE   3

//
// Authorization status
//
typedef enum {
  UnifiedAuthStatusUnauthorized = 0,
  UnifiedAuthStatusAuthorized,
  UnifiedAuthStatusExpired,
  UnifiedAuthStatusInvalid,
  UnifiedAuthStatusHardwareMismatch,
  UnifiedAuthStatusFileNotFound
} UNIFIED_AUTH_STATUS;

//
// Hardware fingerprint structure
//
#pragma pack(1)
typedef struct {
  UINT32 CpuSignature;        // CPU signature
  UINT32 CpuBrandHash;        // CPU brand hash
  UINT64 CpuSerialNumber;     // CPU serial number
  UINT64 SystemTime;          // System time
  UINT32 MemorySize;          // Memory size
  UINT16 PciDeviceCount;      // PCI device count
  UINT16 Reserved1;           // Reserved
  UINT32 MainboardSerialHash; // Mainboard serial hash
  UINT32 Reserved2;           // Reserved
  UINT32 PlatformType;        // Platform type (Intel/AMD)
  UINT32 SecurityFeatures;    // Security features
  UINT32 VirtualizationSupport; // Virtualization support
  UINT32 IoMmuSupport;        // IOMMU support
  UINT32 TpmVersion;          // TPM version
  UINT32 SecureBootStatus;    // Secure boot status
} UNIFIED_HARDWARE_FINGERPRINT;
#pragma pack()

//
// Authorization structure
//
#pragma pack(1)
typedef struct {
  UINT32 Signature;           // 'AUTH'
  UINT32 Version;             // Version number
  UINT32 Magic;               // Magic number
  UINT32 TotalSize;           // Total size
  UINT32 AuthType;            // Authorization type
  UINT32 Platform;            // Platform type
  UINT32 IssuedTime;          // Issued timestamp
  UINT32 ExpiryTime;          // Expiry timestamp
  UINT32 UsageCount;          // Usage count (deprecated, always 0)
  UINT32 MaxUsageCount;       // Max usage count (deprecated, always 0)
  UNIFIED_HARDWARE_FINGERPRINT HardwareFingerprint; // Hardware fingerprint
  UINT32 Checksum;            // Checksum
  UINT8  Reserved[64];        // Reserved for future use
} UNIFIED_AUTHORIZATION;
#pragma pack()

//
// Authorization context
//
typedef struct {
  BOOLEAN Initialized;
  UNIFIED_AUTHORIZATION *CurrentAuth;
  UNIFIED_HARDWARE_FINGERPRINT CurrentHardware;
  UNIFIED_AUTH_STATUS Status;
  UINT32 CompatibilityScore;
  UINT32 AuthorizationThreshold;
} UNIFIED_AUTH_CONTEXT;

//
// Function declarations
//

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
  );

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
  );

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
  );

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
  );

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
  );

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
  );

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
  );

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
  );

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
  );

#endif // UNIFIED_AUTH_H_
