/** @file
  MiniVisor Common Framework
  
  Unified common utilities and interfaces to reduce code duplication
  across Intel VT-d and AMD SVM implementations.
  
  Copyright (c) 2024, MiniVisor Project. All rights reserved.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef __MINI_VISOR_COMMON_H__
#define __MINI_VISOR_COMMON_H__

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <MiniVisorSecurity.h>
#include <MiniVisorMemSafety.h>
#include <MiniVisorConcurrency.h>
#include <MiniVisorAntiDetection.h>
#include <MiniVisorReliability.h>
#include <MiniVisorPerformance.h>

//
// Common Framework Version
//
#define MINI_VISOR_COMMON_VERSION       0x00020000
#define COMMON_FRAMEWORK_SIGNATURE      SIGNATURE_32('M','V','C','M')

//
// Virtualization Technology Types
//
typedef enum {
  VirtTechUnknown = 0,
  VirtTechIntelVtd = 1,
  VirtTechAmdSvm = 2,
  VirtTechArmSmmu = 3
} VIRTUALIZATION_TECHNOLOGY;

//
// Common Hardware Information
//
typedef struct {
  UINT32                      Signature;        // Structure signature
  VIRTUALIZATION_TECHNOLOGY   VirtTech;         // Virtualization technology
  UINT32                      CpuVendor;        // CPU vendor ID
  UINT32                      CpuFamily;        // CPU family
  UINT32                      CpuModel;         // CPU model
  UINT32                      CpuStepping;      // CPU stepping
  UINT64                      CpuFeatures;      // CPU feature flags
  UINT32                      CoreCount;        // Number of CPU cores
  UINT32                      ThreadCount;      // Number of threads
  BOOLEAN                     VirtSupported;    // Virtualization supported
  BOOLEAN                     VirtEnabled;      // Virtualization enabled
  CHAR8                       CpuBrandString[48]; // CPU brand string
  CHAR8                       SystemSerial[32]; // System serial number
  CHAR8                       MainboardSerial[32]; // Mainboard serial
} COMMON_HARDWARE_INFO;

//
// Unified Authorization Structure
//
typedef struct {
  UINT32                    Signature;          // Authorization signature
  UINT32                    Version;            // Authorization version
  VIRTUALIZATION_TECHNOLOGY TargetTech;        // Target virtualization tech
  UINT32                    AuthLevel;          // Authorization level
  UINT64                    ExpirationTime;     // Expiration timestamp
  UINT8                     HardwareFingerprint[32]; // Hardware fingerprint
  UINT8                     SecurityHash[32];   // Security hash
  UINT8                     DigitalSignature[256]; // Digital signature
  UINT32                    Flags;              // Authorization flags
  CHAR8                     LicenseInfo[64];    // License information
} UNIFIED_AUTHORIZATION;

//
// Common VM Context
//
typedef struct {
  UINT32                    Signature;          // Context signature
  UINT32                    Version;            // Context version
  VIRTUALIZATION_TECHNOLOGY VirtTech;          // Virtualization technology
  SECURITY_STATE_CONTEXT    *SecurityContext;  // Security context
  STEALTH_CONTEXT           *StealthContext;   // Stealth context
  RELIABILITY_CONTEXT       *ReliabilityContext; // Reliability context
  PERFORMANCE_CONTEXT       *PerformanceContext; // Performance context
  COMMON_HARDWARE_INFO      HardwareInfo;      // Hardware information
  UNIFIED_AUTHORIZATION     Authorization;     // Authorization info
  BOOLEAN                   Initialized;       // Initialization status
  UINT64                    CreationTime;      // Context creation time
  UINT32                    IntegrityCheck;    // Context integrity
} COMMON_VM_CONTEXT;

//
// Common Function Interface
//
typedef struct {
  //
  // Initialization Functions
  //
  EFI_STATUS (*InitializeVirtualization)(IN OUT COMMON_VM_CONTEXT *Context);
  EFI_STATUS (*UninitializeVirtualization)(IN COMMON_VM_CONTEXT *Context);
  
  //
  // Hardware Detection Functions
  //
  EFI_STATUS (*DetectHardwareCapabilities)(OUT COMMON_HARDWARE_INFO *HwInfo);
  EFI_STATUS (*ValidateHardwareCompatibility)(IN COMMON_HARDWARE_INFO *HwInfo);
  
  //
  // Authorization Functions
  //
  EFI_STATUS (*ValidateAuthorization)(IN UNIFIED_AUTHORIZATION *Auth);
  EFI_STATUS (*UpdateAuthorization)(IN OUT UNIFIED_AUTHORIZATION *Auth);
  
  //
  // VM Management Functions
  //
  EFI_STATUS (*StartVirtualMachine)(IN COMMON_VM_CONTEXT *Context);
  EFI_STATUS (*StopVirtualMachine)(IN COMMON_VM_CONTEXT *Context);
  EFI_STATUS (*HandleVmExit)(IN COMMON_VM_CONTEXT *Context, IN UINTN ExitReason);
  
  //
  // Security Functions
  //
  EFI_STATUS (*EnableSecurityFeatures)(IN COMMON_VM_CONTEXT *Context);
  EFI_STATUS (*ConfigureAntiDetection)(IN COMMON_VM_CONTEXT *Context);
  
} COMMON_VIRTUALIZATION_INTERFACE;

//
// Hardware Fingerprinting Functions
//

/**
  Collect comprehensive hardware fingerprint across platforms.
  
  @param[out] HardwareInfo      Hardware information structure
  
  @retval EFI_SUCCESS           Hardware info collected successfully
  @retval EFI_INVALID_PARAMETER Invalid parameters
  @retval EFI_DEVICE_ERROR      Hardware detection failed
**/
EFI_STATUS
EFIAPI
CollectHardwareFingerprint (
  OUT COMMON_HARDWARE_INFO  *HardwareInfo
  );

/**
  Generate unified hardware fingerprint hash.
  
  @param[in]  HardwareInfo      Hardware information
  @param[out] Fingerprint       Generated fingerprint hash
  
  @retval EFI_SUCCESS           Fingerprint generated successfully
  @retval EFI_INVALID_PARAMETER Invalid parameters
**/
EFI_STATUS
EFIAPI
GenerateHardwareFingerprint (
  IN  COMMON_HARDWARE_INFO  *HardwareInfo,
  OUT UINT8                 Fingerprint[32]
  );

/**
  Compare hardware fingerprints with tolerance.
  
  @param[in] Fingerprint1       First fingerprint
  @param[in] Fingerprint2       Second fingerprint
  @param[in] Tolerance          Comparison tolerance (0-100)
  
  @retval TRUE                  Fingerprints match within tolerance
  @retval FALSE                 Fingerprints do not match
**/
BOOLEAN
EFIAPI
CompareHardwareFingerprints (
  IN UINT8  Fingerprint1[32],
  IN UINT8  Fingerprint2[32],
  IN UINT32 Tolerance
  );

//
// Authorization Functions
//

/**
  Validate unified authorization structure.
  
  @param[in] Authorization      Authorization structure to validate
  @param[in] HardwareInfo       Current hardware information
  
  @retval EFI_SUCCESS           Authorization is valid
  @retval EFI_INVALID_PARAMETER Invalid parameters
  @retval EFI_SECURITY_VIOLATION Authorization validation failed
  @retval EFI_ACCESS_DENIED     Authorization expired or insufficient
**/
EFI_STATUS
EFIAPI
ValidateUnifiedAuthorization (
  IN UNIFIED_AUTHORIZATION  *Authorization,
  IN COMMON_HARDWARE_INFO   *HardwareInfo
  );

/**
  Generate authorization hash for integrity verification.
  
  @param[in]  Authorization     Authorization structure
  @param[out] Hash              Generated hash
  
  @retval EFI_SUCCESS           Hash generated successfully
  @retval EFI_INVALID_PARAMETER Invalid parameters
**/
EFI_STATUS
EFIAPI
GenerateAuthorizationHash (
  IN  UNIFIED_AUTHORIZATION  *Authorization,
  OUT UINT8                  Hash[32]
  );

//
// Common VM Context Management
//

/**
  Initialize common VM context with all frameworks.
  
  @param[out] VmContext         VM context to initialize
  @param[in]  VirtTech          Virtualization technology
  @param[in]  SecurityLevel     Security level
  @param[in]  StealthLevel      Stealth level
  
  @retval EFI_SUCCESS           Context initialized successfully
  @retval EFI_INVALID_PARAMETER Invalid parameters
  @retval EFI_OUT_OF_RESOURCES  Insufficient resources
**/
EFI_STATUS
EFIAPI
InitializeCommonVmContext (
  OUT COMMON_VM_CONTEXT           **VmContext,
  IN  VIRTUALIZATION_TECHNOLOGY   VirtTech,
  IN  MINI_VISOR_SECURITY_LEVEL   SecurityLevel,
  IN  STEALTH_LEVEL               StealthLevel
  );

/**
  Destroy common VM context and cleanup all resources.
  
  @param[in] VmContext          VM context to destroy
  
  @retval EFI_SUCCESS           Context destroyed successfully
  @retval EFI_INVALID_PARAMETER Invalid parameters
**/
EFI_STATUS
EFIAPI
DestroyCommonVmContext (
  IN COMMON_VM_CONTEXT  *VmContext
  );

/**
  Validate VM context integrity.
  
  @param[in] VmContext          VM context to validate
  
  @retval EFI_SUCCESS           Context integrity verified
  @retval EFI_INVALID_PARAMETER Invalid context
  @retval EFI_CRC_ERROR         Integrity check failed
**/
EFI_STATUS
EFIAPI
ValidateVmContextIntegrity (
  IN COMMON_VM_CONTEXT  *VmContext
  );

//
// Cross-Platform Compatibility Functions
//

/**
  Detect available virtualization technologies.
  
  @param[out] SupportedTech     Bitmask of supported technologies
  @param[out] PreferredTech     Recommended technology
  
  @retval EFI_SUCCESS           Detection completed successfully
  @retval EFI_INVALID_PARAMETER Invalid parameters
  @retval EFI_NOT_FOUND         No virtualization support found
**/
EFI_STATUS
EFIAPI
DetectVirtualizationSupport (
  OUT UINT32                        *SupportedTech,
  OUT VIRTUALIZATION_TECHNOLOGY     *PreferredTech
  );

/**
  Get virtualization interface for specific technology.
  
  @param[in]  VirtTech          Virtualization technology
  @param[out] Interface         Virtualization interface
  
  @retval EFI_SUCCESS           Interface retrieved successfully
  @retval EFI_INVALID_PARAMETER Invalid technology
  @retval EFI_UNSUPPORTED       Technology not supported
**/
EFI_STATUS
EFIAPI
GetVirtualizationInterface (
  IN  VIRTUALIZATION_TECHNOLOGY      VirtTech,
  OUT COMMON_VIRTUALIZATION_INTERFACE **Interface
  );

//
// Unified Error Handling
//

/**
  Handle common errors across all virtualization technologies.
  
  @param[in] VmContext          VM context
  @param[in] ErrorType          Type of error
  @param[in] ErrorCode          Specific error code
  @param[in] ErrorData          Additional error data
  
  @retval EFI_SUCCESS           Error handled successfully
  @retval EFI_INVALID_PARAMETER Invalid parameters
  @retval EFI_DEVICE_ERROR      Unrecoverable error
**/
EFI_STATUS
EFIAPI
HandleCommonError (
  IN COMMON_VM_CONTEXT  *VmContext,
  IN UINT32             ErrorType,
  IN EFI_STATUS         ErrorCode,
  IN VOID               *ErrorData
  );

//
// Performance Monitoring
//

/**
  Start performance monitoring for the VM context.
  
  @param[in] VmContext          VM context
  
  @retval EFI_SUCCESS           Monitoring started successfully
  @retval EFI_INVALID_PARAMETER Invalid context
**/
EFI_STATUS
EFIAPI
StartPerformanceMonitoring (
  IN COMMON_VM_CONTEXT  *VmContext
  );

/**
  Stop performance monitoring and get results.
  
  @param[in]  VmContext         VM context
  @param[out] Metrics           Performance metrics
  
  @retval EFI_SUCCESS           Monitoring stopped successfully
  @retval EFI_INVALID_PARAMETER Invalid parameters
**/
EFI_STATUS
EFIAPI
StopPerformanceMonitoring (
  IN  COMMON_VM_CONTEXT     *VmContext,
  OUT PERFORMANCE_METRICS   *Metrics
  );

//
// Common Utility Macros
//

/**
  Initialize all framework components.
**/
#define INIT_ALL_FRAMEWORKS(Context, SecurityLevel, StealthLevel) \
  do { \
    InitializeSecurityFramework(&(Context)->SecurityContext, (SecurityLevel)); \
    InitializeAntiDetection(&(Context)->StealthContext, (StealthLevel)); \
    InitializeConcurrencyFramework(); \
    InitializeMemorySafety(MemSafetyLevelStandard); \
    InitializeReliabilityFramework(&(Context)->ReliabilityContext, NULL); \
    InitializePerformanceFramework(&(Context)->PerformanceContext, PerfLevelStandard); \
  } while (0)

/**
  Cleanup all framework components.
**/
#define CLEANUP_ALL_FRAMEWORKS(Context) \
  do { \
    if ((Context)->SecurityContext != NULL) { \
      DestroySecurityContext((Context)->SecurityContext); \
    } \
    if ((Context)->StealthContext != NULL) { \
      DestroyStealthContext((Context)->StealthContext); \
    } \
    if ((Context)->ReliabilityContext != NULL) { \
      DestroyReliabilityContext((Context)->ReliabilityContext); \
    } \
    if ((Context)->PerformanceContext != NULL) { \
      DestroyPerformanceContext((Context)->PerformanceContext); \
    } \
  } while (0)

/**
  Validate all critical pointers.
**/
#define VALIDATE_VM_CONTEXT(Context) \
  do { \
    VALIDATE_POINTER(Context); \
    if ((Context)->Signature != COMMON_FRAMEWORK_SIGNATURE) { \
      return EFI_INVALID_PARAMETER; \
    } \
    if (EFI_ERROR(ValidateVmContextIntegrity(Context))) { \
      return EFI_CRC_ERROR; \
    } \
  } while (0)

//
// Unified Security Macros and Error Handling
//
#define VALIDATE_POINTER(ptr) \
  do { \
    if ((ptr) == NULL) { \
      return EFI_INVALID_PARAMETER; \
    } \
  } while (0)

#define VALIDATE_SIZE(size) \
  do { \
    if ((size) == 0 || (size) > MAX_SAFE_BUFFER_SIZE) { \
      return EFI_INVALID_PARAMETER; \
    } \
  } while (0)

#define SAFE_ARRAY_ACCESS(array, index, max_size) \
  (((index) < (max_size)) ? &(array)[(index)] : NULL)

#define SAFE_MEMORY_ACCESS(ptr, offset, size, total_size) \
  (((offset) + (size) <= (total_size)) ? ((UINT8*)(ptr) + (offset)) : NULL)

//
// Safe Buffer Management
//
typedef struct {
  VOID *Buffer;
  UINTN Size;
  BOOLEAN Allocated;
  CHAR16 *Description;
} SAFE_BUFFER;

#define INIT_SAFE_BUFFER(safe_buf, desc) \
  do { \
    (safe_buf)->Buffer = NULL; \
    (safe_buf)->Size = 0; \
    (safe_buf)->Allocated = FALSE; \
    (safe_buf)->Description = (desc); \
  } while (0)

//
// Error Code Mapping
//
EFI_STATUS MapErrorCode(EFI_STATUS OriginalStatus);

//
// Safe Memory Allocation Functions
//
EFI_STATUS SafeAllocatePool(
  IN UINTN Size,
  OUT VOID **Buffer,
  IN CHAR16 *Description
);

EFI_STATUS SafeAllocatePages(
  IN EFI_ALLOCATE_TYPE Type,
  IN EFI_MEMORY_TYPE MemoryType,
  IN UINTN Pages,
  OUT EFI_PHYSICAL_ADDRESS *Memory,
  IN CHAR16 *Description
);

VOID SafeBufferCleanup(SAFE_BUFFER *SafeBuf);

//
// Performance and Security Optimizations
//
typedef struct {
  UINT64 Key;
  UINT64 Value;
  UINT64 Timestamp;
  BOOLEAN Valid;
} SAFE_CACHE_ENTRY;

BOOLEAN SafeCacheLookup(
  IN UINT64 Key,
  OUT UINT64 *Value,
  IN UINT64 CurrentTime,
  IN UINT64 Timeout
);

VOID SafeCacheInsert(
  IN UINT64 Key,
  IN UINT64 Value,
  IN UINT64 CurrentTime
);

//
// CPU Vendor IDs
//
#define CPU_VENDOR_INTEL      0x756E6547  // "Genu"
#define CPU_VENDOR_AMD        0x68747541  // "Auth"
#define CPU_VENDOR_VIA        0x746E6543  // "Cent"

//
// Virtualization Feature Flags
//
#define VIRT_FEATURE_VMX      BIT0
#define VIRT_FEATURE_SVM      BIT1
#define VIRT_FEATURE_EPT      BIT2
#define VIRT_FEATURE_NPT      BIT3
#define VIRT_FEATURE_VPID     BIT4
#define VIRT_FEATURE_ASID     BIT5

//
// Authorization Levels
//
#define AUTH_LEVEL_BASIC      1
#define AUTH_LEVEL_STANDARD   2
#define AUTH_LEVEL_PREMIUM    3
#define AUTH_LEVEL_ENTERPRISE 4

//
// Authorization Flags
//
#define AUTH_FLAG_VALID       BIT0
#define AUTH_FLAG_PERMANENT   BIT1
#define AUTH_FLAG_TRANSFERABLE BIT2
#define AUTH_FLAG_ENTERPRISE  BIT3
#define AUTH_FLAG_DEBUG       BIT4

#endif // __MINI_VISOR_COMMON_H__
