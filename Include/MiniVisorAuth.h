/** @file
  MiniVisor Universal Authorization System
  
  This file contains the next-generation unified authorization system for both
  Intel VT-d and AMD SVM drivers, featuring advanced compatibility matrix,
  quantum-resistant cryptography, and cloud-based management.
  
  Copyright (c) 2024, MiniVisor Project. All rights reserved.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef __MINI_VISOR_AUTH_H__
#define __MINI_VISOR_AUTH_H__

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

//
// MiniVisor Authorization System Version
//
#define MINI_VISOR_AUTH_MAJOR_VERSION    2
#define MINI_VISOR_AUTH_MINOR_VERSION    0
#define MINI_VISOR_AUTH_BUILD_VERSION    0
#define MINI_VISOR_AUTH_REVISION         1

//
// Universal Authorization Signatures
//
#define MINI_VISOR_AUTH_SIGNATURE        0x4D564155  // 'MVAU' - MiniVisor Authorization Universal
#define MINI_VISOR_AUTH_MAGIC            0x4175744D  // 'AutM' - Authorization Magic
#define MINI_VISOR_HARDWARE_SIG          0x48574647  // 'HWFG' - Hardware Fingerprint

//
// Cryptographic Constants (Quantum-Resistant)
//
#define KYBER_PUBLIC_KEY_SIZE           1568    // Kyber-1024 public key
#define KYBER_PRIVATE_KEY_SIZE          3168    // Kyber-1024 private key  
#define KYBER_CIPHERTEXT_SIZE           1568    // Kyber-1024 ciphertext
#define DILITHIUM_PUBLIC_KEY_SIZE       1952    // Dilithium-5 public key
#define DILITHIUM_SIGNATURE_SIZE        4595    // Dilithium-5 signature
#define AES_256_KEY_SIZE                32      // AES-256 key
#define AES_256_IV_SIZE                 16      // AES-256 IV
#define SHA3_512_HASH_SIZE              64      // SHA3-512 hash
#define BLAKE3_HASH_SIZE                32      // BLAKE3 hash

//
// Hardware Compatibility Scoring Constants
//
#define MAX_COMPATIBILITY_SCORE         1000    // Perfect compatibility
#define MIN_AUTHORIZATION_THRESHOLD     600     // Minimum for authorization
#define RECOMMENDED_THRESHOLD           750     // Recommended threshold
#define STRICT_THRESHOLD                900     // Strict enterprise threshold

//
// Authorization Types and Tiers
//
typedef enum {
  MiniVisorAuthTypeUnknown = 0,
  MiniVisorAuthTypePersonal = 1,        // Personal/developer use
  MiniVisorAuthTypeProfessional = 2,    // Professional workstations
  MiniVisorAuthTypeEnterprise = 3,      // Enterprise deployment
  MiniVisorAuthTypeDatacenter = 4,      // Datacenter/cloud deployment
  MiniVisorAuthTypeOEM = 5,             // OEM/system integrator
  MiniVisorAuthTypeResearch = 6,        // Academic/research use
  MiniVisorAuthTypeEvaluation = 7       // Evaluation/trial use
} MINI_VISOR_AUTH_TYPE;

typedef enum {
  MiniVisorPlatformUnknown = 0,
  MiniVisorPlatformIntel = 1,           // Intel VT-x/VT-d platform
  MiniVisorPlatformAMD = 2,             // AMD SVM/IOMMU platform
  MiniVisorPlatformUniversal = 3        // Universal (works on both)
} MINI_VISOR_PLATFORM_TYPE;

typedef enum {
  MiniVisorAuthStatusUnauthorized = 0,
  MiniVisorAuthStatusAuthorized = 1,
  MiniVisorAuthStatusExpired = 2,
  MiniVisorAuthStatusInvalid = 3,
  MiniVisorAuthStatusOverLimit = 4,
  MiniVisorAuthStatusBlacklisted = 5,
  MiniVisorAuthStatusPending = 6,
  MiniVisorAuthStatusSuspended = 7,
  MiniVisorAuthStatusRevoked = 8
} MINI_VISOR_AUTH_STATUS;

//
// Advanced Hardware Fingerprint (Universal for Intel/AMD)
//
#pragma pack(1)
typedef struct {
  // CPU Information
  UINT32  CpuVendorId;                  // CPU vendor ID
  UINT32  CpuModelId;                   // CPU model ID
  UINT32  CpuSteppingId;                // CPU stepping ID
  UINT64  CpuFeatures;                  // CPU feature flags
  UINT32  CpuCoreCount;                 // Number of CPU cores
  UINT32  CpuThreadCount;               // Number of CPU threads
  UINT32  CpuCacheL1Size;               // L1 cache size in KB
  UINT32  CpuCacheL2Size;               // L2 cache size in KB
  UINT32  CpuCacheL3Size;               // L3 cache size in KB
  UINT64  CpuMaxFreq;                   // Maximum CPU frequency in MHz
  UINT8   CpuBrandString[48];           // CPU brand string
  
  // Memory Information
  UINT64  TotalMemorySize;              // Total physical memory in bytes
  UINT32  MemoryChannelCount;           // Number of memory channels
  UINT32  MemorySpeed;                  // Memory speed in MHz
  UINT32  MemoryType;                   // Memory type (DDR3/DDR4/DDR5)
  
  // Platform Information
  UINT32  ChipsetVendorId;              // Chipset vendor ID
  UINT32  ChipsetDeviceId;              // Chipset device ID
  UINT32  BiosVendorId;                 // BIOS vendor ID
  UINT32  BiosVersion;                  // BIOS version
  UINT64  BiosDate;                     // BIOS date
  
  // Storage Information
  UINT32  StorageControllerCount;       // Number of storage controllers
  UINT64  TotalStorageSize;             // Total storage size in bytes
  UINT32  StorageType;                  // Storage type (SSD/HDD/NVMe)
  
  // Network Information
  UINT32  NetworkAdapterCount;          // Number of network adapters
  UINT64  NetworkAdapterIds[4];         // Network adapter IDs
  
  // Security Features
  UINT64  SecurityFeatures;             // Security feature flags
  UINT32  TpmVersion;                   // TPM version
  UINT32  SecureBootEnabled;            // Secure Boot status
  
  // Virtualization Features
  UINT64  VirtualizationFeatures;       // Virtualization feature flags
  UINT32  VtXEnabled;                   // Intel VT-x status
  UINT32  VtDEnabled;                   // Intel VT-d status
  UINT32  AmdVEnabled;                  // AMD-V status
  UINT32  AmdIommuEnabled;              // AMD IOMMU status
  
  // Performance Metrics
  UINT64  BenchmarkScore;               // Performance benchmark score
  UINT32  PowerEfficiency;              // Power efficiency rating
  UINT32  ThermalRating;                // Thermal performance rating
  
  // Unique Identifiers
  UINT64  SystemSerialNumber;           // System serial number
  UINT64  MotherboardId;                // Motherboard ID
  UINT64  ProcessorId;                  // Processor unique ID
  
  // Legacy compatibility members (for backward compatibility)
  UINT32  CpuSignature;                 // Legacy CPU signature
  UINT32  CpuSerialNumber;              // Legacy CPU serial number
  UINT32  MainboardSerialHash;          // Legacy mainboard serial hash
  UINT32  MemorySize;                   // Legacy memory size
  
  // Code-compatible members (matching the implementation)
  UINT32  CpuFamily;                    // CPU family
  UINT32  CpuModel;                     // CPU model
  UINT64  CpuFeatureFlags;              // CPU feature flags
  UINT32  CpuBrandHash;                 // CPU brand hash
  UINT32  ChipsetModelHash;             // Chipset model hash
  UINT32  BiosVersionHash;              // BIOS version hash
  UINT16  PciDeviceCount;               // PCI device count
  UINT16  UsbDeviceCount;               // USB device count
  UINT32  MemoryConfigHash;             // Memory configuration hash
  UINT32  StorageConfigHash;            // Storage configuration hash
  UINT32  NetworkConfigHash;            // Network configuration hash
  UINT64  IommuFeatures;                // IOMMU features
  UINT64  SystemTime;                   // System time
  UINT32  FingerprintCrc32;             // Fingerprint CRC32
  
  // Cryptographic Hash
  UINT8   FingerprintHash[64];          // SHA-512 hash of all fingerprint data
  
  // Reserved for future expansion
  UINT8   Reserved[64];                 // Reserved space
} MINI_VISOR_HARDWARE_FINGERPRINT;
#pragma pack()

//
// Compatibility Matrix Structure
//
#pragma pack(1)
typedef struct {
  UINT32  MatrixVersion;                // Matrix version number
  UINT32  MatrixSize;                   // Size of compatibility matrix
  UINT32  CpuCompatibilityScore;        // CPU compatibility score (0-1000)
  UINT32  MemoryCompatibilityScore;     // Memory compatibility score (0-1000)
  UINT32  PlatformCompatibilityScore;   // Platform compatibility score (0-1000)
  UINT32  SecurityCompatibilityScore;   // Security compatibility score (0-1000)
  UINT32  PerformanceCompatibilityScore; // Performance compatibility score (0-1000)
  UINT32  OverallCompatibilityScore;    // Overall compatibility score (0-1000)
  
  // Detailed compatibility flags
  UINT64  CpuCompatibilityFlags;        // CPU-specific compatibility flags
  UINT64  MemoryCompatibilityFlags;     // Memory-specific compatibility flags
  UINT64  PlatformCompatibilityFlags;   // Platform-specific compatibility flags
  UINT64  SecurityCompatibilityFlags;   // Security-specific compatibility flags
  UINT64  PerformanceCompatibilityFlags; // Performance-specific compatibility flags
  
  // Code-compatible members (matching the implementation)
  UINT32  Signature;                    // Matrix signature
  UINT32  Version;                      // Matrix version
  UINT32  CpuFamilyWeight;              // CPU family weight
  UINT32  CpuModelWeight;               // CPU model weight
  UINT32  CpuFeatureWeight;             // CPU feature weight
  UINT32  ChipsetWeight;                // Chipset weight
  UINT32  BiosWeight;                   // BIOS weight
  UINT32  MainboardWeight;              // Mainboard weight
  UINT32  VmxSvmWeight;                 // VMX/SVM weight
  UINT32  IommuWeight;                  // IOMMU weight
  UINT32  SecurityWeight;               // Security weight
  UINT32  CpuTolerance;                 // CPU tolerance
  UINT32  PlatformTolerance;            // Platform tolerance
  UINT32  ConfigTolerance;              // Configuration tolerance
  UINT32  MlWeights[8];                 // Machine learning weights
  UINT32  MlBiases[8];                  // Machine learning biases
  
  // Compatibility notes and recommendations
  CHAR8   CompatibilityNotes[512];      // Human-readable compatibility notes
  CHAR8   Recommendations[512];         // Recommendations for improvement
  
  // Reserved for future expansion
  UINT8   Reserved[128];                // Reserved space
} MINI_VISOR_COMPATIBILITY_MATRIX;
#pragma pack()

//
// Usage Analytics Structure
//
#pragma pack(1)
typedef struct {
  UINT64  TotalUsageTime;               // Total usage time in seconds
  UINT32  SessionCount;                 // Number of sessions
  UINT32  AverageSessionLength;         // Average session length in seconds
  UINT32  PeakConcurrentUsers;          // Peak concurrent users
  UINT32  FeatureUsageBitmap;           // Which features are used
  UINT8   Reserved[32];                 // Reserved for analytics expansion
} MINI_VISOR_USAGE_ANALYTICS;
#pragma pack()

//
// Universal Authorization Structure (Compatible with both Intel VT-d and AMD SVM)
//
#pragma pack(1)
typedef struct {
  UINT32  Signature;                    // MINI_VISOR_AUTH_SIGNATURE
  UINT32  Version;                      // Version number
  UINT32  Magic;                        // MINI_VISOR_AUTH_MAGIC
  UINT32  TotalSize;                    // Total structure size
  UINT32  AuthType;                     // Authorization type
  UINT32  Platform;                     // Target platform
  UINT64  IssuedTime;                   // Issuance timestamp
  UINT64  ExpiryTime;                   // Expiration timestamp
  UINT32  ActivationLimit;              // Maximum activations
  UINT32  CurrentActivations;           // Current activation count
  UINT32  AuthorizationPeriodDays;      // Authorization period in days
  UINT32  Reserved1;                    // Reserved for future use
  
  // Hardware fingerprint (universal format)
  MINI_VISOR_HARDWARE_FINGERPRINT HardwareFingerprint;
  
  // Compatibility matrix (universal format)
  MINI_VISOR_COMPATIBILITY_MATRIX CompatibilityMatrix;
  
  // Cryptographic data
  UINT8   AuthorizationPayload[512];    // Encrypted authorization data
  UINT8   DigitalSignature[256];        // RSA-2048 signature
  UINT8   IntegrityHash[64];            // SHA-512 integrity hash
  UINT8   AntiTamperSeal[32];           // HMAC anti-tamper seal
  
  // Extended data
  UINT8   CustomData[1024];             // Custom data field
  UINT8   Reserved2[256];               // Reserved for future use
  
  // Usage analytics
  UINT64  FirstActivation;              // First activation timestamp
  UINT64  LastUsage;                    // Last usage timestamp
  UINT32  ActivationCount;              // Total activation count
  UINT32  UsagePattern;                 // Usage pattern hash
  
  // Security metadata
  UINT32  SecurityLevel;                // Security level
  UINT32  CryptoVersion;                // Cryptographic algorithm version
  UINT64  SecurityFlags;                // Security feature flags
  
  // Checksum for integrity verification
  UINT32  Checksum;                     // CRC32 checksum
  
  // Legacy compatibility members (for backward compatibility with existing drivers)
  UINT64  AuthorizedTime;               // Legacy authorized time
  UINT32  MaxUsageCount;                // Legacy max usage count
  UINT32  CurrentUsageCount;            // Legacy current usage count
  UINT8   EncryptedPayload[64];         // Legacy encrypted payload
  UINT8   RsaSignature[256];            // Legacy RSA signature
  UINT8   SecurityHash[32];             // Legacy security hash
  MINI_VISOR_HARDWARE_FINGERPRINT HwFingerprint; // Legacy hardware fingerprint
} MINI_VISOR_UNIVERSAL_AUTHORIZATION;
#pragma pack()

// Legacy compatibility structures (for backward compatibility)
typedef MINI_VISOR_UNIVERSAL_AUTHORIZATION VTD_AUTHORIZATION_INFO;
typedef MINI_VISOR_UNIVERSAL_AUTHORIZATION SVM_AUTHORIZATION_INFO;
typedef MINI_VISOR_UNIVERSAL_AUTHORIZATION MINI_VISOR_AUTHORIZATION;

//
// Authorization Engine Context
//
typedef struct {
  BOOLEAN                         Initialized;
  MINI_VISOR_AUTH_STATUS          CurrentStatus;
  MINI_VISOR_AUTHORIZATION        *CurrentAuth;
  MINI_VISOR_HARDWARE_FINGERPRINT CurrentHardware;
  UINT32                          CompatibilityScore;
  UINT32                          AuthorizationThreshold;
  BOOLEAN                         CloudConnected;
  UINT64                          LastVerification;
  EFI_EVENT                       PeriodicCheckEvent;
  
  // Feature flags
  BOOLEAN                         QuantumCryptoEnabled;
  BOOLEAN                         CloudSyncEnabled;
  BOOLEAN                         TelemetryEnabled;
  BOOLEAN                         AutoUpdateEnabled;
  
  // Counters  
  UINT32                          VerificationCount;
  UINT32                          FailureCount;
  UINT32                          CloudSyncCount;
  
  // Callbacks
  EFI_STATUS (*OnAuthorizationSuccess)(VOID);
  EFI_STATUS (*OnAuthorizationFailure)(MINI_VISOR_AUTH_STATUS Status);
  EFI_STATUS (*OnHardwareChange)(MINI_VISOR_HARDWARE_FINGERPRINT *OldHw, 
                                 MINI_VISOR_HARDWARE_FINGERPRINT *NewHw);
} MINI_VISOR_AUTH_CONTEXT;

//
// Function Prototypes - Core Authorization Engine
//

/**
  Initialize the universal MiniVisor authorization system.
  
  @param[in] Context            Pointer to authorization context.
  @param[in] Platform          Target platform (Intel/AMD/Universal).
  @param[in] Threshold         Compatibility threshold for authorization.
  
  @retval EFI_SUCCESS          Authorization system initialized successfully.
  @retval Others               Initialization failed.
**/
EFI_STATUS
EFIAPI
MiniVisorAuthInitialize (
  IN OUT MINI_VISOR_AUTH_CONTEXT    *Context,
  IN MINI_VISOR_PLATFORM_TYPE       Platform,
  IN UINT32                         Threshold
  );

/**
  Perform comprehensive hardware fingerprinting.
  
  @param[out] Fingerprint      Pointer to receive hardware fingerprint.
  
  @retval EFI_SUCCESS          Fingerprint generated successfully.
  @retval Others               Failed to generate fingerprint.
**/
EFI_STATUS
EFIAPI
MiniVisorAuthGenerateFingerprint (
  OUT MINI_VISOR_HARDWARE_FINGERPRINT *Fingerprint
  );

/**
  Calculate intelligent hardware compatibility score.
  
  @param[in] AuthFingerprint   Authorized hardware fingerprint.
  @param[in] CurrentFingerprint Current hardware fingerprint.
  @param[in] Matrix            Compatibility matrix.
  
  @return                      Compatibility score (0-1000).
**/
UINT32
EFIAPI
MiniVisorAuthCalculateCompatibility (
  IN MINI_VISOR_HARDWARE_FINGERPRINT *AuthFingerprint,
  IN MINI_VISOR_HARDWARE_FINGERPRINT *CurrentFingerprint,
  IN MINI_VISOR_COMPATIBILITY_MATRIX  *Matrix
  );

/**
  Verify authorization with advanced security checks.
  
  @param[in] Context           Authorization context.
  @param[in] Authorization     Authorization structure to verify.
  
  @retval MINI_VISOR_AUTH_STATUS Authorization status.
**/
MINI_VISOR_AUTH_STATUS
EFIAPI
MiniVisorAuthVerify (
  IN MINI_VISOR_AUTH_CONTEXT   *Context,
  IN MINI_VISOR_AUTHORIZATION  *Authorization
  );

/**
  Load authorization from file system with auto-discovery.
  
  @param[in] Context           Authorization context.
  @param[in] FileName          Authorization file name (optional).
  
  @retval EFI_SUCCESS          Authorization loaded successfully.
  @retval Others               Failed to load authorization.
**/
EFI_STATUS
EFIAPI
MiniVisorAuthLoad (
  IN MINI_VISOR_AUTH_CONTEXT *Context,
  IN CHAR16                  *FileName OPTIONAL
  );

/**
  Save authorization to file system.
  
  @param[in] Context           Authorization context.
  @param[in] FileName          Authorization file name.
  
  @retval EFI_SUCCESS          Authorization saved successfully.
  @retval Others               Failed to save authorization.
**/
EFI_STATUS
EFIAPI
MiniVisorAuthSave (
  IN MINI_VISOR_AUTH_CONTEXT *Context,
  IN CHAR16                  *FileName
  );

/**
  Predict compatibility for hardware changes.
  
  @param[in] CurrentHw         Current hardware fingerprint.
  @param[in] ProposedHw        Proposed hardware changes.
  @param[in] Matrix            Compatibility matrix.
  
  @return                      Predicted compatibility score.
**/
UINT32
EFIAPI
MiniVisorAuthPredictCompatibility (
  IN MINI_VISOR_HARDWARE_FINGERPRINT *CurrentHw,
  IN MINI_VISOR_HARDWARE_FINGERPRINT *ProposedHw,
  IN MINI_VISOR_COMPATIBILITY_MATRIX  *Matrix
  );

//
// Function Prototypes - Diagnostics and Reporting
//

/**
  Generate detailed authorization diagnostics.
  
  @param[in] Context           Authorization context.
  @param[out] Report           Buffer for diagnostics report.
  @param[in,out] ReportSize    Size of report buffer.
  
  @retval EFI_SUCCESS          Diagnostics generated successfully.
**/
EFI_STATUS
EFIAPI
MiniVisorAuthGenerateDiagnostics (
  IN MINI_VISOR_AUTH_CONTEXT *Context,
  OUT CHAR8                  *Report,
  IN OUT UINTN               *ReportSize
  );

/**
  Display user-friendly authorization status.
  
  @param[in] Context           Authorization context.
  @param[in] Verbose           TRUE for detailed output.
  
  @retval EFI_SUCCESS          Status displayed successfully.
**/
EFI_STATUS
EFIAPI
MiniVisorAuthDisplayStatus (
  IN MINI_VISOR_AUTH_CONTEXT *Context,
  IN BOOLEAN                 Verbose
  );

/**
  Suggest solutions for authorization problems.
  
  @param[in] Context           Authorization context.
  @param[in] Status            Current authorization status.
  
  @retval EFI_SUCCESS          Suggestions provided successfully.
**/
EFI_STATUS
EFIAPI
MiniVisorAuthSuggestSolutions (
  IN MINI_VISOR_AUTH_CONTEXT *Context,
  IN MINI_VISOR_AUTH_STATUS  Status
  );

//
// Utility Functions
//

/**
  Calculate feature similarity between two feature sets.
  
  @param[in] AuthFeatures      First feature set.
  @param[in] CurrentFeatures   Second feature set.
  
  @retval UINT32               Similarity score (0-100).
**/
UINT32
EFIAPI
CalculateFeatureSimilarity (
  IN UINT64 AuthFeatures,
  IN UINT64 CurrentFeatures
  );

/**
  Calculate CRC32 checksum.
  
  @param[in] Data              Data to calculate CRC32 for.
  @param[in] Length            Length of data.
  
  @retval UINT32               CRC32 checksum.
**/
UINT32
EFIAPI
CalculateCrc32 (
  IN UINT8 *Data,
  IN UINTN Length
  );

/**
  Initialize compatibility matrix.
  
  @param[out] Matrix           Compatibility matrix to initialize.
  @param[in] Platform          Target platform type.
  
  @retval EFI_SUCCESS          Matrix initialized.
  @retval Others               Failed to initialize matrix.
**/
EFI_STATUS
EFIAPI
MiniVisorAuthInitializeMatrix (
  OUT MINI_VISOR_COMPATIBILITY_MATRIX *Matrix,
  IN MINI_VISOR_PLATFORM_TYPE         Platform
  );

//
// Global Variables
//
extern MINI_VISOR_AUTH_CONTEXT  gMiniVisorAuthContext;
extern BOOLEAN                  gMiniVisorAuthDebugMode;

//
// Utility Macros
//
#define MINI_VISOR_AUTH_DEBUG(Expression) \
  do { \
    if (gMiniVisorAuthDebugMode) { \
      DEBUG(Expression); \
    } \
  } while (FALSE)

#define IS_AUTH_INITIALIZED() \
  (gMiniVisorAuthContext.Initialized)

#define IS_AUTH_AUTHORIZED() \
  (gMiniVisorAuthContext.CurrentStatus == MiniVisorAuthStatusAuthorized)

#define GET_COMPATIBILITY_SCORE() \
  (gMiniVisorAuthContext.CompatibilityScore)

//
// Compatibility Score Evaluation Macros
//
#define IS_EXCELLENT_COMPATIBILITY(Score) ((Score) >= 900)
#define IS_GOOD_COMPATIBILITY(Score)      ((Score) >= 750)
#define IS_ACCEPTABLE_COMPATIBILITY(Score) ((Score) >= 600)
#define IS_POOR_COMPATIBILITY(Score)      ((Score) < 600)

#endif // __MINI_VISOR_AUTH_H__
