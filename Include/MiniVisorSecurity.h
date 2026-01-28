/** @file
  MiniVisor Enterprise Security Library Header
  
  This file defines the enterprise-grade security capabilities including
  advanced authorization verification, cryptographic functions, and
  secure memory management.
  
  Copyright (c) 2024, MiniVisor Project. All rights reserved.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef __MINI_VISOR_SECURITY_H__
#define __MINI_VISOR_SECURITY_H__

#include <Uefi.h>

// Missing type definitions for backward compatibility
typedef struct {
  UINT32  CpuSignature;
  UINT32  CpuSerialNumber;
  UINT32  MainboardSerialHash;
  UINT32  Reserved;
  UINT32  CpuBrandHash;
  UINT64  SystemTime;
  UINT64  MemorySize;
  UINT32  PciDeviceCount;
} VTD_HARDWARE_FINGERPRINT;

//
// Security Levels
//
#define SECURITY_LEVEL_BASIC      1
#define SECURITY_LEVEL_ADVANCED   2
#define SECURITY_LEVEL_ENTERPRISE 3
#define SECURITY_LEVEL_HIGH       4
#define SecurityLevelHigh         4  // Alias for compatibility

//
// Stealth Levels
//
#define STEALTH_LEVEL_BASIC       1
#define STEALTH_LEVEL_ADVANCED    2
#define STEALTH_LEVEL_ENTERPRISE  3

//
// Key Purpose Definitions
//
#define KEY_PURPOSE_AUTHENTICATION 1
#define KEY_PURPOSE_ENCRYPTION     2
#define KEY_PURPOSE_SIGNING        3

//
// Dynamic Key Context
//
typedef struct {
  UINT32  Signature;
  UINT32  Version;
  UINTN   KeySize;
  UINT8   *KeyData;
  UINT64  ExpiryTime;
} DYNAMIC_KEY_CONTEXT;

//
// Security State Context
//
typedef struct {
  UINT32  Signature;
  UINT32  Version;
  UINTN   Level;
  BOOLEAN Initialized;
  UINT64  LastUpdate;
} SECURITY_STATE_CONTEXT;

//
// Security Context Structure
//
typedef struct {
  UINT32  Signature;
  UINT32  Version;
  UINTN   Level;
  BOOLEAN Initialized;
  
  // Cryptographic components
  BOOLEAN CryptoEnabled;
  BOOLEAN HashEnabled;
  BOOLEAN SignatureEnabled;
  
  // Security counters
  UINT32  VerificationCount;
  UINT32  FailureCount;
  UINT64  LastVerification;
  
  // Entropy source
  UINT64  EntropySeed;
} SECURITY_CONTEXT;

//
// Security Statistics Structure
//
typedef struct {
  UINT32  VerificationCount;
  UINT32  FailureCount;
  UINT64  LastVerification;
  BOOLEAN CryptoEnabled;
  BOOLEAN HashEnabled;
  BOOLEAN SignatureEnabled;
} SECURITY_STATS;

//
// Function Prototypes
//

/**
  Initialize enterprise security system.
  
  @param[in] Level         Security level.
  
  @retval EFI_SUCCESS      Initialization successful.
  @retval Others           Initialization failed.
**/
EFI_STATUS
EFIAPI
InitializeSecuritySystem (
  IN UINTN Level
  );

/**
  Generate hardware-based entropy.
  
  @param[out] Entropy      Buffer for entropy data.
  @param[in] EntropySize   Size of entropy buffer.
  
  @retval EFI_SUCCESS      Entropy generated successfully.
  @retval Others           Failed to generate entropy.
**/
EFI_STATUS
EFIAPI
GenerateHardwareEntropy (
  OUT UINT8 *Entropy,
  IN UINTN EntropySize
  );

/**
  Generate hardware fingerprint for VT-d.
  
  @param[out] Fingerprint  Hardware fingerprint structure.
  
  @retval EFI_SUCCESS      Fingerprint generated successfully.
  @retval Others           Failed to generate fingerprint.
**/
EFI_STATUS
EFIAPI
VtdGenerateHardwareFingerprint (
  OUT VTD_HARDWARE_FINGERPRINT *Fingerprint
  );

/**
  Simple hash function for SVM.
  
  @param[in] Data          Data to hash.
  @param[in] DataSize      Size of data.
  
  @retval UINT32           Hash value.
**/
UINT32
EFIAPI
SvmSimpleHash (
  IN UINT8 *Data,
  IN UINTN DataSize
  );

/**
  RSA signature verification for SVM.
  
  @param[in] Data          Data to verify.
  @param[in] DataSize      Size of data.
  @param[in] Signature     Signature to verify.
  @param[in] SignatureSize Size of signature.
  
  @retval EFI_SUCCESS      Signature verified successfully.
  @retval Others           Signature verification failed.
**/
EFI_STATUS
EFIAPI
SvmRsaVerifySignature (
  IN UINT8 *Data,
  IN UINTN DataSize,
  IN UINT8 *Signature,
  IN UINTN SignatureSize
  );

/**
  Verify license for SVM.
  
  @param[in] LicenseData   License data.
  @param[in] LicenseSize   Size of license data.
  
  @retval EFI_SUCCESS      License verified successfully.
  @retval Others           License verification failed.
**/
EFI_STATUS
EFIAPI
SvmAuthVerifyLicense (
  IN UINT8 *LicenseData,
  IN UINTN LicenseSize
  );

/**
  Compute SHA-256 hash.
  
  @param[in] Data          Input data.
  @param[in] DataSize      Size of input data.
  @param[out] Hash         Output hash buffer.
  
  @retval EFI_SUCCESS      Hash computed successfully.
**/

/**
  Generate Intel VT-d hardware fingerprint.
  
  @param[out] Fingerprint  Hardware fingerprint.
  
  @retval EFI_SUCCESS      Fingerprint generated successfully.
**/
EFI_STATUS
EFIAPI
VtdGenerateHardwareFingerprint (
  OUT VTD_HARDWARE_FINGERPRINT *Fingerprint
  );

/**
  Compute simple hash for VT-d.
  
  @param[in] Data          Input data.
  @param[in] DataSize      Size of input data.
  
  @retval UINT32           Computed hash value.
**/
UINT32
EFIAPI
VtdSimpleHash (
  IN UINT8 *Data,
  IN UINTN DataSize
  );

/**
  Compute simple hash for SVM.
  
  @param[in] Data          Input data.
  @param[in] DataSize      Size of input data.
  
  @retval UINT32           Computed hash value.
**/
UINT32
EFIAPI
SvmSimpleHash (
  IN UINT8 *Data,
  IN UINTN DataSize
  );

/**
  Verify RSA signature for SVM.
  
  @param[in] Data          Data to verify.
  @param[in] DataSize      Size of data.
  @param[in] Signature     RSA signature.
  @param[in] SignatureSize Size of signature.
  
  @retval EFI_SUCCESS      Signature verified successfully.
**/
EFI_STATUS
EFIAPI
SvmRsaVerifySignature (
  IN UINT8 *Data,
  IN UINTN DataSize,
  IN UINT8 *Signature,
  IN UINTN SignatureSize
  );

/**
  Compute SHA-256 hash for SVM.
  
  @param[in] Data          Input data.
  @param[in] DataSize      Size of input data.
  @param[out] Hash         Output hash buffer.
  
  @retval EFI_SUCCESS      Hash computed successfully.
**/
EFI_STATUS
EFIAPI
SvmSha256Hash (
  IN UINT8 *Data,
  IN UINTN DataSize,
  OUT UINT8 *Hash
  );

/**
  Initialize security framework.
  
  @param[in] Level         Security level.
  @param[out] Context      Security context.
  
  @retval EFI_SUCCESS      Framework initialized successfully.
**/
EFI_STATUS
EFIAPI
InitializeSecurityFramework (
  IN UINT32 Level,
  OUT VOID **Context
  );

/**
  Generate dynamic key.
  
  @param[in] Context       Security context.
  @param[in] Purpose       Key purpose.
  @param[out] Key          Generated key.
  
  @retval EFI_SUCCESS      Key generated successfully.
**/
EFI_STATUS
EFIAPI
GenerateDynamicKey (
  IN VOID *Context,
  IN UINT32 Purpose,
  OUT UINT8 *Key
  );

/**
  Retrieve secure credential.
  
  @param[in] Context       Security context.
  @param[out] Credential   Retrieved credential.
  
  @retval EFI_SUCCESS      Credential retrieved successfully.
**/
EFI_STATUS
EFIAPI
RetrieveSecureCredential (
  IN VOID *Context,
  OUT UINT8 *Credential
  );

/**
  Destroy security context.
  
  @param[in] Context       Security context to destroy.
  
  @retval EFI_SUCCESS      Context destroyed successfully.
**/
EFI_STATUS
EFIAPI
DestroySecurityContext (
  IN VOID *Context
  );

/**
  Verify SVM authorization license.
  
  @param[in] AuthData      Authorization data.
  @param[in] AuthSize      Size of authorization data.
  
  @retval EFI_SUCCESS      License verified successfully.
**/
EFI_STATUS
EFIAPI
SvmAuthVerifyLicense (
  IN UINT8 *AuthData,
  IN UINTN AuthSize
  );

/**
  Compute SHA-256 hash.
  
  @param[in] Data          Data to hash.
  @param[in] DataSize      Size of data.
  @param[out] Hash         Output hash buffer.
  
  @retval EFI_SUCCESS      Hash computed successfully.
  @retval Others           Failed to compute hash.
**/
EFI_STATUS
EFIAPI
ComputeSha256Hash (
  IN UINT8 *Data,
  IN UINTN DataSize,
  OUT UINT8 *Hash
  );

/**
  Verify RSA-4096 signature.
  
  @param[in] Data          Data to verify.
  @param[in] DataSize      Size of data.
  @param[in] Signature     Digital signature.
  @param[in] PublicKey     RSA public key.
  
  @retval EFI_SUCCESS      Signature is valid.
  @retval Others           Signature verification failed.
**/
EFI_STATUS
EFIAPI
VerifyRsaSignature (
  IN UINT8 *Data,
  IN UINTN DataSize,
  IN UINT8 *Signature,
  IN UINT8 *PublicKey
  );

/**
  Compute HMAC-SHA256.
  
  @param[in] Data          Input data.
  @param[in] DataSize      Size of input data.
  @param[in] Key           HMAC key.
  @param[in] KeySize       Size of HMAC key.
  @param[out] Hmac         Output HMAC buffer.
  
  @retval EFI_SUCCESS      HMAC computed successfully.
  @retval Others           Failed to compute HMAC.
**/
EFI_STATUS
EFIAPI
ComputeHmacSha256 (
  IN UINT8 *Data,
  IN UINTN DataSize,
  IN UINT8 *Key,
  IN UINTN KeySize,
  OUT UINT8 *Hmac
  );

/**
  Verify authorization structure integrity.
  
  @param[in] AuthData      Authorization data.
  @param[in] AuthSize      Size of authorization data.
  
  @retval EFI_SUCCESS      Authorization is valid.
  @retval Others           Authorization verification failed.
**/
EFI_STATUS
EFIAPI
VerifyAuthorizationIntegrity (
  IN UINT8 *AuthData,
  IN UINTN AuthSize
  );

/**
  Perform comprehensive security verification.
  
  @param[in] AuthData      Authorization data.
  @param[in] AuthSize      Size of authorization data.
  @param[in] PublicKey     Public key for signature verification.
  
  @retval EFI_SUCCESS      Security verification passed.
  @retval Others           Security verification failed.
**/
EFI_STATUS
EFIAPI
PerformSecurityVerification (
  IN UINT8 *AuthData,
  IN UINTN AuthSize,
  IN UINT8 *PublicKey
  );

/**
  Get security statistics.
  
  @param[out] Stats        Security statistics.
  
  @retval EFI_SUCCESS      Statistics retrieved.
**/
EFI_STATUS
EFIAPI
GetSecurityStats (
  OUT SECURITY_STATS *Stats
  );

#endif // __MINI_VISOR_SECURITY_H__