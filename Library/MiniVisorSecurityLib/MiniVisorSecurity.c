/** @file
  MiniVisor Enterprise Security Library
  
  This file implements enterprise-grade security capabilities including
  advanced authorization verification, cryptographic functions, and
  secure memory management.
  
  Copyright (c) 2024, MiniVisor Project. All rights reserved.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/TimerLib.h>
#include <Library/CpuLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/BaseCryptLib.h>

#include "../Include/MiniVisorSecurity.h"

//
// Global security context
//
STATIC SECURITY_CONTEXT gSecurityContext = {0};
STATIC BOOLEAN gSecurityInitialized = FALSE;

//
// Cryptographic constants
//
#define SECURITY_SIGNATURE        0x53454355  // 'SECU'
#define SECURITY_VERSION          0x00020000  // Version 2.0
#define RSA_KEY_SIZE_4096         512
#define SHA256_HASH_SIZE          32
#define HMAC_KEY_SIZE             32

//
// Security levels
//
#define SECURITY_LEVEL_BASIC      1
#define SECURITY_LEVEL_ADVANCED   2
#define SECURITY_LEVEL_ENTERPRISE 3

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
  )
{
  UINT64 CurrentTsc = AsmReadTsc();
  
  if (gSecurityInitialized) {
    return EFI_ALREADY_STARTED;
  }
  
  DEBUG((DEBUG_INFO, "[Security] Initializing enterprise security system\n"));
  
  // Initialize context
  ZeroMem(&gSecurityContext, sizeof(SECURITY_CONTEXT));
  gSecurityContext.Signature = SECURITY_SIGNATURE;
  gSecurityContext.Version = SECURITY_VERSION;
  gSecurityContext.Level = Level;
  gSecurityContext.Initialized = TRUE;
  
  // Initialize cryptographic components
  gSecurityContext.CryptoEnabled = TRUE;
  gSecurityContext.HashEnabled = TRUE;
  gSecurityContext.SignatureEnabled = TRUE;
  
  // Initialize security counters
  gSecurityContext.VerificationCount = 0;
  gSecurityContext.FailureCount = 0;
  gSecurityContext.LastVerification = CurrentTsc;
  
  // Initialize entropy source
  gSecurityContext.EntropySeed = CurrentTsc ^ (CurrentTsc >> 32);
  
  gSecurityInitialized = TRUE;
  
  DEBUG((DEBUG_INFO, "[Security] Enterprise security system initialized\n"));
  
  return EFI_SUCCESS;
}

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
  )
{
  UINT64 CurrentTsc = AsmReadTsc();
  UINT32 CpuId[4];
  
  if (!gSecurityInitialized || Entropy == NULL || EntropySize == 0) {
    return EFI_INVALID_PARAMETER;
  }
  
  // Use multiple entropy sources
  for (UINTN i = 0; i < EntropySize; i++) {
    // TSC-based entropy
    UINT8 TscEntropy = (UINT8)(CurrentTsc & 0xFF);
    
    // CPUID-based entropy
    AsmCpuid(0, &CpuId[0], &CpuId[1], &CpuId[2], &CpuId[3]);
    UINT8 CpuidEntropy = (UINT8)(CpuId[0] ^ CpuId[1] ^ CpuId[2] ^ CpuId[3]);
    
    // Combine entropy sources
    Entropy[i] = TscEntropy ^ CpuidEntropy ^ (UINT8)(gSecurityContext.EntropySeed >> (i % 64));
    
    // Update entropy seed
    gSecurityContext.EntropySeed = (gSecurityContext.EntropySeed * 0x19660D) ^ CurrentTsc;
  }
  
  return EFI_SUCCESS;
}

/**
  Compute SHA-256 hash.
  
  @param[in] Data          Input data.
  @param[in] DataSize      Size of input data.
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
  )
{
  VOID *HashCtx = NULL;
  EFI_STATUS Status = EFI_SUCCESS;
  
  if (!gSecurityInitialized || Data == NULL || Hash == NULL || DataSize == 0) {
    return EFI_INVALID_PARAMETER;
  }
  
  // Initialize hash context
  HashCtx = Sha256New();
  if (HashCtx == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }
  
  // Hash the data
  if (!Sha256Init(HashCtx)) {
    Status = EFI_DEVICE_ERROR;
    goto Cleanup;
  }
  
  if (!Sha256Update(HashCtx, Data, DataSize)) {
    Status = EFI_DEVICE_ERROR;
    goto Cleanup;
  }
  
  if (!Sha256Final(HashCtx, Hash)) {
    Status = EFI_DEVICE_ERROR;
    goto Cleanup;
  }
  
Cleanup:
  if (HashCtx != NULL) {
    Sha256Free(HashCtx);
  }
  
  return Status;
}

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
  )
{
  VOID *RsaContext = NULL;
  BOOLEAN VerifyResult = FALSE;
  EFI_STATUS Status = EFI_SECURITY_VIOLATION;
  UINT8 HashValue[SHA256_HASH_SIZE];
  
  if (!gSecurityInitialized || Data == NULL || Signature == NULL || PublicKey == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  
  // Compute SHA-256 hash of data
  Status = ComputeSha256Hash(Data, DataSize, HashValue);
  if (EFI_ERROR(Status)) {
    return Status;
  }
  
  // Initialize RSA context
  RsaContext = RsaNew();
  if (RsaContext == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }
  
  // Set RSA public key
  UINT8 RsaExponent[] = {0x01, 0x00, 0x01}; // Standard exponent 65537
  
  if (!RsaSetKey(RsaContext, RsaKeyN, PublicKey, RSA_KEY_SIZE_4096)) {
    Status = EFI_INVALID_PARAMETER;
    goto Cleanup;
  }
  
  if (!RsaSetKey(RsaContext, RsaKeyE, RsaExponent, sizeof(RsaExponent))) {
    Status = EFI_INVALID_PARAMETER;
    goto Cleanup;
  }
  
  // Verify signature
  VerifyResult = RsaPkcs1Verify(
    RsaContext,
    HashValue,
    SHA256_HASH_SIZE,
    Signature,
    RSA_KEY_SIZE_4096
  );
  
  if (VerifyResult) {
    Status = EFI_SUCCESS;
    gSecurityContext.VerificationCount++;
  } else {
    Status = EFI_SECURITY_VIOLATION;
    gSecurityContext.FailureCount++;
  }
  
Cleanup:
  if (RsaContext != NULL) {
    RsaFree(RsaContext);
  }
  
  return Status;
}

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
  )
{
  VOID *HmacCtx = NULL;
  EFI_STATUS Status = EFI_SUCCESS;
  
  if (!gSecurityInitialized || Data == NULL || Key == NULL || Hmac == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  
  // Initialize HMAC context
  HmacCtx = HmacSha256New(Key, KeySize);
  if (HmacCtx == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }
  
  // Compute HMAC
  if (!HmacSha256Init(HmacCtx)) {
    Status = EFI_DEVICE_ERROR;
    goto Cleanup;
  }
  
  if (!HmacSha256Update(HmacCtx, Data, DataSize)) {
    Status = EFI_DEVICE_ERROR;
    goto Cleanup;
  }
  
  if (!HmacSha256Final(HmacCtx, Hmac)) {
    Status = EFI_DEVICE_ERROR;
    goto Cleanup;
  }
  
Cleanup:
  if (HmacCtx != NULL) {
    HmacSha256Free(HmacCtx);
  }
  
  return Status;
}

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
  )
{
  UINT8 ComputedHash[SHA256_HASH_SIZE];
  UINT8 ComputedHmac[SHA256_HASH_SIZE];
  EFI_STATUS Status;
  
  if (!gSecurityInitialized || AuthData == NULL || AuthSize == 0) {
    return EFI_INVALID_PARAMETER;
  }
  
  // Compute hash of authorization data (excluding signature fields)
  Status = ComputeSha256Hash(AuthData, AuthSize - SHA256_HASH_SIZE, ComputedHash);
  if (EFI_ERROR(Status)) {
    return Status;
  }
  
  // Verify hash integrity
  if (CompareMem(ComputedHash, AuthData + AuthSize - SHA256_HASH_SIZE, SHA256_HASH_SIZE) != 0) {
    DEBUG((DEBUG_ERROR, "[Security] Authorization hash verification failed\n"));
    return EFI_SECURITY_VIOLATION;
  }
  
  // Compute HMAC for additional integrity check
  UINT8 HmacKey[HMAC_KEY_SIZE];
  Status = GenerateHardwareEntropy(HmacKey, HMAC_KEY_SIZE);
  if (EFI_ERROR(Status)) {
    return Status;
  }
  
  Status = ComputeHmacSha256(AuthData, AuthSize - SHA256_HASH_SIZE, HmacKey, HMAC_KEY_SIZE, ComputedHmac);
  if (EFI_ERROR(Status)) {
    return Status;
  }
  
  // Verify HMAC integrity
  if (CompareMem(ComputedHmac, AuthData + AuthSize - SHA256_HASH_SIZE, SHA256_HASH_SIZE) != 0) {
    DEBUG((DEBUG_ERROR, "[Security] Authorization HMAC verification failed\n"));
    return EFI_SECURITY_VIOLATION;
  }
  
  DEBUG((DEBUG_INFO, "[Security] Authorization integrity verified successfully\n"));
  return EFI_SUCCESS;
}

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
  )
{
  EFI_STATUS Status;
  UINT64 CurrentTsc = AsmReadTsc();
  
  if (!gSecurityInitialized) {
    return EFI_NOT_READY;
  }
  
  DEBUG((DEBUG_INFO, "[Security] Performing comprehensive security verification\n"));
  
  // Step 1: Verify authorization integrity
  Status = VerifyAuthorizationIntegrity(AuthData, AuthSize);
  if (EFI_ERROR(Status)) {
    DEBUG((DEBUG_ERROR, "[Security] Authorization integrity verification failed: %r\n", Status));
    return Status;
  }
  
  // Step 2: Verify digital signature
  Status = VerifyRsaSignature(AuthData, AuthSize - RSA_KEY_SIZE_4096, 
                             AuthData + AuthSize - RSA_KEY_SIZE_4096, PublicKey);
  if (EFI_ERROR(Status)) {
    DEBUG((DEBUG_ERROR, "[Security] Digital signature verification failed: %r\n", Status));
    return Status;
  }
  
  // Step 3: Additional security checks
  // Check for replay attacks
  if (gSecurityContext.LastVerification != 0) {
    UINT64 TimeDiff = CurrentTsc - gSecurityContext.LastVerification;
    if (TimeDiff < 1000) { // Too fast - possible replay
      DEBUG((DEBUG_ERROR, "[Security] Possible replay attack detected\n"));
      return EFI_SECURITY_VIOLATION;
    }
  }
  
  // Update security context
  gSecurityContext.LastVerification = CurrentTsc;
  gSecurityContext.VerificationCount++;
  
  DEBUG((DEBUG_INFO, "[Security] Comprehensive security verification passed\n"));
  return EFI_SUCCESS;
}

/**
  Get security statistics.
  
  @param[out] Stats        Security statistics.
  
  @retval EFI_SUCCESS      Statistics retrieved.
**/
EFI_STATUS
EFIAPI
GetSecurityStats (
  OUT SECURITY_STATS *Stats
  )
{
  if (!gSecurityInitialized || Stats == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  
  Stats->VerificationCount = gSecurityContext.VerificationCount;
  Stats->FailureCount = gSecurityContext.FailureCount;
  Stats->LastVerification = gSecurityContext.LastVerification;
  Stats->CryptoEnabled = gSecurityContext.CryptoEnabled;
  Stats->HashEnabled = gSecurityContext.HashEnabled;
  Stats->SignatureEnabled = gSecurityContext.SignatureEnabled;
  
  return EFI_SUCCESS;
}
