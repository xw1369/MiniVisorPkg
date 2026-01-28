/** @file
  SVM Driver Next-Generation Authorization Implementation
  
  This file implements the unified authorization system for the
  SVM driver, providing backward compatibility with legacy authorization
  while enabling advanced features.
  
  Copyright (c) 2024, Virtualization Project. All rights reserved.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiLib.h>

#include "MiniVisorSvmDxe.h"

//
// Global Variables
//
MINI_VISOR_AUTH_CONTEXT gSvmAuthContext = {0};

// Forward declarations for callbacks used before their definitions
EFI_STATUS
EFIAPI
SvmOnAuthorizationSuccess (
  VOID
  );

EFI_STATUS
EFIAPI
SvmOnAuthorizationFailure (
  IN MINI_VISOR_AUTH_STATUS Status
  );

EFI_STATUS
EFIAPI
SvmOnHardwareChange (
  IN MINI_VISOR_HARDWARE_FINGERPRINT *OldHw,
  IN MINI_VISOR_HARDWARE_FINGERPRINT *NewHw
  );

/**
  Initialize SVM authorization system with next-generation features.
  
  @retval EFI_SUCCESS          Authorization system initialized successfully.
  @retval Others               Initialization failed.
**/
EFI_STATUS
EFIAPI
SvmAuthInitializeNextGen (
  VOID
  )
{
  EFI_STATUS Status;
  
  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM NextGen Auth] Initializing next-generation authorization system...\n"));

  //
  // Initialize the unified authorization context for AMD SVM platform
  //
  Status = MiniVisorAuthInitialize(
    &gSvmAuthContext,
    MiniVisorPlatformAMD,      // AMD SVM platform
    RECOMMENDED_THRESHOLD      // Use recommended threshold (750)
  );

  if (EFI_ERROR(Status)) {
    MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM NextGen Auth] Failed to initialize authorization context: %r\n", Status));
    return Status;
  }

  //
  // Set SVM-specific configuration
  //
  gSvmAuthContext.QuantumCryptoEnabled = TRUE;   // Enable quantum-safe crypto
  gSvmAuthContext.CloudSyncEnabled = FALSE;     // Disable cloud sync for security
  gSvmAuthContext.TelemetryEnabled = TRUE;      // Enable telemetry for optimization
  gSvmAuthContext.AutoUpdateEnabled = FALSE;    // Disable auto-update

  //
  // Set up callbacks
  //
  gSvmAuthContext.OnAuthorizationSuccess = SvmOnAuthorizationSuccess;
  gSvmAuthContext.OnAuthorizationFailure = SvmOnAuthorizationFailure;
  gSvmAuthContext.OnHardwareChange = SvmOnHardwareChange;

  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM Unified Auth] Unified authorization system initialized\n"));
  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM Unified Auth] - Platform: AMD SVM/IOMMU\n"));
  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM Unified Auth] - Threshold: %d/%d\n", 
    gSvmAuthContext.AuthorizationThreshold, MAX_COMPATIBILITY_SCORE));
  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM Unified Auth] - Quantum Crypto: Enabled\n"));
  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM Unified Auth] - Telemetry: Enabled\n"));

  return EFI_SUCCESS;
}

/**
  Verify authorization using the unified authorization system.
  
  @retval MINI_VISOR_AUTH_STATUS Authorization status.
**/
MINI_VISOR_AUTH_STATUS
EFIAPI
SvmAuthVerifyUnified (
  VOID
  )
{
  EFI_STATUS Status;
  MINI_VISOR_AUTH_STATUS AuthStatus;
  
  if (!gSvmAuthContext.Initialized) {
    MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM NextGen Auth] Context not initialized\n"));
    return MiniVisorAuthStatusInvalid;
  }

  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM Unified Auth] Starting unified authorization verification...\n"));

  //
  // Try to load authorization file if not already loaded
  //
  if (gSvmAuthContext.CurrentAuth == NULL) {
    Status = MiniVisorAuthLoad(&gSvmAuthContext, NULL); // Auto-discover
    if (EFI_ERROR(Status)) {
      MINI_VISOR_SVM_DEBUG((DEBUG_WARN, "[SVM Unified Auth] No unified authorization file found, status: %r\n", Status));
      return MiniVisorAuthStatusUnauthorized;
    }
  }

  //
  // Perform unified verification
  //
  if (gSvmAuthContext.CurrentAuth != NULL) {
    AuthStatus = MiniVisorAuthVerify(&gSvmAuthContext, gSvmAuthContext.CurrentAuth);
  } else {
    AuthStatus = MiniVisorAuthStatusUnauthorized;
  }

  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM Unified Auth] Unified verification result: %d\n", AuthStatus));

  return AuthStatus;
}

/**
  Verify authorization using unified authorization library.
  
  @retval EFI_SUCCESS       Authorization verified successfully.
  @retval EFI_ACCESS_DENIED Authorization verification failed.
  @retval Others            Other errors occurred.
**/
EFI_STATUS
EFIAPI
SvmAuthVerifyUnifiedLibrary (
  VOID
  )
{
  EFI_STATUS Status;
  UNIFIED_AUTH_CONTEXT UnifiedContext;
  
  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM-AUTH] Starting unified authorization library verification\n"));
  
  //
  // Initialize unified authorization context
  //
  Status = UnifiedAuthInitialize(&UnifiedContext, PLATFORM_AMD, 750);
  if (EFI_ERROR(Status)) {
    MINI_VISOR_SVM_DEBUG((DEBUG_ERROR, "[SVM-AUTH] Failed to initialize unified auth context: %r\n", Status));
    return Status;
  }
  
  //
  // Try to load authorization file from standard locations (USB root or C: root)
  //
  Status = UnifiedAuthLoadFromStandardLocations(&UnifiedContext);
  if (EFI_ERROR(Status)) {
    MINI_VISOR_SVM_DEBUG((DEBUG_WARN, "[SVM-AUTH] No auth.dat file found in standard locations (USB root or C: root): %r\n", Status));
    return EFI_ACCESS_DENIED;
  }
  
  //
  // Verify authorization
  //
  Status = UnifiedAuthVerify(&UnifiedContext);
  if (EFI_ERROR(Status)) {
    MINI_VISOR_SVM_DEBUG((DEBUG_WARN, "[SVM-AUTH] Unified authorization verification failed: %r\n", Status));
    UnifiedAuthDisplayStatus(&UnifiedContext, TRUE);
    return Status;
  }
  
  //
  // Authorization successful
  //
  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM-AUTH] Unified authorization library verification PASSED\n"));
  UnifiedAuthDisplayStatus(&UnifiedContext, FALSE);
  
  //
  // Update global status
  //
  gMiniVisorSvmGlobalData.Status |= MINI_VISOR_STATUS_AUTH_VERIFIED;
  gMiniVisorSvmGlobalData.Status |= MINI_VISOR_STATUS_UNIFIED_AUTH;
  gMiniVisorSvmGlobalData.UnifiedAuthEnabled = TRUE;
  
  return EFI_SUCCESS;
}

/**
  Display comprehensive authorization status for SVM driver.
  
  @param[in] Verbose           TRUE for detailed output.
  
  @retval EFI_SUCCESS          Status displayed successfully.
**/
EFI_STATUS
EFIAPI
SvmAuthDisplayStatus (
  IN BOOLEAN Verbose
  )
{
  EFI_STATUS Status;
  
  Print(L"\n=== SVM Driver Authorization Status ===\n");
  
  if (!gSvmAuthContext.Initialized) {
    Print(L"[SVM Unified Auth] Unified authorization system not initialized\n");
    Print(L"[SVM 统一授权] 统一授权系统未初始化\n");
    return EFI_NOT_READY;
  }

  //
  // Use unified status display
  //
  Status = MiniVisorAuthDisplayStatus(&gSvmAuthContext, Verbose);
  if (EFI_ERROR(Status)) {
    return Status;
  }

  //
  // Add SVM-specific information
  //
  if (Verbose) {
    Print(L"\n--- SVM-Specific Features ---\n");
    Print(L"Driver Type: AMD SVM/IOMMU\n");
    Print(L"Nested Virtualization: %s\n", 
      gMiniVisorSvmGlobalData.AdvancedFeatures.NestedSvmEnabled ? L"Enabled" : L"Disabled");
    Print(L"AVIC Support: %s\n", 
      gMiniVisorSvmGlobalData.AdvancedFeatures.AvicEnabled ? L"Enabled" : L"Disabled");
    Print(L"NPT Support: %s\n", 
      gMiniVisorSvmGlobalData.NptEnabled ? L"Enabled" : L"Disabled");
    Print(L"Current ASID: %d/%d\n", 
      gMiniVisorSvmGlobalData.CurrentAsid, gMiniVisorSvmGlobalData.MaxAsid);
  }

  Print(L"=========================================\n\n");
  
  return EFI_SUCCESS;
}

//
// Callback Functions
//

/**
  Callback function called when authorization succeeds.
  
  @retval EFI_SUCCESS          Callback handled successfully.
**/
EFI_STATUS
EFIAPI
SvmOnAuthorizationSuccess (
  VOID
  )
{
  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM NextGen Auth] Authorization success callback triggered\n"));
  
  //
  // Update SVM driver state
  //
  gMiniVisorSvmGlobalData.Status |= MINI_VISOR_SVM_STATUS_INITIALIZED;
  
  //
  // Log success event
  //
  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM NextGen Auth] SVM driver authorization completed successfully\n"));
  
  return EFI_SUCCESS;
}

/**
  Callback function called when authorization fails.
  
  @param[in] Status            Authorization failure status.
  
  @retval EFI_SUCCESS          Callback handled successfully.
**/
EFI_STATUS
EFIAPI
SvmOnAuthorizationFailure (
  IN MINI_VISOR_AUTH_STATUS Status
  )
{
  MINI_VISOR_SVM_DEBUG((DEBUG_WARN, "[SVM NextGen Auth] Authorization failure callback triggered: %d\n", Status));
  
  //
  // Update SVM driver state
  //
  gMiniVisorSvmGlobalData.Status |= MINI_VISOR_SVM_STATUS_ERROR;
  
  //
  // Provide specific guidance based on failure type
  //
  switch (Status) {
    case MiniVisorAuthStatusExpired:
      Print(L"[SVM NextGen Auth] Suggestion: Contact your vendor to renew authorization\n");
      break;
    case MiniVisorAuthStatusInvalid:
      Print(L"[SVM NextGen Auth] Suggestion: Verify authorization file integrity\n");
      break;
    default:
      Print(L"[SVM NextGen Auth] Suggestion: Run hardware compatibility assessment\n");
      break;
  }
  
  return EFI_SUCCESS;
}

/**
  Callback function called when hardware changes are detected.
  
  @param[in] OldHw             Previous hardware fingerprint.
  @param[in] NewHw             New hardware fingerprint.
  
  @retval EFI_SUCCESS          Callback handled successfully.
**/
EFI_STATUS
EFIAPI
SvmOnHardwareChange (
  IN MINI_VISOR_HARDWARE_FINGERPRINT *OldHw,
  IN MINI_VISOR_HARDWARE_FINGERPRINT *NewHw
  )
{
  MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM NextGen Auth] Hardware change callback triggered\n"));
  
  if (OldHw == NULL || NewHw == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Analyze the type of hardware change
  //
  if (OldHw->CpuSignature != NewHw->CpuSignature) {
    MINI_VISOR_SVM_DEBUG((DEBUG_WARN, "[SVM NextGen Auth] CPU change detected: 0x%08x -> 0x%08x\n", 
      OldHw->CpuSignature, NewHw->CpuSignature));
    Print(L"[SVM NextGen Auth] Major hardware change detected (CPU)\n");
  }
  
  if (OldHw->MainboardSerialHash != NewHw->MainboardSerialHash) {
    MINI_VISOR_SVM_DEBUG((DEBUG_WARN, "[SVM NextGen Auth] Mainboard change detected: 0x%08x -> 0x%08x\n", 
      OldHw->MainboardSerialHash, NewHw->MainboardSerialHash));
    Print(L"[SVM NextGen Auth] Major hardware change detected (Mainboard)\n");
  }
  
  if (OldHw->MemorySize != NewHw->MemorySize) {
    MINI_VISOR_SVM_DEBUG((DEBUG_INFO, "[SVM NextGen Auth] Memory change detected: %d -> %d MB\n", 
      (UINT32)(OldHw->MemorySize / (1024*1024)), (UINT32)(NewHw->MemorySize / (1024*1024))));
    Print(L"[SVM NextGen Auth] Memory configuration changed\n");
  }

  //
  // Suggest re-authorization if significant changes detected
  //
  if (OldHw->CpuSignature != NewHw->CpuSignature || 
      OldHw->MainboardSerialHash != NewHw->MainboardSerialHash) {
    Print(L"[SVM NextGen Auth] Recommendation: Update authorization for new hardware\n");
  }
  
  return EFI_SUCCESS;
}


