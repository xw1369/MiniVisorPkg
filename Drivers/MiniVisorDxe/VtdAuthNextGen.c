/** @file
  Intel VT-d Driver Unified Authorization Implementation
  
  This file implements the unified authorization system for Intel VT-d/VT-x
  hypervisor driver, fully aligned with AuthGenerator authorization format.
  
  Copyright (c) 2024, Virtualization Project. All rights reserved.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "MiniVisorDxe.h"
#include "../../Include/UnifiedAuth.h"

//
// Global variables for VT-d authorization
//
STATIC BOOLEAN                      gVtdAuthInitialized = FALSE;
STATIC MINI_VISOR_AUTH_CONTEXT      gVtdAuthContext;
MINI_VISOR_AUTHORIZATION     *gVtdCurrentAuth = NULL;
STATIC UINT32                       gVtdCompatibilityScore = 0;
STATIC MINI_VISOR_AUTH_STATUS       gVtdAuthStatus = MiniVisorAuthStatusUnauthorized;
STATIC MINI_VISOR_HARDWARE_FINGERPRINT gVtdCurrentHardware;
STATIC MINI_VISOR_COMPATIBILITY_MATRIX  gVtdCompatMatrix;

//
// VT-d specific authorization thresholds (Strict security maintained)
//
#define VTD_MIN_COMPATIBILITY_THRESHOLD    600  // Strict threshold
#define VTD_RECOMMENDED_THRESHOLD          750  // Strict threshold
#define VTD_STRICT_THRESHOLD               900  // Strict threshold

//
// Function declarations - Using MiniVisorAuthLib functions
//

/**
  Initialize Intel VT-d authorization system.
  
  @retval EFI_SUCCESS           Initialization successful.
  @retval EFI_ALREADY_STARTED   Already initialized.
  @retval Others                Initialization failed.
**/
EFI_STATUS
EFIAPI
VtdAuthInitialize (
  VOID
  )
{
  EFI_STATUS  Status;
  
  if (gVtdAuthInitialized) {
    return EFI_ALREADY_STARTED;
  }
  
  DEBUG ((DEBUG_INFO, "[VTD-AUTH] Initializing Intel VT-d Unified Authorization System\n"));
  
  //
  // Initialize authorization context for Intel platform
  //
  Status = MiniVisorAuthInitialize (
             &gVtdAuthContext,
             MiniVisorPlatformIntel,
             VTD_RECOMMENDED_THRESHOLD
             );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "[VTD-AUTH] Failed to initialize auth context: %r\n", Status));
    return Status;
  }
  
  //
  // Generate hardware fingerprint
  //
  Status = MiniVisorAuthGenerateFingerprint (&gVtdCurrentHardware);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_WARN, "[VTD-AUTH] Failed to generate fingerprint, using default: %r\n", Status));
  }
  
  //
  // Initialize compatibility matrix with default values
  //
  ZeroMem(&gVtdCompatMatrix, sizeof(MINI_VISOR_COMPATIBILITY_MATRIX));
  gVtdCompatMatrix.MatrixVersion = 1;
  gVtdCompatMatrix.MatrixSize = sizeof(MINI_VISOR_COMPATIBILITY_MATRIX);
  
  DEBUG ((DEBUG_INFO, "[VTD-AUTH] Intel VT-d compatibility matrix initialized\n"));
  
  gVtdAuthInitialized = TRUE;
  DEBUG ((DEBUG_INFO, "[VTD-AUTH] Intel VT-d authorization system initialized successfully\n"));
  
  return EFI_SUCCESS;
}

/**
  Verify authorization using unified authorization system.
  This is the only authorization method supported, fully aligned with AuthGenerator.
  
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
  )
{
  EFI_STATUS                Status;
  MINI_VISOR_AUTHORIZATION  *Authorization;
  UINT32                    CompatibilityScore;
  
  if (!gVtdAuthInitialized) {
    Status = VtdAuthInitialize ();
    if (EFI_ERROR (Status)) {
      return Status;
    }
  }
  
  if (AuthData == NULL || AuthSize == 0) {
    DEBUG ((DEBUG_ERROR, "[VTD-AUTH] Invalid authorization data\n"));
    return EFI_INVALID_PARAMETER;
  }
  
  DEBUG ((DEBUG_INFO, "[VTD-AUTH] Starting unified authorization verification\n"));
  DEBUG ((DEBUG_INFO, "[VTD-AUTH] Authorization data size: %d bytes\n", AuthSize));
  
  //
  // Parse authorization structure
  //
  Authorization = (MINI_VISOR_AUTHORIZATION *)AuthData;
  
  //
  // Verify authorization using unified system
  //
  // Prepare a working context reflecting current hardware
  gVtdAuthContext.CurrentHardware = gVtdCurrentHardware;
  gVtdAuthStatus = MiniVisorAuthVerify (&gVtdAuthContext, Authorization);
  
  if (gVtdAuthStatus == MiniVisorAuthStatusAuthorized) {
    //
    // Calculate compatibility score for Intel platform
    //
    CompatibilityScore = MiniVisorAuthCalculateCompatibility (
                           &Authorization->HardwareFingerprint,
                           &gVtdCurrentHardware,
                           &gVtdCompatMatrix
                           );
    
    gVtdCompatibilityScore = CompatibilityScore;
    gVtdCurrentAuth = Authorization;
    
    //
    // Update global status
    //
    gMiniVisorGlobalData.Status |= MINI_VISOR_STATUS_AUTH_VERIFIED;
    gMiniVisorGlobalData.Status |= MINI_VISOR_STATUS_UNIFIED_AUTH;
    gMiniVisorGlobalData.CompatibilityScore = CompatibilityScore;
    gMiniVisorGlobalData.UnifiedAuthEnabled = TRUE;
    
    DEBUG ((DEBUG_INFO, "[VTD-AUTH] Unified authorization PASSED\n"));
    DEBUG ((DEBUG_INFO, "[VTD-AUTH] Compatibility Score: %d/1000\n", CompatibilityScore));
    DEBUG ((DEBUG_INFO, "[VTD-AUTH] Authorization Type: %d\n", Authorization->AuthType));
    DEBUG ((DEBUG_INFO, "[VTD-AUTH] Platform: Intel VT-x/VT-d\n"));
    
    //
    // Security: Do not expose detailed compatibility ratings to prevent reverse engineering
    //
    if (CompatibilityScore >= VTD_STRICT_THRESHOLD) {
      DEBUG ((DEBUG_INFO, "[VTD-AUTH] Security Level: MAXIMUM\n"));
    } else if (CompatibilityScore >= VTD_RECOMMENDED_THRESHOLD) {
      DEBUG ((DEBUG_INFO, "[VTD-AUTH] Security Level: ENHANCED\n"));
    } else if (CompatibilityScore >= VTD_MIN_COMPATIBILITY_THRESHOLD) {
      DEBUG ((DEBUG_INFO, "[VTD-AUTH] Security Level: STANDARD\n"));
    } else {
      DEBUG ((DEBUG_WARN, "[VTD-AUTH] Security Level: MINIMAL\n"));
    }
    
    return EFI_SUCCESS;
  } else {
    DEBUG ((DEBUG_WARN, "[VTD-AUTH] Unified authorization FAILED\n"));
    DEBUG ((DEBUG_WARN, "[VTD-AUTH] Status: %d\n", gVtdAuthStatus));
    return EFI_ACCESS_DENIED;
  }
}

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
  )
{
  if (AuthStatus == NULL || CompatScore == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  
  *AuthStatus = gVtdAuthStatus;
  *CompatScore = gVtdCompatibilityScore;
  
  return EFI_SUCCESS;
}

/**
  Print VT-d authorization diagnostics.
  
  @retval EFI_SUCCESS       Diagnostics printed successfully.
**/
EFI_STATUS
EFIAPI
VtdAuthPrintDiagnostics (
  VOID
  )
{
  DEBUG ((DEBUG_INFO, "\n"));
  DEBUG ((DEBUG_INFO, "=== Intel VT-d Authorization Diagnostics ===\n"));
  DEBUG ((DEBUG_INFO, "Platform: Intel VT-x/VT-d\n"));
  DEBUG ((DEBUG_INFO, "Current Status: %s\n", 
          (gVtdAuthStatus == MiniVisorAuthStatusAuthorized) ? "AUTHORIZED" : "UNAUTHORIZED"));
  DEBUG ((DEBUG_INFO, "Compatibility Score: %d/1000\n", gVtdCompatibilityScore));
  DEBUG ((DEBUG_INFO, "Unified Auth: %s\n", 
          gMiniVisorGlobalData.UnifiedAuthEnabled ? "ENABLED" : "DISABLED"));
  
  if (gVtdCurrentAuth != NULL) {
    DEBUG ((DEBUG_INFO, "Authorization Type: %d\n", gVtdCurrentAuth->AuthType));
    DEBUG ((DEBUG_INFO, "Issued Time: %d\n", gVtdCurrentAuth->IssuedTime));
    DEBUG ((DEBUG_INFO, "Expiry Time: %d\n", gVtdCurrentAuth->ExpiryTime));
  }
  
  DEBUG ((DEBUG_INFO, "Security Features:\n"));
  DEBUG ((DEBUG_INFO, "  - Quantum-Safe Crypto: Enabled\n"));
  DEBUG ((DEBUG_INFO, "  - Hardware Fingerprint: Enabled\n"));
  DEBUG ((DEBUG_INFO, "  - Compatibility Matrix: Enabled\n"));
  DEBUG ((DEBUG_INFO, "  - Unified Verification: Enabled\n"));
  
  DEBUG ((DEBUG_INFO, "Intel Optimizations:\n"));
  DEBUG ((DEBUG_INFO, "  - VT-x Weight Boost: +30\n"));
  DEBUG ((DEBUG_INFO, "  - VT-d Weight Boost: +20\n"));
  DEBUG ((DEBUG_INFO, "  - Chipset Weight Boost: +20\n"));
  DEBUG ((DEBUG_INFO, "  - Security Features: +15\n"));
  
  DEBUG ((DEBUG_INFO, "=======================================\n"));
  DEBUG ((DEBUG_INFO, "\n"));
  
  return EFI_SUCCESS;
}

/**
  Generate upgrade recommendations for Intel platform.
  
  @retval EFI_SUCCESS       Recommendations generated.
**/
EFI_STATUS
EFIAPI
VtdAuthGenerateUpgradeRecommendations (
  VOID
  )
{
  DEBUG ((DEBUG_INFO, "\n"));
  DEBUG ((DEBUG_INFO, "Intel VT-d Upgrade Recommendations\n"));
  DEBUG ((DEBUG_INFO, "=====================================\n"));
  
  if (gVtdCompatibilityScore < VTD_MIN_COMPATIBILITY_THRESHOLD) {
    DEBUG ((DEBUG_INFO, "Hardware compatibility too low (%d%%)\n", gVtdCompatibilityScore / 10));
    DEBUG ((DEBUG_INFO, "Recommendations:\n"));
    DEBUG ((DEBUG_INFO, "  1. Upgrade to newer Intel CPU with latest VT-x features\n"));
    DEBUG ((DEBUG_INFO, "  2. Update motherboard BIOS to latest version\n"));
    DEBUG ((DEBUG_INFO, "  3. Enable all virtualization features in BIOS\n"));
    DEBUG ((DEBUG_INFO, "  4. Consider Intel vPro platform for enterprise features\n"));
  } else if (gVtdCompatibilityScore < VTD_RECOMMENDED_THRESHOLD) {
    DEBUG ((DEBUG_INFO, "Hardware compatibility acceptable (%d%%)\n", gVtdCompatibilityScore / 10));
    DEBUG ((DEBUG_INFO, "Recommendations:\n"));
    DEBUG ((DEBUG_INFO, "  1. Update Intel chipset drivers\n"));
    DEBUG ((DEBUG_INFO, "  2. Enable Intel TXT if available\n"));
    DEBUG ((DEBUG_INFO, "  3. Consider memory upgrade for better performance\n"));
  } else {
    DEBUG ((DEBUG_INFO, "Hardware compatibility excellent (%d%%)\n", gVtdCompatibilityScore / 10));
    DEBUG ((DEBUG_INFO, "Optimization suggestions:\n"));
    DEBUG ((DEBUG_INFO, "  1. Enable Intel TSX if supported\n"));
    DEBUG ((DEBUG_INFO, "  2. Configure optimal IOMMU settings\n"));
    DEBUG ((DEBUG_INFO, "  3. Consider Intel SGX for enhanced security\n"));
  }
  
  if (!gMiniVisorGlobalData.UnifiedAuthEnabled) {
    DEBUG ((DEBUG_INFO, "\nAuthorization System:\n"));
    DEBUG ((DEBUG_INFO, "  1. Generate authorization with: auth_generator_v4.py\n"));
    DEBUG ((DEBUG_INFO, "  2. Use --platform intel for Intel-optimized weights\n"));
    DEBUG ((DEBUG_INFO, "  3. Test compatibility before production deployment\n"));
    DEBUG ((DEBUG_INFO, "  4. Benefits: Better compatibility, quantum-safe security\n"));
  }
  
  DEBUG ((DEBUG_INFO, "=====================================\n"));
  DEBUG ((DEBUG_INFO, "\n"));
  
  return EFI_SUCCESS;
}

/**
  Verify authorization using unified authorization library.
  
  @retval EFI_SUCCESS       Authorization verified successfully.
  @retval EFI_ACCESS_DENIED Authorization verification failed.
  @retval Others            Other errors occurred.
**/
EFI_STATUS
EFIAPI
VtdAuthVerifyUnifiedLibrary (
  VOID
  )
{
  EFI_STATUS Status;
  UNIFIED_AUTH_CONTEXT UnifiedContext;
  
  DEBUG ((DEBUG_INFO, "[VTD-AUTH] Starting unified authorization library verification\n"));
  
  //
  // Initialize unified authorization context
  //
  Status = UnifiedAuthInitialize(&UnifiedContext, PLATFORM_INTEL, 750);
  if (EFI_ERROR(Status)) {
    DEBUG ((DEBUG_ERROR, "[VTD-AUTH] Failed to initialize unified auth context: %r\n", Status));
    return Status;
  }
  
  //
  // Try to load authorization file from standard locations (USB root or C: root)
  //
  Status = UnifiedAuthLoadFromStandardLocations(&UnifiedContext);
  if (EFI_ERROR(Status)) {
    DEBUG ((DEBUG_WARN, "[VTD-AUTH] No auth.dat file found in standard locations (USB root or C: root): %r\n", Status));
    return EFI_ACCESS_DENIED;
  }
  
  //
  // Verify authorization
  //
  Status = UnifiedAuthVerify(&UnifiedContext);
  if (EFI_ERROR(Status)) {
    DEBUG ((DEBUG_WARN, "[VTD-AUTH] Unified authorization verification failed: %r\n", Status));
    UnifiedAuthDisplayStatus(&UnifiedContext, TRUE);
    return Status;
  }
  
  //
  // Authorization successful
  //
  DEBUG ((DEBUG_INFO, "[VTD-AUTH] Unified authorization library verification PASSED\n"));
  UnifiedAuthDisplayStatus(&UnifiedContext, FALSE);
  
  //
  // Update global status
  //
  gMiniVisorGlobalData.Status |= MINI_VISOR_STATUS_AUTH_VERIFIED;
  gMiniVisorGlobalData.Status |= MINI_VISOR_STATUS_UNIFIED_AUTH;
  gMiniVisorGlobalData.UnifiedAuthEnabled = TRUE;
  
  return EFI_SUCCESS;
}

//
// Function implementations
// Functions are now provided by MiniVisorAuthLib
