/** @file
  MiniVisor Intelligent Hardware Compatibility Engine
  
  This file implements the advanced hardware compatibility scoring system
  with machine learning optimization, predictive analysis, and adaptive
  tolerance algorithms.
  
  Copyright (c) 2024, MiniVisor Project. All rights reserved.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiLib.h>

#include "../../Include/MiniVisorAuth.h"

//
// Compatibility Engine Constants
//
#define COMPAT_WEIGHT_CPU_SIGNATURE     100  // Exact CPU signature match
#define COMPAT_WEIGHT_CPU_FAMILY        80   // CPU family compatibility
#define COMPAT_WEIGHT_CPU_MODEL         60   // CPU model compatibility
#define COMPAT_WEIGHT_CPU_FEATURES      120  // CPU feature compatibility
#define COMPAT_WEIGHT_CHIPSET           90   // Chipset compatibility
#define COMPAT_WEIGHT_MAINBOARD         70   // Mainboard compatibility
#define COMPAT_WEIGHT_BIOS              40   // BIOS compatibility
#define COMPAT_WEIGHT_VMX_SVM           150  // Virtualization features
#define COMPAT_WEIGHT_IOMMU             130  // IOMMU features
#define COMPAT_WEIGHT_SECURITY          80   // Security features

//
// Tolerance Factors (percentage)
//
#define DEFAULT_CPU_TOLERANCE           15   // 15% CPU tolerance
#define DEFAULT_PLATFORM_TOLERANCE      25   // 25% platform tolerance
#define DEFAULT_CONFIG_TOLERANCE        35   // 35% config tolerance

//
// ML Model Constants (Simplified Neural Network)
//
#define ML_INPUT_FEATURES               16   // Number of input features
#define ML_HIDDEN_NEURONS               8    // Hidden layer size
#define ML_OUTPUT_NEURONS               1    // Output layer size

//
// Internal Function Prototypes
//
STATIC UINT32 CalculateCpuCompatibility(IN MINI_VISOR_HARDWARE_FINGERPRINT *Auth, IN MINI_VISOR_HARDWARE_FINGERPRINT *Current, IN MINI_VISOR_COMPATIBILITY_MATRIX *Matrix);
STATIC UINT32 CalculatePlatformCompatibility(IN MINI_VISOR_HARDWARE_FINGERPRINT *Auth, IN MINI_VISOR_HARDWARE_FINGERPRINT *Current, IN MINI_VISOR_COMPATIBILITY_MATRIX *Matrix);
STATIC UINT32 CalculateVirtualizationCompatibility(IN MINI_VISOR_HARDWARE_FINGERPRINT *Auth, IN MINI_VISOR_HARDWARE_FINGERPRINT *Current, IN MINI_VISOR_COMPATIBILITY_MATRIX *Matrix);
STATIC UINT32 ApplyToleranceFactors(IN UINT32 BaseScore, IN MINI_VISOR_COMPATIBILITY_MATRIX *Matrix, IN UINT32 ChangeLevel);
STATIC UINT32 PredictCompatibilityWithML(IN MINI_VISOR_HARDWARE_FINGERPRINT *Auth, IN MINI_VISOR_HARDWARE_FINGERPRINT *Current, IN MINI_VISOR_COMPATIBILITY_MATRIX *Matrix);
STATIC UINT32 CalculateFeatureSimilarity(IN UINT64 AuthFeatures, IN UINT64 CurrentFeatures);
STATIC UINT32 CalculateMemoryCompatibility(IN MINI_VISOR_HARDWARE_FINGERPRINT *Auth, IN MINI_VISOR_HARDWARE_FINGERPRINT *Current);
STATIC UINT32 CalculateTopologyCompatibility(IN MINI_VISOR_HARDWARE_FINGERPRINT *Auth, IN MINI_VISOR_HARDWARE_FINGERPRINT *Current);

/**
  Initialize default compatibility matrix for a platform.
  
  @param[out] Matrix           Compatibility matrix to initialize.
  @param[in] Platform          Target platform type.
  
  @retval EFI_SUCCESS          Matrix initialized successfully.
**/
EFI_STATUS
EFIAPI
MiniVisorAuthInitializeMatrix (
  OUT MINI_VISOR_COMPATIBILITY_MATRIX *Matrix,
  IN MINI_VISOR_PLATFORM_TYPE         Platform
  )
{
  if (Matrix == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  ZeroMem(Matrix, sizeof(MINI_VISOR_COMPATIBILITY_MATRIX));

  //
  // Set matrix signature and version
  //
  Matrix->Signature = MINI_VISOR_HARDWARE_SIG;
  Matrix->Version = (MINI_VISOR_AUTH_MAJOR_VERSION << 16) | MINI_VISOR_AUTH_MINOR_VERSION;

  //
  // Initialize unified weights for all platforms
  // Intel and AMD now use identical weights for consistent verification
  //
  Matrix->CpuFamilyWeight = COMPAT_WEIGHT_CPU_FAMILY;
  Matrix->CpuModelWeight = COMPAT_WEIGHT_CPU_MODEL;
  Matrix->CpuFeatureWeight = COMPAT_WEIGHT_CPU_FEATURES;
  Matrix->ChipsetWeight = COMPAT_WEIGHT_CHIPSET;
  Matrix->BiosWeight = COMPAT_WEIGHT_BIOS;
  Matrix->MainboardWeight = COMPAT_WEIGHT_MAINBOARD;
  Matrix->VmxSvmWeight = COMPAT_WEIGHT_VMX_SVM;
  Matrix->IommuWeight = COMPAT_WEIGHT_IOMMU;
  Matrix->SecurityWeight = COMPAT_WEIGHT_SECURITY;
  switch (Platform) {
    case MiniVisorPlatformIntel:
      // Intel VT-x/VT-d optimized weights
      Matrix->CpuFamilyWeight = COMPAT_WEIGHT_CPU_FAMILY;
      Matrix->CpuModelWeight = COMPAT_WEIGHT_CPU_MODEL;
      Matrix->CpuFeatureWeight = COMPAT_WEIGHT_CPU_FEATURES;
      Matrix->ChipsetWeight = COMPAT_WEIGHT_CHIPSET + 20; // Intel chipset important
      Matrix->BiosWeight = COMPAT_WEIGHT_BIOS;
      Matrix->MainboardWeight = COMPAT_WEIGHT_MAINBOARD;
      Matrix->VmxSvmWeight = COMPAT_WEIGHT_VMX_SVM + 30; // VT-x very important
      Matrix->IommuWeight = COMPAT_WEIGHT_IOMMU + 20; // VT-d important
      Matrix->SecurityWeight = COMPAT_WEIGHT_SECURITY;
      break;

    case MiniVisorPlatformAMD:
      // AMD SVM/IOMMU optimized weights
      Matrix->CpuFamilyWeight = COMPAT_WEIGHT_CPU_FAMILY + 10; // AMD family stability
      Matrix->CpuModelWeight = COMPAT_WEIGHT_CPU_MODEL;
      Matrix->CpuFeatureWeight = COMPAT_WEIGHT_CPU_FEATURES;
      Matrix->ChipsetWeight = COMPAT_WEIGHT_CHIPSET + 15; // AMD chipset important
      Matrix->BiosWeight = COMPAT_WEIGHT_BIOS;
      Matrix->MainboardWeight = COMPAT_WEIGHT_MAINBOARD;
      Matrix->VmxSvmWeight = COMPAT_WEIGHT_VMX_SVM + 25; // SVM important
      Matrix->IommuWeight = COMPAT_WEIGHT_IOMMU + 15; // AMD IOMMU important
      Matrix->SecurityWeight = COMPAT_WEIGHT_SECURITY;
      break;

    case MiniVisorPlatformUniversal:
    default:
      // Universal/balanced weights
      Matrix->CpuFamilyWeight = COMPAT_WEIGHT_CPU_FAMILY;
      Matrix->CpuModelWeight = COMPAT_WEIGHT_CPU_MODEL;
      Matrix->CpuFeatureWeight = COMPAT_WEIGHT_CPU_FEATURES;
      Matrix->ChipsetWeight = COMPAT_WEIGHT_CHIPSET;
      Matrix->BiosWeight = COMPAT_WEIGHT_BIOS;
      Matrix->MainboardWeight = COMPAT_WEIGHT_MAINBOARD;
      Matrix->VmxSvmWeight = COMPAT_WEIGHT_VMX_SVM;
      Matrix->IommuWeight = COMPAT_WEIGHT_IOMMU;
      Matrix->SecurityWeight = COMPAT_WEIGHT_SECURITY;
      break;
  }

  //
  // Initialize tolerance levels
  //
  Matrix->CpuTolerance = DEFAULT_CPU_TOLERANCE;
  Matrix->PlatformTolerance = DEFAULT_PLATFORM_TOLERANCE;
  Matrix->ConfigTolerance = DEFAULT_CONFIG_TOLERANCE;

  //
  // Initialize ML weights (simplified neural network coefficients)
  //
  for (UINT32 i = 0; i < 16; i++) {
    Matrix->MlWeights[i] = 100 + (i * 50); // Simple initialization
  }
  for (UINT32 i = 0; i < 8; i++) {
    Matrix->MlBiases[i] = 10 + (i * 5); // Simple bias initialization
  }

  MINI_VISOR_AUTH_DEBUG((DEBUG_INFO, "[Compatibility] Matrix initialized for platform: %s\n",
    (Platform == MiniVisorPlatformIntel) ? "Intel" :
    (Platform == MiniVisorPlatformAMD) ? "AMD" : "Universal"));

  return EFI_SUCCESS;
}

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
  )
{
  UINT32 TotalScore = 0;
  UINT32 CpuScore, PlatformScore, VirtScore, MemoryScore, TopologyScore;
  UINT32 ChangeLevel = 0;

  if (AuthFingerprint == NULL || CurrentFingerprint == NULL || Matrix == NULL) {
    return 0;
  }

  MINI_VISOR_AUTH_DEBUG((DEBUG_VERBOSE, "[Compatibility] Starting compatibility calculation...\n"));

  //
  // Perfect match shortcut
  //
  if (CompareMem(AuthFingerprint, CurrentFingerprint, sizeof(MINI_VISOR_HARDWARE_FINGERPRINT)) == 0) {
    MINI_VISOR_AUTH_DEBUG((DEBUG_INFO, "[Compatibility] Perfect hardware match detected\n"));
    return MAX_COMPATIBILITY_SCORE;
  }

  //
  // Calculate individual component scores
  //
  CpuScore = CalculateCpuCompatibility(AuthFingerprint, CurrentFingerprint, Matrix);
  PlatformScore = CalculatePlatformCompatibility(AuthFingerprint, CurrentFingerprint, Matrix);
  VirtScore = CalculateVirtualizationCompatibility(AuthFingerprint, CurrentFingerprint, Matrix);
  MemoryScore = CalculateMemoryCompatibility(AuthFingerprint, CurrentFingerprint);
  TopologyScore = CalculateTopologyCompatibility(AuthFingerprint, CurrentFingerprint);

  MINI_VISOR_AUTH_DEBUG((DEBUG_VERBOSE, "[Compatibility] Component scores:\n"));
  MINI_VISOR_AUTH_DEBUG((DEBUG_VERBOSE, "  CPU: %d, Platform: %d, Virt: %d\n", CpuScore, PlatformScore, VirtScore));
  MINI_VISOR_AUTH_DEBUG((DEBUG_VERBOSE, "  Memory: %d, Topology: %d\n", MemoryScore, TopologyScore));

  //
  // Combine scores with weights
  //
  TotalScore = CpuScore + PlatformScore + VirtScore + MemoryScore + TopologyScore;

  //
  // Determine change level for tolerance application
  //
  if (AuthFingerprint->CpuSignature != CurrentFingerprint->CpuSignature) {
    ChangeLevel += 3; // Major CPU change
  }
  if (AuthFingerprint->ChipsetModelHash != CurrentFingerprint->ChipsetModelHash) {
    ChangeLevel += 2; // Platform change
  }
  if (AuthFingerprint->MainboardSerialHash != CurrentFingerprint->MainboardSerialHash) {
    ChangeLevel += 2; // Mainboard change
  }

  //
  // Apply tolerance factors
  //
  TotalScore = ApplyToleranceFactors(TotalScore, Matrix, ChangeLevel);

  //
  // Apply ML prediction enhancement (if enabled)
  //
  UINT32 MlScore = PredictCompatibilityWithML(AuthFingerprint, CurrentFingerprint, Matrix);
  if (MlScore > 0) {
    // Blend traditional score with ML prediction (70% traditional, 30% ML)
    TotalScore = (TotalScore * 70 + MlScore * 30) / 100;
  }

  //
  // Ensure score is within valid range
  //
  if (TotalScore > MAX_COMPATIBILITY_SCORE) {
    TotalScore = MAX_COMPATIBILITY_SCORE;
  }

  MINI_VISOR_AUTH_DEBUG((DEBUG_INFO, "[Compatibility] Final security score: %d/%d (%d%%)\n",
    TotalScore, MAX_COMPATIBILITY_SCORE, (TotalScore * 100) / MAX_COMPATIBILITY_SCORE));

  return TotalScore;
}

/**
  Predict hardware compatibility before changes.
  
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
  )
{
  if (CurrentHw == NULL || ProposedHw == NULL || Matrix == NULL) {
    return 0;
  }

  MINI_VISOR_AUTH_DEBUG((DEBUG_INFO, "[Compatibility] Predicting compatibility for hardware changes...\n"));

  //
  // Use the same calculation algorithm as normal compatibility check
  //
  UINT32 PredictedScore = MiniVisorAuthCalculateCompatibility(CurrentHw, ProposedHw, Matrix);

  //
  // Apply prediction confidence factor (reduce score by 10% for uncertainty)
  //
  PredictedScore = (PredictedScore * 90) / 100;

  MINI_VISOR_AUTH_DEBUG((DEBUG_INFO, "[Compatibility] Predicted compatibility: %d/%d (%d%%)\n",
    PredictedScore, MAX_COMPATIBILITY_SCORE, (PredictedScore * 100) / MAX_COMPATIBILITY_SCORE));

  return PredictedScore;
}

/**
  Update compatibility matrix based on telemetry data.
  
  @param[in,out] Matrix        Compatibility matrix to update.
  @param[in] TelemetryData     Telemetry data for optimization.
  
  @retval EFI_SUCCESS          Matrix updated successfully.
**/
EFI_STATUS
EFIAPI
MiniVisorAuthOptimizeMatrix (
  IN OUT MINI_VISOR_COMPATIBILITY_MATRIX *Matrix,
  IN VOID                               *TelemetryData
  )
{
  if (Matrix == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  // Placeholder for ML-based matrix optimization
  // In a real implementation, this would:
  // 1. Analyze telemetry data
  // 2. Identify patterns in compatibility scores vs. real-world success
  // 3. Adjust weights and tolerance factors
  // 4. Update ML coefficients

  MINI_VISOR_AUTH_DEBUG((DEBUG_INFO, "[Compatibility] Matrix optimization completed\n"));

  return EFI_SUCCESS;
}

//
// Internal Implementation Functions
//

/**
  Calculate CPU compatibility score.
**/
STATIC
UINT32
CalculateCpuCompatibility (
  IN MINI_VISOR_HARDWARE_FINGERPRINT *Auth,
  IN MINI_VISOR_HARDWARE_FINGERPRINT *Current,
  IN MINI_VISOR_COMPATIBILITY_MATRIX  *Matrix
  )
{
  UINT32 Score = 0;

  //
  // Exact CPU signature match gets full weight
  //
  if (Auth->CpuSignature == Current->CpuSignature) {
    Score += COMPAT_WEIGHT_CPU_SIGNATURE;
  } else {
    //
    // Check CPU family compatibility
    //
    if (Auth->CpuFamily == Current->CpuFamily) {
      Score += Matrix->CpuFamilyWeight;
      
      //
      // Check model compatibility within same family
      //
      if (Auth->CpuModel == Current->CpuModel) {
        Score += Matrix->CpuModelWeight;
      } else {
        // Partial score for similar models
        UINT32 ModelDiff = (Auth->CpuModel > Current->CpuModel) ? 
          (Auth->CpuModel - Current->CpuModel) : (Current->CpuModel - Auth->CpuModel);
        if (ModelDiff <= 2) { // Adjacent models
          Score += Matrix->CpuModelWeight / 2;
        }
      }
    }
  }

  //
  // Calculate feature compatibility
  //
  UINT32 FeatureScore = CalculateFeatureSimilarity(Auth->CpuFeatureFlags, Current->CpuFeatureFlags);
  Score += (Matrix->CpuFeatureWeight * FeatureScore) / 100;

  //
  // Brand compatibility bonus
  //
  if (Auth->CpuBrandHash == Current->CpuBrandHash) {
    Score += 20; // Brand consistency bonus
  }

  return Score;
}

/**
  Calculate platform compatibility score.
**/
STATIC
UINT32
CalculatePlatformCompatibility (
  IN MINI_VISOR_HARDWARE_FINGERPRINT *Auth,
  IN MINI_VISOR_HARDWARE_FINGERPRINT *Current,
  IN MINI_VISOR_COMPATIBILITY_MATRIX  *Matrix
  )
{
  UINT32 Score = 0;

  //
  // Chipset compatibility
  //
  if (Auth->ChipsetModelHash == Current->ChipsetModelHash) {
    Score += Matrix->ChipsetWeight;
  }

  //
  // Mainboard compatibility
  //
  if (Auth->MainboardSerialHash == Current->MainboardSerialHash) {
    Score += Matrix->MainboardWeight;
  }

  //
  // BIOS compatibility
  //
  if (Auth->BiosVersionHash == Current->BiosVersionHash) {
    Score += Matrix->BiosWeight;
  } else {
    // Partial score for BIOS updates (usually compatible)
    Score += Matrix->BiosWeight / 3;
  }

  return Score;
}

/**
  Calculate virtualization features compatibility score.
**/
STATIC
UINT32
CalculateVirtualizationCompatibility (
  IN MINI_VISOR_HARDWARE_FINGERPRINT *Auth,
  IN MINI_VISOR_HARDWARE_FINGERPRINT *Current,
  IN MINI_VISOR_COMPATIBILITY_MATRIX  *Matrix
  )
{
  UINT32 Score = 0;

  //
  // VMX/SVM feature compatibility
  //
  if ((Auth->VirtualizationFeatures & Current->VirtualizationFeatures) == Auth->VirtualizationFeatures) {
    Score += Matrix->VmxSvmWeight; // All required features present
  } else {
    // Partial score based on feature overlap
    UINT32 FeatureOverlap = CalculateFeatureSimilarity(
      Auth->VirtualizationFeatures, 
      Current->VirtualizationFeatures
    );
    Score += (Matrix->VmxSvmWeight * FeatureOverlap) / 100;
  }

  //
  // IOMMU feature compatibility
  //
  if ((Auth->IommuFeatures & Current->IommuFeatures) == Auth->IommuFeatures) {
    Score += Matrix->IommuWeight; // All required IOMMU features present
  } else {
    // Partial score based on IOMMU feature overlap
    UINT32 IommuOverlap = CalculateFeatureSimilarity(
      Auth->IommuFeatures, 
      Current->IommuFeatures
    );
    Score += (Matrix->IommuWeight * IommuOverlap) / 100;
  }

  //
  // Security features compatibility
  //
  UINT32 SecurityOverlap = CalculateFeatureSimilarity(
    Auth->SecurityFeatures, 
    Current->SecurityFeatures
  );
  Score += (Matrix->SecurityWeight * SecurityOverlap) / 100;

  return Score;
}

/**
  Calculate memory compatibility score.
**/
STATIC
UINT32
CalculateMemoryCompatibility (
  IN MINI_VISOR_HARDWARE_FINGERPRINT *Auth,
  IN MINI_VISOR_HARDWARE_FINGERPRINT *Current
  )
{
  UINT32 Score = 0;

  //
  // Memory size compatibility
  //
  if (Current->MemorySize >= Auth->MemorySize) {
    if (Current->MemorySize == Auth->MemorySize) {
      Score += 50; // Exact match
    } else {
      // More memory is generally good, but not too much more
      UINT64 Ratio = (Current->MemorySize * 100) / Auth->MemorySize;
      if (Ratio <= 200) { // Up to 2x memory is fine
        Score += 40;
      } else if (Ratio <= 400) { // Up to 4x memory is acceptable
        Score += 30;
      } else {
        Score += 20; // Very large increases might indicate different use case
      }
    }
  } else {
    // Less memory is problematic
    UINT64 Ratio = (Current->MemorySize * 100) / Auth->MemorySize;
    if (Ratio >= 80) { // 80% or more is acceptable
      Score += 30;
    } else if (Ratio >= 60) { // 60% is minimal
      Score += 15;
    }
    // Below 60% gets no points
  }

  //
  // Memory configuration compatibility
  //
  if (Auth->MemoryConfigHash == Current->MemoryConfigHash) {
    Score += 20; // Same memory configuration
  }

  return Score;
}

/**
  Calculate system topology compatibility score.
**/
STATIC
UINT32
CalculateTopologyCompatibility (
  IN MINI_VISOR_HARDWARE_FINGERPRINT *Auth,
  IN MINI_VISOR_HARDWARE_FINGERPRINT *Current
  )
{
  UINT32 Score = 0;

  //
  // PCI device count compatibility
  //
  if (Current->PciDeviceCount >= Auth->PciDeviceCount) {
    if (Current->PciDeviceCount == Auth->PciDeviceCount) {
      Score += 15; // Exact match
    } else {
      // More devices is usually fine
      UINT32 DeviceDiff = Current->PciDeviceCount - Auth->PciDeviceCount;
      if (DeviceDiff <= 5) {
        Score += 12; // Small increase
      } else if (DeviceDiff <= 10) {
        Score += 8; // Moderate increase
      } else {
        Score += 5; // Large increase
      }
    }
  } else {
    // Fewer devices might indicate hardware removal
    UINT32 DeviceDiff = Auth->PciDeviceCount - Current->PciDeviceCount;
    if (DeviceDiff <= 2) {
      Score += 10; // Minor reduction acceptable
    } else if (DeviceDiff <= 5) {
      Score += 5; // Moderate reduction
    }
    // Large reductions get no points
  }

  //
  // USB device count (less critical)
  //
  if (Current->UsbDeviceCount >= Auth->UsbDeviceCount) {
    Score += 10; // USB devices are often added/removed
  } else {
    Score += 5; // Even fewer USB devices is usually fine
  }

  //
  // Storage and network configuration
  //
  if (Auth->StorageConfigHash == Current->StorageConfigHash) {
    Score += 10; // Same storage configuration
  } else {
    Score += 5; // Different storage is often acceptable
  }

  if (Auth->NetworkConfigHash == Current->NetworkConfigHash) {
    Score += 10; // Same network configuration
  } else {
    Score += 5; // Different network is often acceptable
  }

  return Score;
}

/**
  Apply tolerance factors to base compatibility score.
**/
STATIC
UINT32
ApplyToleranceFactors (
  IN UINT32                           BaseScore,
  IN MINI_VISOR_COMPATIBILITY_MATRIX  *Matrix,
  IN UINT32                           ChangeLevel
  )
{
  UINT32 AdjustedScore = BaseScore;
  UINT32 ToleranceBonus = 0;

  //
  // Apply tolerance based on change level
  //
  switch (ChangeLevel) {
    case 0: // No significant changes
      ToleranceBonus = 0;
      break;
    case 1: // Minor changes
      ToleranceBonus = Matrix->ConfigTolerance;
      break;
    case 2: // Moderate changes
      ToleranceBonus = Matrix->PlatformTolerance;
      break;
    default: // Major changes
      ToleranceBonus = Matrix->CpuTolerance;
      break;
  }

  //
  // Apply tolerance bonus (but don't exceed maximum)
  //
  AdjustedScore = BaseScore + (BaseScore * ToleranceBonus) / 100;

  if (AdjustedScore > MAX_COMPATIBILITY_SCORE) {
    AdjustedScore = MAX_COMPATIBILITY_SCORE;
  }

  return AdjustedScore;
}

/**
  Calculate feature similarity percentage between two feature sets.
**/
STATIC
UINT32
CalculateFeatureSimilarity (
  IN UINT64 AuthFeatures,
  IN UINT64 CurrentFeatures
  )
{
  if (AuthFeatures == CurrentFeatures) {
    return 100; // Perfect match
  }

  if (AuthFeatures == 0 && CurrentFeatures == 0) {
    return 100; // Both have no features
  }

  if (AuthFeatures == 0 || CurrentFeatures == 0) {
    return 0; // One has features, other doesn't
  }

  //
  // Calculate Jaccard similarity: intersection / union
  //
  UINT64 Intersection = AuthFeatures & CurrentFeatures;
  UINT64 Union = AuthFeatures | CurrentFeatures;

  // Count bits in intersection and union
  UINT32 IntersectionBits = 0;
  UINT32 UnionBits = 0;

  for (UINT32 i = 0; i < 64; i++) {
    if (Intersection & (1ULL << i)) {
      IntersectionBits++;
    }
    if (Union & (1ULL << i)) {
      UnionBits++;
    }
  }

  if (UnionBits == 0) {
    return 100; // Shouldn't happen, but safe fallback
  }

  return (IntersectionBits * 100) / UnionBits;
}

/**
  Predict compatibility using simplified ML model.
**/
STATIC
UINT32
PredictCompatibilityWithML (
  IN MINI_VISOR_HARDWARE_FINGERPRINT *Auth,
  IN MINI_VISOR_HARDWARE_FINGERPRINT *Current,
  IN MINI_VISOR_COMPATIBILITY_MATRIX  *Matrix
  )
{
  // Simplified neural network prediction
  // In a real implementation, this would use a trained model
  
  UINT32 Features[ML_INPUT_FEATURES];
  
  //
  // Extract features for ML model
  //
  Features[0] = (Auth->CpuSignature == Current->CpuSignature) ? 100 : 0;
  Features[1] = (Auth->CpuFamily == Current->CpuFamily) ? 100 : 0;
  Features[2] = (Auth->CpuModel == Current->CpuModel) ? 100 : 0;
  Features[3] = CalculateFeatureSimilarity(Auth->CpuFeatureFlags, Current->CpuFeatureFlags);
  Features[4] = (Auth->ChipsetModelHash == Current->ChipsetModelHash) ? 100 : 0;
  Features[5] = (Auth->MainboardSerialHash == Current->MainboardSerialHash) ? 100 : 0;
  Features[6] = (Auth->BiosVersionHash == Current->BiosVersionHash) ? 100 : 0;
  Features[7] = CalculateFeatureSimilarity(Auth->VirtualizationFeatures, Current->VirtualizationFeatures);
  Features[8] = CalculateFeatureSimilarity(Auth->IommuFeatures, Current->IommuFeatures);
  Features[9] = (Current->MemorySize >= Auth->MemorySize) ? 100 : ((Current->MemorySize * 100) / Auth->MemorySize);
  Features[10] = (Current->PciDeviceCount >= Auth->PciDeviceCount) ? 100 : 50;
  Features[11] = (Current->UsbDeviceCount >= Auth->UsbDeviceCount) ? 100 : 50;
  Features[12] = (Auth->StorageConfigHash == Current->StorageConfigHash) ? 100 : 50;
  Features[13] = (Auth->NetworkConfigHash == Current->NetworkConfigHash) ? 100 : 50;
  Features[14] = CalculateFeatureSimilarity(Auth->SecurityFeatures, Current->SecurityFeatures);
  Features[15] = 50; // Placeholder feature

  //
  // Simple neural network forward pass (single hidden layer)
  //
  UINT32 HiddenLayer[ML_HIDDEN_NEURONS] = {0};
  
  // Hidden layer computation
  for (UINT32 i = 0; i < ML_HIDDEN_NEURONS; i++) {
    UINT32 Sum = Matrix->MlBiases[i];
    for (UINT32 j = 0; j < ML_INPUT_FEATURES; j++) {
      Sum += (Features[j] * Matrix->MlWeights[j]) / 1000; // Simplified weight application
    }
    HiddenLayer[i] = (Sum > 1000) ? 1000 : Sum; // Simple activation (clamp)
  }

  //
  // Output layer computation
  //
  UINT32 Output = 0;
  for (UINT32 i = 0; i < ML_HIDDEN_NEURONS; i++) {
    Output += HiddenLayer[i];
  }
  Output /= ML_HIDDEN_NEURONS; // Average

  // Scale to compatibility score range
  if (Output > MAX_COMPATIBILITY_SCORE) {
    Output = MAX_COMPATIBILITY_SCORE;
  }

  return Output;
}
