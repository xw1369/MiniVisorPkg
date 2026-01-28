/** @file
  MiniVisor Advanced Anti-Detection Library Header
  
  This file defines the enterprise-grade anti-detection capabilities including
  advanced hypervisor concealment, timing attack protection, and behavioral
  pattern masking.
  
  Copyright (c) 2024, MiniVisor Project. All rights reserved.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef __MINI_VISOR_ANTI_DETECTION_H__
#define __MINI_VISOR_ANTI_DETECTION_H__

#include <Uefi.h>

//
// Anti-Detection Levels
//
#define ANTI_DETECTION_LEVEL_BASIC     1
#define ANTI_DETECTION_LEVEL_ADVANCED  2
#define ANTI_DETECTION_LEVEL_ENTERPRISE 3

//
// Anti-Detection Context Structure
//
typedef struct {
  UINT32  Signature;
  UINTN   Level;
  BOOLEAN Initialized;
  
  // Statistics
  UINT32  TimingProtectionCount;
  UINT32  BehavioralMaskingCount;
  UINT32  MemoryObfuscationCount;
  UINT32  AnalysisAttemptsDetected;
  UINT32  CountermeasuresApplied;
  
  // Configuration
  BOOLEAN TimingProtectionEnabled;
  BOOLEAN BehavioralMaskingEnabled;
  BOOLEAN MemoryObfuscationEnabled;
  BOOLEAN AnalysisDetectionEnabled;
  
  // State tracking
  UINT64  LastUpdateTime;
  UINT32  CurrentState;
  UINT32  PatternIndex;
} ANTI_DETECTION_CONTEXT;

// Compatibility typedef for existing code
typedef ANTI_DETECTION_CONTEXT STEALTH_CONTEXT;

//
// Anti-Detection Statistics Structure
//
typedef struct {
  UINT32  TimingProtectionCount;
  UINT32  BehavioralMaskingCount;
  UINT32  MemoryObfuscationCount;
  UINT32  AnalysisAttemptsDetected;
  UINT32  CountermeasuresApplied;
  UINT64  TotalExecutionTime;
} ANTI_DETECTION_STATS;

//
// Configuration Structures
//
typedef struct {
  UINT32  Signature;
  BOOLEAN Enabled;
  UINT32  SpoofingLevel;
  BOOLEAN SpoofiingEnabled;
  BOOLEAN HideVmxSupport;
  BOOLEAN HideHypervisor;
  UINT32  Reserved[2];
} CPUID_SPOOFING_CONFIG;

typedef struct {
  UINT32  Signature;
  BOOLEAN Enabled;
  UINT32  ObfuscationLevel;
  BOOLEAN EnableTimeJitter;
  UINT32  JitterRange;
  BOOLEAN FakeRdtsc;
  UINT32  Reserved[2];
} TIMING_OBFUSCATION_CONFIG;

typedef struct {
  UINT32  Signature;
  BOOLEAN Enabled;
  UINT32  MaskingLevel;
  BOOLEAN MaskMemoryLayout;
  BOOLEAN HideRegisters;
  BOOLEAN MaskCacheTimings;
  UINT32  Reserved[2];
} BEHAVIORAL_MASKING_CONFIG;

typedef struct {
  UINT32  Signature;
  UINT32  Version;
  UINT32  Reserved[6];
} STEALTH_SIGNATURE;

//
// Function Prototypes
//

/**
  Initialize advanced anti-detection system.
  
  @param[out] StealthCtx   Anti-detection context.
  @param[in] Level         Anti-detection level.
  
  @retval EFI_SUCCESS      Initialization successful.
  @retval Others           Initialization failed.
**/
EFI_STATUS
EFIAPI
InitializeAntiDetection (
  OUT ANTI_DETECTION_CONTEXT **StealthCtx,
  IN UINTN Level
  );

/**
  Apply advanced timing protection.
  
  @param[in] Context       Anti-detection context.
  
  @retval EFI_SUCCESS      Timing protection applied.
**/
EFI_STATUS
EFIAPI
ApplyTimingProtection (
  IN ANTI_DETECTION_CONTEXT *Context
  );

/**
  Apply behavioral pattern masking.
  
  @param[in] Context       Anti-detection context.
  
  @retval EFI_SUCCESS      Behavioral masking applied.
**/

/**
  Configure CPUID spoofing.
  
  @param[in] StealthCtx    Anti-detection context.
  @param[in] Config        CPUID spoofing configuration.
  
  @retval EFI_SUCCESS      Configuration applied.
**/
EFI_STATUS
EFIAPI
ConfigureCpuidSpoofing (
  IN ANTI_DETECTION_CONTEXT *StealthCtx,
  IN CPUID_SPOOFING_CONFIG *Config
  );

/**
  Configure timing obfuscation.
  
  @param[in] StealthCtx    Anti-detection context.
  @param[in] Config        Timing obfuscation configuration.
  
  @retval EFI_SUCCESS      Configuration applied.
**/
EFI_STATUS
EFIAPI
ConfigureTimingObfuscation (
  IN ANTI_DETECTION_CONTEXT *StealthCtx,
  IN TIMING_OBFUSCATION_CONFIG *Config
  );

/**
  Configure behavioral masking.
  
  @param[in] StealthCtx    Anti-detection context.
  @param[in] Config        Behavioral masking configuration.
  
  @retval EFI_SUCCESS      Configuration applied.
**/
EFI_STATUS
EFIAPI
ConfigureBehavioralMasking (
  IN ANTI_DETECTION_CONTEXT *StealthCtx,
  IN BEHAVIORAL_MASKING_CONFIG *Config
  );

/**
  Apply behavioral pattern masking.
  
  @param[in] Context       Anti-detection context.
  
  @retval EFI_SUCCESS      Behavioral masking applied.
**/
EFI_STATUS
EFIAPI
ApplyBehavioralMasking (
  IN ANTI_DETECTION_CONTEXT *Context
  );

/**
  Destroy anti-detection context.
  
  @param[in] StealthCtx    Anti-detection context to destroy.
  
  @retval EFI_SUCCESS      Context destroyed successfully.
**/
EFI_STATUS
EFIAPI
DestroyStealthContext (
  IN ANTI_DETECTION_CONTEXT *StealthCtx
  );

/**
  Apply memory layout obfuscation.
  
  @param[in] Context       Anti-detection context.
  
  @retval EFI_SUCCESS      Memory obfuscation applied.
**/
EFI_STATUS
EFIAPI
ApplyMemoryObfuscation (
  IN ANTI_DETECTION_CONTEXT *Context
  );

/**
  Advanced CPUID spoofing with multi-strategy approach.
  
  @param[in] Function      CPUID function.
  @param[in] SubFunction   CPUID sub-function.
  @param[in,out] Eax       EAX register.
  @param[in,out] Ebx       EBX register.
  @param[in,out] Ecx       ECX register.
  @param[in,out] Edx       EDX register.
  
  @retval EFI_SUCCESS      CPUID spoofing applied.
**/
EFI_STATUS
EFIAPI
AdvancedCpuidSpoofing (
  IN UINT32 Function,
  IN UINT32 SubFunction,
  IN OUT UINT32 *Eax,
  IN OUT UINT32 *Ebx,
  IN OUT UINT32 *Ecx,
  IN OUT UINT32 *Edx
  );

/**
  Advanced MSR spoofing with comprehensive coverage.
  
  @param[in] MsrNumber     MSR number.
  @param[in] IsWrite       TRUE for write operation.
  @param[in,out] MsrValue  MSR value.
  
  @retval EFI_SUCCESS      MSR spoofing applied.
**/
EFI_STATUS
EFIAPI
AdvancedMsrSpoofing (
  IN UINT32 MsrNumber,
  IN BOOLEAN IsWrite,
  IN OUT UINT64 *MsrValue
  );

/**
  Advanced RDTSC/RDTSCP spoofing with timing attack protection.
  
  @param[in,out] TscValue  TSC value.
  @param[in,out] AuxValue  Auxiliary value (for RDTSCP).
  
  @retval EFI_SUCCESS      TSC spoofing applied.
**/
EFI_STATUS
EFIAPI
AdvancedTscSpoofing (
  IN OUT UINT64 *TscValue,
  IN OUT UINT32 *AuxValue OPTIONAL
  );

/**
  Detect and respond to analysis attempts.
  
  @param[in] Context       Anti-detection context.
  
  @retval BOOLEAN          TRUE if analysis detected.
**/
BOOLEAN
EFIAPI
DetectAnalysisAttempt (
  IN ANTI_DETECTION_CONTEXT *Context
  );

/**
  Apply comprehensive anti-detection measures.
  
  @param[in] Context       Anti-detection context.
  
  @retval EFI_SUCCESS      Anti-detection measures applied.
**/
EFI_STATUS
EFIAPI
ApplyComprehensiveAntiDetection (
  IN ANTI_DETECTION_CONTEXT *Context
  );

/**
  Get anti-detection statistics.
  
  @param[out] Stats        Anti-detection statistics.
  
  @retval EFI_SUCCESS      Statistics retrieved.
**/
EFI_STATUS
EFIAPI
GetAntiDetectionStats (
  OUT ANTI_DETECTION_STATS *Stats
  );

#endif // __MINI_VISOR_ANTI_DETECTION_H__