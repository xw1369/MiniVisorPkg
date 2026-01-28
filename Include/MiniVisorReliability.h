/** @file
  MiniVisor Reliability and Fault Tolerance Framework
  
  Comprehensive reliability mechanisms including fault detection,
  automatic recovery, state consistency, and system health monitoring.
  
  Copyright (c) 2024, MiniVisor Project. All rights reserved.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef __MINI_VISOR_RELIABILITY_H__
#define __MINI_VISOR_RELIABILITY_H__

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/TimerLib.h>

//
// String conversion macros
//
#define _STRINGIFY(x) #x
#define STRINGIFY(x) _STRINGIFY(x)

//
// Reliability Framework Version
//
#define RELIABILITY_FRAMEWORK_VERSION    0x00010000
#define RELIABILITY_SIGNATURE            SIGNATURE_32('R','E','L','I')

//
// Fault Types and Severity Levels
//
typedef enum {
  FaultSeverityNone        = 0,
  FaultSeverityInfo        = 1,
  FaultSeverityWarning     = 2,
  FaultSeverityError       = 3,
  FaultSeverityCritical    = 4,
  FaultSeverityFatal       = 5
} FAULT_SEVERITY;

typedef enum {
  FaultTypeNone            = 0,
  FaultTypeMemory          = 1,
  FaultTypeConcurrency     = 2,
  FaultTypeHardware        = 3,
  FaultTypeSecurity        = 4,
  FaultTypePerformance     = 5,
  FaultTypeConfiguration   = 6,
  FaultTypeProtocol        = 7
} FAULT_TYPE;

//
// Recovery Strategies
//
typedef enum {
  RecoveryStrategyNone     = 0,
  RecoveryStrategyRetry    = 1,
  RecoveryStrategyFallback = 2,
  RecoveryStrategyRestart  = 3,
  RecoveryStrategyIsolate  = 4,
  RecoveryStrategyShutdown = 5
} RECOVERY_STRATEGY;

//
// System Health Status
//
typedef enum {
  HealthStatusUnknown      = 0,
  HealthStatusHealthy      = 1,
  HealthStatusDegraded     = 2,
  HealthStatusUnstable     = 3,
  HealthStatusCritical     = 4,
  HealthStatusFailed       = 5
} SYSTEM_HEALTH_STATUS;

//
// Fault Record Structure
//
typedef struct {
  UINT32            Signature;        // Fault record signature
  UINT32            FaultId;          // Unique fault identifier
  FAULT_TYPE        FaultType;        // Type of fault
  FAULT_SEVERITY    Severity;         // Fault severity level
  UINT64            Timestamp;        // When fault occurred
  CHAR8             Description[128]; // Fault description
  CHAR8             Location[64];     // Source location (__FILE__:__LINE__)
  UINT32            ErrorCode;        // Associated error code
  UINTN             Context[4];       // Additional context data
  RECOVERY_STRATEGY RecoveryAction;   // Recommended recovery action
  UINT32            RecoveryAttempts; // Number of recovery attempts
  BOOLEAN           Resolved;         // Whether fault was resolved
  UINT64            ResolvedTime;     // When fault was resolved
} FAULT_RECORD;

//
// Health Monitor Configuration
//
typedef struct {
  UINT32    Signature;              // Configuration signature
  BOOLEAN   EnableHealthMonitoring; // Enable health monitoring
  UINT32    MonitoringInterval;     // Monitoring interval in milliseconds
  UINT32    HealthCheckTimeout;     // Health check timeout
  UINT32    MaxFaultHistory;        // Maximum fault records to keep
  BOOLEAN   AutoRecoveryEnabled;    // Enable automatic recovery
  UINT32    RecoveryThreshold;      // Fault count before recovery
  BOOLEAN   FailsafeMode;           // Enable failsafe mode
} HEALTH_MONITOR_CONFIG;

//
// System Health Metrics
//
typedef struct {
  UINT32                Signature;        // Metrics signature
  UINT64                LastHealthCheck;  // Last health check timestamp
  SYSTEM_HEALTH_STATUS  CurrentStatus;    // Current system health status
  UINT32                TotalFaults;      // Total fault count
  UINT32                CriticalFaults;   // Critical fault count
  UINT32                SuccessfulRecoveries; // Successful recovery count
  UINT32                FailedRecoveries; // Failed recovery count
  UINT64                UptimeSeconds;    // System uptime in seconds
  UINT32                MemoryLeaks;      // Detected memory leaks
  UINT32                ConcurrencyIssues; // Concurrency problems
  UINT32                SecurityViolations; // Security violations
  UINT64                PerformanceScore; // Overall performance score
} SYSTEM_HEALTH_METRICS;

//
// Reliability Context
//
typedef struct {
  UINT32                  Signature;        // Context signature
  UINT32                  Version;          // Context version
  HEALTH_MONITOR_CONFIG   Config;           // Health monitor configuration
  SYSTEM_HEALTH_METRICS   Metrics;          // Current health metrics
  FAULT_RECORD            *FaultHistory;    // Fault history array
  UINT32                  FaultHistorySize; // Size of fault history
  UINT32                  FaultCount;       // Current fault count
  UINT64                  InitializationTime; // Framework initialization time
  BOOLEAN                 MonitoringActive; // Whether monitoring is active
  UINT32                  IntegrityCheck;   // Context integrity checksum
} RELIABILITY_CONTEXT;

//
// Recovery Action Descriptor
//
typedef struct {
  UINT32            Signature;        // Action signature
  RECOVERY_STRATEGY Strategy;         // Recovery strategy
  CHAR8             ActionName[32];   // Action name
  EFI_STATUS        (*RecoveryFunc)(VOID *Context); // Recovery function
  VOID              *ActionContext;   // Action-specific context
  UINT32            MaxAttempts;      // Maximum retry attempts
  UINT32            DelayBetweenAttempts; // Delay between attempts (ms)
  BOOLEAN           CriticalAction;   // Whether action is critical
} RECOVERY_ACTION_DESCRIPTOR;

//
// Function Prototypes
//

/**
  Initialize reliability framework with health monitoring.
  
  @param[out] ReliabilityContext Reliability context to initialize
  @param[in]  Config             Health monitor configuration
  
  @retval EFI_SUCCESS           Framework initialized successfully
  @retval EFI_INVALID_PARAMETER Invalid parameters
  @retval EFI_OUT_OF_RESOURCES  Insufficient resources
**/
EFI_STATUS
EFIAPI
InitializeReliabilityFramework (
  OUT RELIABILITY_CONTEXT      **ReliabilityContext,
  IN  HEALTH_MONITOR_CONFIG    *Config
  );

/**
  Record a fault in the system for tracking and analysis.
  
  @param[in] Context            Reliability context
  @param[in] FaultType          Type of fault
  @param[in] Severity           Fault severity
  @param[in] Description        Fault description
  @param[in] Location           Source location
  @param[in] ErrorCode          Associated error code
  
  @retval EFI_SUCCESS           Fault recorded successfully
  @retval EFI_INVALID_PARAMETER Invalid parameters
  @retval EFI_OUT_OF_RESOURCES  Fault history full
**/
EFI_STATUS
EFIAPI
RecordSystemFault (
  IN RELIABILITY_CONTEXT  *Context,
  IN FAULT_TYPE           FaultType,
  IN FAULT_SEVERITY       Severity,
  IN CHAR8                *Description,
  IN CHAR8                *Location,
  IN UINT32               ErrorCode
  );

/**
  Perform comprehensive system health check.
  
  @param[in] Context            Reliability context
  
  @retval EFI_SUCCESS           Health check completed
  @retval EFI_INVALID_PARAMETER Invalid context
  @retval EFI_DEVICE_ERROR      Health check failed
**/
EFI_STATUS
EFIAPI
PerformSystemHealthCheck (
  IN RELIABILITY_CONTEXT  *Context
  );

/**
  Attempt automatic recovery from detected faults.
  
  @param[in] Context            Reliability context
  @param[in] FaultRecord        Fault to recover from
  
  @retval EFI_SUCCESS           Recovery successful
  @retval EFI_INVALID_PARAMETER Invalid parameters
  @retval EFI_UNSUPPORTED       No recovery strategy available
  @retval EFI_DEVICE_ERROR      Recovery failed
**/
EFI_STATUS
EFIAPI
AttemptAutomaticRecovery (
  IN RELIABILITY_CONTEXT  *Context,
  IN FAULT_RECORD         *FaultRecord
  );

/**
  Validate system state consistency.
  
  @param[in] Context            Reliability context
  
  @retval EFI_SUCCESS           System state is consistent
  @retval EFI_INVALID_PARAMETER Invalid context
  @retval EFI_CRC_ERROR         State consistency violation
**/
EFI_STATUS
EFIAPI
ValidateSystemStateConsistency (
  IN RELIABILITY_CONTEXT  *Context
  );

/**
  Monitor system resources for potential issues.
  
  @param[in] Context            Reliability context
  
  @retval EFI_SUCCESS           Resource monitoring completed
  @retval EFI_INVALID_PARAMETER Invalid context
  @retval EFI_DEVICE_ERROR      Resource issues detected
**/
EFI_STATUS
EFIAPI
MonitorSystemResources (
  IN RELIABILITY_CONTEXT  *Context
  );

/**
  Register a custom recovery action for specific fault types.
  
  @param[in] Context            Reliability context
  @param[in] FaultType          Fault type to handle
  @param[in] RecoveryAction     Recovery action descriptor
  
  @retval EFI_SUCCESS           Recovery action registered
  @retval EFI_INVALID_PARAMETER Invalid parameters
  @retval EFI_OUT_OF_RESOURCES  No space for new actions
**/
EFI_STATUS
EFIAPI
RegisterRecoveryAction (
  IN RELIABILITY_CONTEXT         *Context,
  IN FAULT_TYPE                  FaultType,
  IN RECOVERY_ACTION_DESCRIPTOR  *RecoveryAction
  );

/**
  Get current system health status and metrics.
  
  @param[in]  Context           Reliability context
  @param[out] HealthStatus      Current health status
  @param[out] Metrics           Detailed health metrics
  
  @retval EFI_SUCCESS           Health information retrieved
  @retval EFI_INVALID_PARAMETER Invalid parameters
**/
EFI_STATUS
EFIAPI
GetSystemHealthStatus (
  IN  RELIABILITY_CONTEXT      *Context,
  OUT SYSTEM_HEALTH_STATUS     *HealthStatus,
  OUT SYSTEM_HEALTH_METRICS    *Metrics
  );

/**
  Enable or disable failsafe mode for critical situations.
  
  @param[in] Context            Reliability context
  @param[in] EnableFailsafe     Enable failsafe mode
  
  @retval EFI_SUCCESS           Failsafe mode updated
  @retval EFI_INVALID_PARAMETER Invalid context
**/
EFI_STATUS
EFIAPI
SetFailsafeMode (
  IN RELIABILITY_CONTEXT  *Context,
  IN BOOLEAN              EnableFailsafe
  );

/**
  Cleanup and destroy reliability context.
  
  @param[in] Context            Reliability context to destroy
  
  @retval EFI_SUCCESS           Context destroyed successfully
  @retval EFI_INVALID_PARAMETER Invalid context
**/
EFI_STATUS
EFIAPI
DestroyReliabilityContext (
  IN RELIABILITY_CONTEXT  *Context
  );

//
// Reliability Utility Macros
//

/**
  Record fault with automatic location tracking.
**/
#define RECORD_FAULT(Context, Type, Severity, Description, ErrorCode) \
  RecordSystemFault((Context), (Type), (Severity), (Description), \
                   __FILE__ ":" STRINGIFY(__LINE__), (ErrorCode))

/**
  Validate function parameters with fault recording.
**/
#define VALIDATE_PARAM_WITH_FAULT(Context, Param, Type) \
  do { \
    if ((Param) == NULL) { \
      RECORD_FAULT((Context), (Type), FaultSeverityError, \
                  "Null parameter validation failed", EFI_INVALID_PARAMETER); \
      return EFI_INVALID_PARAMETER; \
    } \
  } while (0)

/**
  Execute function with automatic fault handling.
**/
#define EXECUTE_WITH_FAULT_HANDLING(Context, Function, FaultType) \
  do { \
    EFI_STATUS __Status = (Function); \
    if (EFI_ERROR(__Status)) { \
      RECORD_FAULT((Context), (FaultType), FaultSeverityError, \
                  "Function execution failed", __Status); \
      return __Status; \
    } \
  } while (0)

/**
  Check system health before critical operations.
**/
#define CHECK_SYSTEM_HEALTH(Context) \
  do { \
    SYSTEM_HEALTH_STATUS __Health; \
    GetSystemHealthStatus((Context), &__Health, NULL); \
    if (__Health >= HealthStatusCritical) { \
      DEBUG((EFI_D_ERROR, "System health critical, aborting operation\n")); \
      return EFI_ABORTED; \
    } \
  } while (0)

/**
  Conditional failsafe activation.
**/
#define ACTIVATE_FAILSAFE_IF_NEEDED(Context, Condition) \
  do { \
    if (Condition) { \
      SetFailsafeMode((Context), TRUE); \
      DEBUG((EFI_D_ERROR, "Failsafe mode activated due to: %a\n", #Condition)); \
    } \
  } while (0)

//
// Health Check Types
//
#define HEALTH_CHECK_MEMORY             BIT0
#define HEALTH_CHECK_CONCURRENCY        BIT1
#define HEALTH_CHECK_SECURITY           BIT2
#define HEALTH_CHECK_PERFORMANCE        BIT3
#define HEALTH_CHECK_HARDWARE           BIT4
#define HEALTH_CHECK_CONFIGURATION      BIT5
#define HEALTH_CHECK_ALL                0xFFFFFFFF

//
// Fault Flags
//
#define FAULT_FLAG_AUTOMATIC_RECOVERY   BIT0
#define FAULT_FLAG_REQUIRES_RESTART     BIT1
#define FAULT_FLAG_SECURITY_CRITICAL    BIT2
#define FAULT_FLAG_PERFORMANCE_IMPACT   BIT3
#define FAULT_FLAG_USER_NOTIFICATION    BIT4

#endif // __MINI_VISOR_RELIABILITY_H__
