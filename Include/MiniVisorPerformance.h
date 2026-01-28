/** @file
  MiniVisor Performance Optimization Framework
  
  High-performance utilities for VM exit handling, memory management,
  cache optimization, and low-latency operations.
  
  Copyright (c) 2024, MiniVisor Project. All rights reserved.
  @license BSD-2-Clause-Patent
**/

#ifndef __MINI_VISOR_PERFORMANCE_H__
#define __MINI_VISOR_PERFORMANCE_H__

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/TimerLib.h>

// Compiler-specific includes
#if defined(_MSC_VER)
  #include <intrin.h>    // For MSVC intrinsics
  #include <xmmintrin.h> // For _mm_prefetch
#endif

//
// Performance Framework Version
//
#define PERFORMANCE_FRAMEWORK_VERSION    0x00010000
#define PERFORMANCE_SIGNATURE            SIGNATURE_32('P','E','R','F')

//
// Performance Optimization Levels
//
typedef enum {
  PerfLevelNone         = 0,
  PerfLevelBasic        = 1,
  PerfLevelStandard     = 2,
  PerfLevelAggressive   = 3,
  PerfLevelMaximum      = 4
} PERFORMANCE_LEVEL;

//
// VM Exit Types for Optimization
//
typedef enum {
  VmExitCpuid           = 10,
  VmExitRdtsc           = 16,
  VmExitCrAccess        = 28,
  VmExitMsrRead         = 31,
  VmExitMsrWrite        = 32,
  VmExitEptViolation    = 48,
  VmExitEptMisconfig    = 49
} VM_EXIT_TYPE;

//
// Cache Optimization Configuration
//
typedef struct {
  UINT32    Signature;          // Configuration signature
  BOOLEAN   EnablePrefetching;  // Enable data prefetching
  UINT32    PrefetchDistance;   // Prefetch distance in cache lines
  BOOLEAN   OptimizeLayout;     // Optimize data structure layout
  BOOLEAN   MinimizeFootprint;  // Minimize memory footprint
  UINT32    CacheLineSize;      // Target cache line size
  BOOLEAN   AlignCriticalData;  // Align critical data structures
} CACHE_OPTIMIZATION_CONFIG;

//
// Memory Pool Configuration
//
typedef struct {
  UINT32    Signature;          // Pool signature
  UINTN     PoolSize;           // Total pool size
  UINTN     BlockSize;          // Fixed block size
  UINTN     Alignment;          // Memory alignment requirement
  BOOLEAN   PreAllocate;        // Pre-allocate all blocks
  BOOLEAN   ZeroOnFree;         // Zero memory on free
  UINT32    MaxBlocks;          // Maximum number of blocks
} MEMORY_POOL_CONFIG;

//
// Fast Memory Pool
//
typedef struct {
  UINT32    Signature;          // Pool signature
  UINT32    Version;            // Pool version
  VOID      **FreeList;         // Free block list
  UINT8     *PoolMemory;        // Pool memory base
  UINTN     TotalBlocks;        // Total number of blocks
  UINTN     FreeBlocks;         // Number of free blocks
  UINTN     BlockSize;          // Size of each block
  UINTN     Alignment;          // Block alignment
  UINT64    AllocCount;         // Allocation counter
  UINT64    FreeCount;          // Free counter
  BOOLEAN   Initialized;        // Pool initialization status
} FAST_MEMORY_POOL;

//
// VM Exit Performance Profile
//
typedef struct {
  VM_EXIT_TYPE  ExitType;       // Type of VM exit
  UINT64        MinCycles;      // Minimum cycles for this exit
  UINT64        MaxCycles;      // Maximum cycles for this exit
  UINT64        AvgCycles;      // Average cycles for this exit
  UINT64        TotalExits;     // Total number of exits
  UINT64        TotalCycles;    // Total cycles spent
  BOOLEAN       FastPathEnabled;// Fast path optimization enabled
  VOID          *FastHandler;   // Fast path handler function
} VM_EXIT_PERFORMANCE_PROFILE;

//
// Performance Metrics
//
typedef struct {
  UINT32    Signature;          // Metrics signature
  UINT64    TotalVmExits;       // Total VM exits
  UINT64    FastPathHits;       // Fast path hits
  UINT64    SlowPathHits;       // Slow path hits
  UINT64    CacheHits;          // Cache hits
  UINT64    CacheMisses;        // Cache misses
  UINT64    MemoryAllocations;  // Memory allocations
  UINT64    MemoryDeallocations;// Memory deallocations
  UINT64    AverageExitLatency; // Average exit latency (cycles)
  UINT64    PeakExitLatency;    // Peak exit latency (cycles)
  UINT32    PerformanceScore;   // Overall performance score
} PERFORMANCE_METRICS;

//
// Performance Context
//
typedef struct {
  UINT32                        Signature;      // Context signature
  UINT32                        Version;        // Context version
  PERFORMANCE_LEVEL             OptLevel;       // Optimization level
  CACHE_OPTIMIZATION_CONFIG     CacheConfig;    // Cache optimization config
  FAST_MEMORY_POOL              MemoryPool;     // Fast memory pool
  VM_EXIT_PERFORMANCE_PROFILE   ExitProfiles[64]; // VM exit profiles
  PERFORMANCE_METRICS           Metrics;        // Performance metrics
  UINT64                        StartTime;      // Framework start time
  BOOLEAN                       ProfilingEnabled; // Performance profiling
  UINT32                        IntegrityCheck; // Context integrity
} PERFORMANCE_CONTEXT;

//
// Function Prototypes
//

/**
  Initialize performance optimization framework.
  
  @param[out] PerfContext       Performance context to initialize
  @param[in]  OptLevel          Desired optimization level
  
  @retval EFI_SUCCESS           Framework initialized successfully
  @retval EFI_INVALID_PARAMETER Invalid optimization level
  @retval EFI_OUT_OF_RESOURCES  Insufficient resources
**/
EFI_STATUS
EFIAPI
InitializePerformanceFramework (
  OUT PERFORMANCE_CONTEXT  **PerfContext,
  IN  PERFORMANCE_LEVEL    OptLevel
  );

/**
  Initialize fast memory pool for high-frequency allocations.
  
  @param[out] MemoryPool        Memory pool to initialize
  @param[in]  PoolConfig        Pool configuration
  
  @retval EFI_SUCCESS           Pool initialized successfully
  @retval EFI_INVALID_PARAMETER Invalid configuration
  @retval EFI_OUT_OF_RESOURCES  Insufficient memory
**/
EFI_STATUS
EFIAPI
InitializeFastMemoryPool (
  OUT FAST_MEMORY_POOL      *MemoryPool,
  IN  MEMORY_POOL_CONFIG    *PoolConfig
  );

/**
  Allocate block from fast memory pool.
  
  @param[in]  MemoryPool        Memory pool
  @param[out] Block             Allocated memory block
  
  @retval EFI_SUCCESS           Block allocated successfully
  @retval EFI_INVALID_PARAMETER Invalid pool
  @retval EFI_OUT_OF_RESOURCES  No free blocks available
**/
EFI_STATUS
EFIAPI
FastPoolAllocate (
  IN  FAST_MEMORY_POOL  *MemoryPool,
  OUT VOID              **Block
  );

/**
  Free block back to fast memory pool.
  
  @param[in] MemoryPool         Memory pool
  @param[in] Block              Memory block to free
  
  @retval EFI_SUCCESS           Block freed successfully
  @retval EFI_INVALID_PARAMETER Invalid parameters
**/
EFI_STATUS
EFIAPI
FastPoolFree (
  IN FAST_MEMORY_POOL  *MemoryPool,
  IN VOID              *Block
  );

/**
  Optimize VM exit handler for specific exit type.
  
  @param[in] PerfContext        Performance context
  @param[in] ExitType           VM exit type to optimize
  @param[in] FastHandler        Fast path handler function
  
  @retval EFI_SUCCESS           Handler optimized successfully
  @retval EFI_INVALID_PARAMETER Invalid parameters
**/
EFI_STATUS
EFIAPI
OptimizeVmExitHandler (
  IN PERFORMANCE_CONTEXT  *PerfContext,
  IN VM_EXIT_TYPE         ExitType,
  IN VOID                 *FastHandler
  );

/**
  Record VM exit performance data for analysis.
  
  @param[in] PerfContext        Performance context
  @param[in] ExitType           VM exit type
  @param[in] StartCycles        Start cycle count
  @param[in] EndCycles          End cycle count
  
  @retval EFI_SUCCESS           Performance data recorded
  @retval EFI_INVALID_PARAMETER Invalid parameters
**/
EFI_STATUS
EFIAPI
RecordVmExitPerformance (
  IN PERFORMANCE_CONTEXT  *PerfContext,
  IN VM_EXIT_TYPE         ExitType,
  IN UINT64               StartCycles,
  IN UINT64               EndCycles
  );

/**
  Configure cache optimization settings.
  
  @param[in] PerfContext        Performance context
  @param[in] CacheConfig        Cache optimization configuration
  
  @retval EFI_SUCCESS           Cache optimization configured
  @retval EFI_INVALID_PARAMETER Invalid configuration
**/
EFI_STATUS
EFIAPI
ConfigureCacheOptimization (
  IN PERFORMANCE_CONTEXT        *PerfContext,
  IN CACHE_OPTIMIZATION_CONFIG  *CacheConfig
  );

/**
  Perform cache-friendly data structure alignment.
  
  @param[in] DataStructure      Data structure to align
  @param[in] StructureSize      Size of data structure
  @param[in] CacheLineSize      Target cache line size
  
  @retval AlignedPointer        Cache-aligned pointer
**/
VOID *
EFIAPI
AlignToCacheLine (
  IN VOID   *DataStructure,
  IN UINTN  StructureSize,
  IN UINTN  CacheLineSize
  );

/**
  Prefetch memory for upcoming access patterns.
  
  @param[in] Address            Memory address to prefetch
  @param[in] Size               Size of memory region
  @param[in] AccessPattern      Expected access pattern
  
  @retval EFI_SUCCESS           Prefetch initiated successfully
  @retval EFI_INVALID_PARAMETER Invalid parameters
**/
EFI_STATUS
EFIAPI
PrefetchMemory (
  IN VOID   *Address,
  IN UINTN  Size,
  IN UINT32 AccessPattern
  );

/**
  Get current performance metrics.
  
  @param[in]  PerfContext       Performance context
  @param[out] Metrics           Current performance metrics
  
  @retval EFI_SUCCESS           Metrics retrieved successfully
  @retval EFI_INVALID_PARAMETER Invalid parameters
**/
EFI_STATUS
EFIAPI
GetPerformanceMetrics (
  IN  PERFORMANCE_CONTEXT  *PerfContext,
  OUT PERFORMANCE_METRICS  *Metrics
  );

/**
  Analyze and optimize performance based on collected data.
  
  @param[in] PerfContext        Performance context
  
  @retval EFI_SUCCESS           Analysis completed successfully
  @retval EFI_INVALID_PARAMETER Invalid context
**/
EFI_STATUS
EFIAPI
AnalyzeAndOptimizePerformance (
  IN PERFORMANCE_CONTEXT  *PerfContext
  );

/**
  Destroy performance context and cleanup resources.
  
  @param[in] PerfContext        Performance context to destroy
  
  @retval EFI_SUCCESS           Context destroyed successfully
  @retval EFI_INVALID_PARAMETER Invalid context
**/
EFI_STATUS
EFIAPI
DestroyPerformanceContext (
  IN PERFORMANCE_CONTEXT  *PerfContext
  );

//
// High-Performance Utility Macros
//

/**
  Fast cycle counter reading with minimal overhead.
**/
#define READ_PERFORMANCE_COUNTER() AsmReadTsc()

/**
  Cache line prefetch hint.
**/
#if defined(__GNUC__) || defined(__clang__)
  #define PREFETCH_FOR_READ(Address) \
    __builtin_prefetch((Address), 0, 3)
  #define PREFETCH_FOR_WRITE(Address) \
    __builtin_prefetch((Address), 1, 3)
#elif defined(_MSC_VER)
  #define PREFETCH_FOR_READ(Address) \
    _mm_prefetch((const char*)(Address), _MM_HINT_T0)
  #define PREFETCH_FOR_WRITE(Address) \
    _mm_prefetch((const char*)(Address), _MM_HINT_T0)
#else
  // Fallback: no-op for unsupported compilers
  #define PREFETCH_FOR_READ(Address)  ((void)0)
  #define PREFETCH_FOR_WRITE(Address) ((void)0)
#endif

/**
  Likely/unlikely branch prediction hints.
**/
#if defined(__GNUC__) || defined(__clang__)
  #define LIKELY(x)   __builtin_expect(!!(x), 1)
  #define UNLIKELY(x) __builtin_expect(!!(x), 0)
#else
  // Fallback: no-op for compilers without __builtin_expect
  #define LIKELY(x)   (x)
  #define UNLIKELY(x) (x)
#endif

/**
  Fast VM exit timing measurement.
**/
#define MEASURE_VM_EXIT_PERFORMANCE(Context, ExitType, Code) \
  do { \
    UINT64 __StartCycles = READ_PERFORMANCE_COUNTER(); \
    Code; \
    UINT64 __EndCycles = READ_PERFORMANCE_COUNTER(); \
    RecordVmExitPerformance((Context), (ExitType), __StartCycles, __EndCycles); \
  } while (0)

/**
  Memory barrier optimizations.
**/
#if defined(__GNUC__) || defined(__clang__)
  #define COMPILER_BARRIER()  __asm__ __volatile__("" ::: "memory")
#elif defined(_MSC_VER)
  #define COMPILER_BARRIER()  _ReadWriteBarrier()
#else
  #define COMPILER_BARRIER()  ((void)0)
#endif
#define MEMORY_BARRIER()    MemoryFence()

/**
  Cache-efficient structure padding.
**/
#if defined(__GNUC__) || defined(__clang__)
  #define CACHE_ALIGN         __attribute__((aligned(64)))
#elif defined(_MSC_VER)
  #define CACHE_ALIGN         __declspec(align(64))
#else
  #define CACHE_ALIGN         // No alignment support
#endif
#define CACHE_LINE_SIZE     64

/**
  Fast memory operations.
**/
#define FAST_ZERO_MEMORY(Dest, Size) \
  do { \
    if ((Size) <= 64) { \
      SetMem((Dest), (Size), 0); \
    } else { \
      ZeroMem((Dest), (Size)); \
    } \
  } while (0)

#define FAST_COPY_MEMORY(Dest, Src, Size) \
  do { \
    if ((Size) <= 64) { \
      CopyMem((Dest), (Src), (Size)); \
    } else { \
      PREFETCH_FOR_READ(Src); \
      PREFETCH_FOR_WRITE(Dest); \
      CopyMem((Dest), (Src), (Size)); \
    } \
  } while (0)

//
// Access Pattern Types for Prefetching
//
#define ACCESS_PATTERN_SEQUENTIAL    0x01
#define ACCESS_PATTERN_RANDOM        0x02
#define ACCESS_PATTERN_STRIDED       0x03
#define ACCESS_PATTERN_TEMPORAL      0x04

//
// Performance Optimization Flags
//
#define PERF_FLAG_ENABLE_FAST_PATH   BIT0
#define PERF_FLAG_CACHE_OPTIMIZE     BIT1
#define PERF_FLAG_PREFETCH_ENABLE    BIT2
#define PERF_FLAG_ALIGN_DATA         BIT3
#define PERF_FLAG_MINIMIZE_FOOTPRINT BIT4
#define PERF_FLAG_PROFILE_ENABLED    BIT5

//
// Cache Optimization Hints
//
#define CACHE_HINT_TEMPORAL          0x01
#define CACHE_HINT_NON_TEMPORAL      0x02
#define CACHE_HINT_STREAMING         0x03

#endif // __MINI_VISOR_PERFORMANCE_H__
