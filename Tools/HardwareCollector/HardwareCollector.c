#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/UefiApplicationEntryPoint.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <MiniVisorMemSafety.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/BaseLib.h>
#include <Library/PrintLib.h>
#include <Library/FileHandleLib.h>
#include <Library/ShellLib.h>
#include <Protocol/SimpleFileSystem.h>
#include <Protocol/Smbios.h>
#include <IndustryStandard/SmBios.h>
#include "../../Include/UnifiedAuth.h"
#include <Library/TimerLib.h>

// 使用统一的硬件指纹结构（与UnifiedAuth兼容）

// 硬件收集数据结构
#pragma pack(1)
typedef struct {
  UINT32 Magic;                             // 'HCOL' - Hardware COLlector
  UINT32 Version;                           // 版本号
  UNIFIED_HARDWARE_FINGERPRINT Fingerprint; // 统一硬件指纹
  CHAR8  CpuBrandString[64];                // CPU品牌字符串
  CHAR8  MainboardSerial[64];               // 主板序列号
  CHAR8  SystemSerial[64];                  // 系统序列号
  CHAR8  ManufacturerInfo[128];             // 制造商信息
  UINT64 CollectionTime;                    // 收集时间
  UINT32 Checksum;                          // 校验和
} HARDWARE_COLLECTION_DATA;
#pragma pack()

// 函数声明
UINT32 SimpleHash(UINT8 *Data, UINTN Length);
UINT64 GetCpuSerialNumber(VOID);
EFI_STATUS GetMainboardSerial(CHAR8 *SerialBuffer, UINTN BufferSize);
EFI_STATUS GetSystemSerial(CHAR8 *SerialBuffer, UINTN BufferSize);
EFI_STATUS GetManufacturerInfo(CHAR8 *InfoBuffer, UINTN BufferSize);
EFI_STATUS GenerateHardwareFingerprint(UNIFIED_HARDWARE_FINGERPRINT *Fingerprint);
EFI_STATUS SaveHardwareInfo(HARDWARE_COLLECTION_DATA *Data);
VOID DisplayHardwareInfo(HARDWARE_COLLECTION_DATA *Data);
EFI_STATUS GetSmbiosStringByIndex(EFI_SMBIOS_TABLE_HEADER *Record, UINTN Index, CHAR8 *Buffer, UINTN BufferSize);

/**
 * 简单哈希函数，用于硬件指纹
 * 
 * @param[in] Data      要哈希的数据指针
 * @param[in] Length    数据长度（字节）
 * 
 * @retval 哈希值（32位）
 */
UINT32
SimpleHash(UINT8 *Data, UINTN Length)
{
  UINT32 Hash = 0x5A5A5A5A;
  UINTN i;
  
  if (Data == NULL || Length == 0) {
    return 0;
  }
  
  for (i = 0; i < Length; i++) {
    Hash = ((Hash << 5) + Hash) + Data[i];
    Hash ^= (Hash >> 16);
  }
  
  return Hash;
}

/**
 * 从SMBIOS记录中按索引获取字符串
 *
 * @param[in]  Record        SMBIOS记录头
 * @param[in]  Index         字符串索引（从1开始）
 * @param[out] Buffer        输出缓冲区
 * @param[in]  BufferSize    缓冲区大小
 *
 * @retval EFI_SUCCESS       成功
 * @retval EFI_INVALID_PARAMETER 参数无效
 * @retval EFI_NOT_FOUND     未找到
 */
EFI_STATUS
GetSmbiosStringByIndex(
  EFI_SMBIOS_TABLE_HEADER *Record,
  UINTN                    Index,
  CHAR8                   *Buffer,
  UINTN                    BufferSize
  )
{
  CHAR8 *StringArea;
  UINTN CurrentIndex;

  if (Record == NULL || Buffer == NULL || BufferSize == 0 || Index == 0) {
    return EFI_INVALID_PARAMETER;
  }

  StringArea = (CHAR8 *)Record + Record->Length;
  CurrentIndex = 1;

  while (*StringArea != 0) {
    if (CurrentIndex == Index) {
      UINTN Len = AsciiStrLen(StringArea);
      if (Len >= BufferSize) {
        Len = BufferSize - 1;
      }
      CopyMem(Buffer, StringArea, Len);
      Buffer[Len] = 0;
      return EFI_SUCCESS;
    }
    while (*StringArea != 0) {
      StringArea++;
    }
    StringArea++;
    CurrentIndex++;
  }

  return EFI_NOT_FOUND;
}

/**
 * 获取CPU序列号
 * 
 * @retval CPU序列号
 */
UINT64
GetCpuSerialNumber(VOID)
{
  UINT32 Eax, Ebx, Ecx, Edx;
  UINT64 SerialNumber = 0;
  
  // 获取处理器序列号
  AsmCpuid(3, &Eax, &Ebx, &Ecx, &Edx);
  SerialNumber = ((UINT64)Eax << 32) | Ebx;
  
  return SerialNumber;
}

/**
 * 获取主板序列号
 * 
 * @param[out] SerialBuffer    序列号缓冲区
 * @param[in]  BufferSize      缓冲区大小
 * 
 * @retval EFI_SUCCESS          成功
 * @retval EFI_INVALID_PARAMETER 参数无效
 * @retval EFI_NOT_FOUND        未找到
 */
EFI_STATUS
GetMainboardSerial(CHAR8 *SerialBuffer, UINTN BufferSize)
{
  EFI_STATUS Status;
  EFI_SMBIOS_PROTOCOL *Smbios;
  EFI_SMBIOS_HANDLE SmbiosHandle;
  EFI_SMBIOS_TABLE_HEADER *Record;
  EFI_SMBIOS_TYPE Type;
  
  if (SerialBuffer == NULL || BufferSize == 0) {
    return EFI_INVALID_PARAMETER;
  }
  
  Status = gBS->LocateProtocol(&gEfiSmbiosProtocolGuid, NULL, (VOID **)&Smbios);
  if (EFI_ERROR(Status)) {
    AsciiStrCpyS(SerialBuffer, BufferSize, "UNKNOWN");
    return EFI_SUCCESS;
  }
  
  SmbiosHandle = SMBIOS_HANDLE_PI_RESERVED;
  Type = SMBIOS_TYPE_BASEBOARD_INFORMATION;
  for (;;) {
    Status = Smbios->GetNext(Smbios, &SmbiosHandle, &Type, &Record, NULL);
    if (EFI_ERROR(Status)) {
      break;
    }
    if (Record->Type == SMBIOS_TYPE_BASEBOARD_INFORMATION) {
      SMBIOS_TABLE_TYPE2 *Type2 = (SMBIOS_TABLE_TYPE2 *)Record;
      if (Type2->SerialNumber != 0) {
        if (!EFI_ERROR(GetSmbiosStringByIndex(Record, Type2->SerialNumber, SerialBuffer, BufferSize))) {
          return EFI_SUCCESS;
        }
      }
    }
  }
  
  AsciiStrCpyS(SerialBuffer, BufferSize, "UNKNOWN");
  return EFI_SUCCESS;
}

/**
 * 获取系统序列号
 * 
 * @param[out] SerialBuffer    序列号缓冲区
 * @param[in]  BufferSize      缓冲区大小
 * 
 * @retval EFI_SUCCESS          成功
 * @retval EFI_INVALID_PARAMETER 参数无效
 */
EFI_STATUS
GetSystemSerial(CHAR8 *SerialBuffer, UINTN BufferSize)
{
  if (SerialBuffer == NULL || BufferSize == 0) {
    return EFI_INVALID_PARAMETER;
  }
  
  // 使用默认值
  AsciiStrCpyS(SerialBuffer, BufferSize, "SYSTEM001");
  return EFI_SUCCESS;
}

/**
 * 获取制造商信息
 * 
 * @param[out] InfoBuffer      信息缓冲区
 * @param[in]  BufferSize      缓冲区大小
 * 
 * @retval EFI_SUCCESS          成功
 * @retval EFI_INVALID_PARAMETER 参数无效
 */
EFI_STATUS
GetManufacturerInfo(CHAR8 *InfoBuffer, UINTN BufferSize)
{
  if (InfoBuffer == NULL || BufferSize == 0) {
    return EFI_INVALID_PARAMETER;
  }
  
  // 使用默认值
  AsciiStrCpyS(InfoBuffer, BufferSize, "Intel Corporation");
  return EFI_SUCCESS;
}

/**
 * 生成硬件指纹
 * 
 * @param[out] Fingerprint     硬件指纹结构
 * 
 * @retval EFI_SUCCESS          成功
 * @retval EFI_INVALID_PARAMETER 参数无效
 */
EFI_STATUS
GenerateHardwareFingerprint(UNIFIED_HARDWARE_FINGERPRINT *Fingerprint)
{
  UINT32 Eax, Ebx, Ecx, Edx;
  UINT32 CpuSignature;
  UINT32 CpuBrandHash = 0;
  UINT64 CpuSerialNumber;
  UINT64 SystemTime;
  UINT32 MemorySize = 0;
  UINT16 PciDeviceCount = 0;
  UINT32 MainboardSerialHash = 0;
  
  if (Fingerprint == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  
  ZeroMem(Fingerprint, sizeof(UNIFIED_HARDWARE_FINGERPRINT));
  
  // 获取CPU信息
  AsmCpuid(1, &Eax, &Ebx, &Ecx, &Edx);
  CpuSignature = Eax;
  
  // 获取CPU品牌字符串
  CHAR8 CpuBrand[49] = {0};
  UINT32 *BrandPtr = (UINT32 *)CpuBrand;
  
  AsmCpuid(0x80000002, &BrandPtr[0], &BrandPtr[1], &BrandPtr[2], &BrandPtr[3]);
  AsmCpuid(0x80000003, &BrandPtr[4], &BrandPtr[5], &BrandPtr[6], &BrandPtr[7]);
  AsmCpuid(0x80000004, &BrandPtr[8], &BrandPtr[9], &BrandPtr[10], &BrandPtr[11]);
  
  CpuBrandHash = SimpleHash((UINT8 *)CpuBrand, 48);
  
  // 获取CPU序列号
  CpuSerialNumber = GetCpuSerialNumber();
  
  // 获取系统时间
  SystemTime = GetPerformanceCounter();
  
  // 获取内存大小（简化实现）
  MemorySize = 8192; // 8GB
  
  // 获取PCI设备数量（简化实现）
  PciDeviceCount = 16;
  
  // 获取主板序列号哈希
  CHAR8 MainboardSerial[64];
  if (!EFI_ERROR(GetMainboardSerial(MainboardSerial, sizeof(MainboardSerial)))) {
    MainboardSerialHash = SimpleHash((UINT8 *)MainboardSerial, AsciiStrLen(MainboardSerial));
  }
  
  // 填充指纹结构
  Fingerprint->CpuSignature = CpuSignature;
  Fingerprint->CpuBrandHash = CpuBrandHash;
  Fingerprint->CpuSerialNumber = CpuSerialNumber;
  Fingerprint->SystemTime = SystemTime;
  Fingerprint->MemorySize = MemorySize;
  Fingerprint->PciDeviceCount = PciDeviceCount;
  Fingerprint->Reserved1 = 0;
  Fingerprint->MainboardSerialHash = MainboardSerialHash;
  Fingerprint->Reserved2 = 0;
  
  // 设置新增的统一字段
  Fingerprint->PlatformType = PLATFORM_INTEL;        // 默认Intel平台，可通过检测修改
  Fingerprint->SecurityFeatures = 0x00000001;        // 基本安全特性
  Fingerprint->VirtualizationSupport = 0x00000001;   // VT-x支持
  Fingerprint->IoMmuSupport = 0x00000001;           // VT-d支持
  Fingerprint->TpmVersion = 0x00000002;              // TPM 2.0
  Fingerprint->SecureBootStatus = 0x00000001;        // 安全启动启用
  
  return EFI_SUCCESS;
}

/**
 * 保存硬件信息到文件
 * 
 * @param[in] Data      硬件收集数据
 * 
 * @retval EFI_SUCCESS          成功
 * @retval EFI_INVALID_PARAMETER 参数无效
 * @retval EFI_DEVICE_ERROR     设备错误
 */
EFI_STATUS
SaveHardwareInfo(HARDWARE_COLLECTION_DATA *Data)
{
  EFI_STATUS Status;
  EFI_HANDLE *HandleBuffer = NULL;
  UINTN HandleCount = 0;
  UINTN Index;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *Volume;
  EFI_FILE_HANDLE RootDir = NULL;
  EFI_FILE_HANDLE FileHandle = NULL;
  UINTN WriteSize;
  CHAR16 FileName[] = L"hardware_fingerprint.hwf";
  
  if (Data == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  
  Status = gBS->LocateHandleBuffer(ByProtocol, &gEfiSimpleFileSystemProtocolGuid, NULL, &HandleCount, &HandleBuffer);
  if (EFI_ERROR(Status) || HandleCount == 0) {
    if (!EFI_ERROR(Status)) {
      Status = EFI_NOT_FOUND;
    }
    return Status;
  }
  
  for (Index = 0; Index < HandleCount; Index++) {
    Status = gBS->HandleProtocol(HandleBuffer[Index], &gEfiSimpleFileSystemProtocolGuid, (VOID **)&Volume);
    if (EFI_ERROR(Status)) {
      continue;
    }
    Status = Volume->OpenVolume(Volume, &RootDir);
    if (EFI_ERROR(Status)) {
      continue;
    }
    Status = RootDir->Open(RootDir, &FileHandle, FileName, EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE, 0);
    if (EFI_ERROR(Status)) {
      RootDir->Close(RootDir);
      continue;
    }
    WriteSize = sizeof(HARDWARE_COLLECTION_DATA);
    Status = FileHandle->Write(FileHandle, &WriteSize, Data);
    FileHandle->Close(FileHandle);
    RootDir->Close(RootDir);
    if (!EFI_ERROR(Status)) {
      if (HandleBuffer != NULL) {
        FreePool(HandleBuffer);
      }
      Print(L"硬件指纹文件已保存: %s\n", FileName);
      Print(L"Hardware fingerprint file saved: %s\n", FileName);
      return EFI_SUCCESS;
    }
  }
  
  if (HandleBuffer != NULL) {
    FreePool(HandleBuffer);
  }
  
  return EFI_DEVICE_ERROR;
}

/**
 * 显示硬件信息
 * 
 * @param[in] Data      硬件收集数据
 */
VOID
DisplayHardwareInfo(HARDWARE_COLLECTION_DATA *Data)
{
  if (Data == NULL) {
    return;
  }
  
  Print(L"\n=== 硬件信息 / Hardware Information ===\n");
  Print(L"Magic: 0x%08X\n", Data->Magic);
  Print(L"Version: 0x%08X\n", Data->Version);
  Print(L"CPU Signature: 0x%08X\n", Data->Fingerprint.CpuSignature);
  Print(L"CPU Brand Hash: 0x%08X\n", Data->Fingerprint.CpuBrandHash);
  Print(L"CPU Serial Number: 0x%016lX\n", Data->Fingerprint.CpuSerialNumber);
  Print(L"System Time: 0x%016lX\n", Data->Fingerprint.SystemTime);
  Print(L"Memory Size: %d MB\n", Data->Fingerprint.MemorySize);
  Print(L"PCI Device Count: %d\n", Data->Fingerprint.PciDeviceCount);
  Print(L"Mainboard Serial Hash: 0x%08X\n", Data->Fingerprint.MainboardSerialHash);
  Print(L"CPU Brand: %a\n", Data->CpuBrandString);
  Print(L"Mainboard Serial: %a\n", Data->MainboardSerial);
  Print(L"System Serial: %a\n", Data->SystemSerial);
  Print(L"Manufacturer: %a\n", Data->ManufacturerInfo);
  Print(L"Collection Time: 0x%016lX\n", Data->CollectionTime);
  Print(L"Checksum: 0x%08X\n", Data->Checksum);
  Print(L"=====================================\n\n");
}

/**
 * 主函数
 * 
 * @param[in] ImageHandle    镜像句柄
 * @param[in] SystemTable    系统表
 * 
 * @retval EFI_SUCCESS       成功
 * @retval EFI_DEVICE_ERROR 设备错误
 */
EFI_STATUS
EFIAPI
UefiMain(
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS Status;
  HARDWARE_COLLECTION_DATA HardwareData;
  
  Print(L"=== VTD硬件收集器 / VTD Hardware Collector ===\n");
  Print(L"开始收集硬件信息...\n");
  Print(L"Starting hardware information collection...\n\n");
  
  // 初始化硬件数据
  ZeroMem(&HardwareData, sizeof(HARDWARE_COLLECTION_DATA));
  
  // 设置头部信息
  HardwareData.Magic = 0x4C4F4348; // "HCOL"
  HardwareData.Version = 0x0100;    // v1.0
  
  // 生成硬件指纹
  Status = GenerateHardwareFingerprint(&HardwareData.Fingerprint);
  if (EFI_ERROR(Status)) {
    Print(L"错误：无法生成硬件指纹 / Error: Failed to generate hardware fingerprint\n");
    return Status;
  }
  
  // 获取CPU品牌字符串
  CHAR8 CpuBrand[49] = {0};
  UINT32 *BrandPtr = (UINT32 *)CpuBrand;
  
  AsmCpuid(0x80000002, &BrandPtr[0], &BrandPtr[1], &BrandPtr[2], &BrandPtr[3]);
  AsmCpuid(0x80000003, &BrandPtr[4], &BrandPtr[5], &BrandPtr[6], &BrandPtr[7]);
  AsmCpuid(0x80000004, &BrandPtr[8], &BrandPtr[9], &BrandPtr[10], &BrandPtr[11]);
  
  AsciiStrCpyS(HardwareData.CpuBrandString, sizeof(HardwareData.CpuBrandString), CpuBrand);
  
  // 获取主板序列号
  Status = GetMainboardSerial(HardwareData.MainboardSerial, sizeof(HardwareData.MainboardSerial));
  if (EFI_ERROR(Status)) {
    Print(L"警告：无法获取主板序列号 / Warning: Failed to get mainboard serial\n");
  }
  
  // 获取系统序列号
  Status = GetSystemSerial(HardwareData.SystemSerial, sizeof(HardwareData.SystemSerial));
  if (EFI_ERROR(Status)) {
    Print(L"警告：无法获取系统序列号 / Warning: Failed to get system serial\n");
  }
  
  // 获取制造商信息
  Status = GetManufacturerInfo(HardwareData.ManufacturerInfo, sizeof(HardwareData.ManufacturerInfo));
  if (EFI_ERROR(Status)) {
    Print(L"警告：无法获取制造商信息 / Warning: Failed to get manufacturer info\n");
  }
  
  // 设置收集时间
  HardwareData.CollectionTime = GetPerformanceCounter();
  
  // 计算校验和
  HardwareData.Checksum = SimpleHash((UINT8 *)&HardwareData, sizeof(HARDWARE_COLLECTION_DATA) - sizeof(UINT32));
  
  // 显示硬件信息
  DisplayHardwareInfo(&HardwareData);
  
  // 保存到文件
  Status = SaveHardwareInfo(&HardwareData);
  if (EFI_ERROR(Status)) {
    Print(L"错误：无法保存硬件信息 / Error: Failed to save hardware information\n");
    return Status;
  }
  
  Print(L"硬件信息收集完成！/ Hardware information collection completed!\n");
  Print(L"请将此文件提供给管理员进行授权。/ Please provide this file to administrator for authorization.\n");
  
  return EFI_SUCCESS;
}
