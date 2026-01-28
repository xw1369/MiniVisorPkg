#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
统一授权生成器 v1.0 - Unified Authorization Generator
====================================================

功能特性:
- 读取硬件收集器生成的bin文件
- 生成与统一授权系统兼容的auth.dat文件
- 跨平台兼容 (Intel VT-x/VT-d 和 AMD SVM)
- 硬件指纹绑定
- 与统一授权库完全兼容

作者: 统一授权开发团队
版本: 1.0
日期: 2024
"""

import os
import sys
import struct
import hashlib
import json
import platform
import subprocess
from datetime import datetime, timedelta
from dataclasses import dataclass
from typing import Optional, Dict, Any

# 平台类型定义
PLATFORM_UNKNOWN = 0
PLATFORM_INTEL = 1
PLATFORM_AMD = 2
PLATFORM_UNIVERSAL = 3

# 授权类型定义
AUTH_TYPE_BASIC = 1
AUTH_TYPE_PROFESSIONAL = 2
AUTH_TYPE_ENTERPRISE = 3

# 统一授权结构常量 (与统一授权库完全匹配)
UNIFIED_AUTH_SIGNATURE = 0x48545541  # 'AUTH'
UNIFIED_AUTH_MAGIC = 0x44484520      # 'DHE '
UNIFIED_AUTH_VERSION = 0x0100        # v1.0

# 硬件收集器文件格式常量
HARDWARE_COLLECTOR_MAGIC = 0x4C4F4348  # 'HCOL'

@dataclass
class UnifiedHardwareFingerprint:
    """统一硬件指纹结构 - 与统一授权库完全匹配"""
    # CPU信息
    cpu_signature: int = 0
    cpu_brand_hash: int = 0
    cpu_serial_number: int = 0
    system_time: int = 0
    
    # 系统配置
    memory_size: int = 0
    pci_device_count: int = 0
    reserved1: int = 0
    mainboard_serial_hash: int = 0
    reserved2: int = 0
    
    # 平台和安全特性
    platform_type: int = PLATFORM_UNKNOWN
    security_features: int = 0
    virtualization_support: int = 0
    iommu_support: int = 0
    tpm_version: int = 0
    secure_boot_status: int = 0

@dataclass
class UnifiedAuthorization:
    """统一授权结构 - 与统一授权库完全匹配"""
    signature: int = UNIFIED_AUTH_SIGNATURE
    version: int = UNIFIED_AUTH_VERSION
    magic: int = UNIFIED_AUTH_MAGIC
    total_size: int = 0
    auth_type: int = AUTH_TYPE_PROFESSIONAL
    platform: int = PLATFORM_UNKNOWN
    issued_time: int = 0
    expiry_time: int = 0
    usage_count: int = 0  # 已弃用，始终为0
    max_usage_count: int = 0  # 已弃用，始终为0
    hardware_fingerprint: UnifiedHardwareFingerprint = None
    checksum: int = 0
    reserved: bytes = b'\x00' * 64

class UnifiedAuthGenerator:
    """统一授权生成器 - 与统一授权库完全匹配"""
    
    def __init__(self):
        self.platform_key = b'UnifiedAuthKey2024'
        
    def detect_platform(self) -> int:
        """自动检测平台类型"""
        try:
            # 检测CPU厂商
            cpu_info = platform.processor().lower()
            
            if 'intel' in cpu_info or 'genuineintel' in cpu_info:
                return PLATFORM_INTEL
            elif 'amd' in cpu_info or 'authenticamd' in cpu_info:
                return PLATFORM_AMD
            else:
                # 尝试通过其他方式检测
                return self._detect_platform_advanced()
                
        except Exception:
            return self._detect_platform_advanced()
    
    def _detect_platform_advanced(self) -> int:
        """高级平台检测"""
        # Windows平台检测
        if platform.system() == 'Windows':
            try:
                import wmi
                c = wmi.WMI()
                for processor in c.Win32_Processor():
                    if 'intel' in processor.Name.lower():
                        return PLATFORM_INTEL
                    elif 'amd' in processor.Name.lower():
                        return PLATFORM_AMD
            except ImportError:
                pass
        
        # Linux平台检测
        try:
            if platform.system() == 'Linux':
                with open('/proc/cpuinfo', 'r') as f:
                    cpuinfo = f.read()
                    if 'GenuineIntel' in cpuinfo:
                        return PLATFORM_INTEL
                    elif 'AuthenticAMD' in cpuinfo:
                        return PLATFORM_AMD
        except Exception:
            pass
        
        return PLATFORM_UNKNOWN
    
    def read_hardware_collector_file(self, filename: str) -> Optional[UnifiedHardwareFingerprint]:
        """读取硬件收集器生成的bin文件"""
        try:
            with open(filename, 'rb') as f:
                # 读取文件头
                magic = struct.unpack('<I', f.read(4))[0]
                if magic != HARDWARE_COLLECTOR_MAGIC:
                    print(f"❌ 无效的硬件收集器文件格式 / Invalid hardware collector file format")
                    return None
                
                version = struct.unpack('<I', f.read(4))[0]
                print(f"✅ 硬件收集器文件版本 / Hardware collector file version: 0x{version:04X}")
                
                # 读取硬件指纹结构 (UNIFIED_HARDWARE_FINGERPRINT)
                cpu_signature = struct.unpack('<I', f.read(4))[0]
                cpu_brand_hash = struct.unpack('<I', f.read(4))[0]
                cpu_serial_number = struct.unpack('<Q', f.read(8))[0]
                system_time = struct.unpack('<Q', f.read(8))[0]
                memory_size = struct.unpack('<I', f.read(4))[0]
                pci_device_count = struct.unpack('<H', f.read(2))[0]
                reserved1 = struct.unpack('<H', f.read(2))[0]
                mainboard_serial_hash = struct.unpack('<I', f.read(4))[0]
                reserved2 = struct.unpack('<I', f.read(4))[0]
                platform_type = struct.unpack('<I', f.read(4))[0]
                security_features = struct.unpack('<I', f.read(4))[0]
                virtualization_support = struct.unpack('<I', f.read(4))[0]
                iommu_support = struct.unpack('<I', f.read(4))[0]
                tpm_version = struct.unpack('<I', f.read(4))[0]
                secure_boot_status = struct.unpack('<I', f.read(4))[0]
                
                # 创建统一硬件指纹
                fingerprint = UnifiedHardwareFingerprint()
                fingerprint.cpu_signature = cpu_signature
                fingerprint.cpu_brand_hash = cpu_brand_hash
                fingerprint.cpu_serial_number = cpu_serial_number
                fingerprint.system_time = system_time
                fingerprint.memory_size = memory_size
                fingerprint.pci_device_count = pci_device_count
                fingerprint.reserved1 = reserved1
                fingerprint.mainboard_serial_hash = mainboard_serial_hash
                fingerprint.reserved2 = reserved2
                
                # 设置平台类型
                platform_type = self.detect_platform()
                fingerprint.platform_type = platform_type
                
                # 设置安全特性 (简化版本)
                fingerprint.security_features = security_features
                fingerprint.virtualization_support = virtualization_support
                fingerprint.iommu_support = iommu_support
                # Correct field assignment: use tpm_version
                fingerprint.tpm_version = tpm_version
                fingerprint.secure_boot_status = secure_boot_status
                
                print(f"✅ 硬件指纹读取成功 / Hardware fingerprint read successfully")
                print(f"   CPU签名 / CPU Signature: 0x{cpu_signature:08X}")
                print(f"   CPU品牌哈希 / CPU Brand Hash: 0x{cpu_brand_hash:08X}")
                print(f"   CPU序列号 / CPU Serial Number: 0x{cpu_serial_number:016X}")
                print(f"   主板序列号哈希 / Mainboard Serial Hash: 0x{mainboard_serial_hash:08X}")
                print(f"   平台类型 / Platform Type: {self._get_platform_name(platform_type)}")
                
                return fingerprint
                
        except Exception as e:
            print(f"❌ 读取硬件收集器文件失败 / Failed to read hardware collector file: {e}")
            return None
    
    def generate_authorization(self, 
                             fingerprint: UnifiedHardwareFingerprint,
                             auth_type: int = AUTH_TYPE_PROFESSIONAL,
                             days: int = 365) -> UnifiedAuthorization:
        """生成授权文件"""
        auth = UnifiedAuthorization()
        
        # 设置授权信息
        auth.auth_type = auth_type
        auth.platform = fingerprint.platform_type
        auth.issued_time = int(datetime.now().timestamp())
        auth.expiry_time = int((datetime.now() + timedelta(days=days)).timestamp())
        auth.usage_count = 0  # 已弃用
        auth.max_usage_count = 0  # 已弃用
        auth.hardware_fingerprint = fingerprint
        
        # 计算总大小
        auth.total_size = struct.calcsize('IIIIIIIIQQIIIIIIIIIIII')
        
        # 计算校验和
        auth.checksum = self._calculate_checksum(auth)
        
        return auth
    
    def _calculate_checksum(self, auth: UnifiedAuthorization) -> int:
        """计算校验和"""
        # 将授权数据打包为字节
        data = struct.pack('IIIIIIIIQQIIIIIIIIIIII',
                          auth.signature,
                          auth.version,
                          auth.magic,
                          auth.total_size,
                          auth.auth_type,
                          auth.platform,
                          auth.issued_time,
                          auth.expiry_time,
                          auth.usage_count,
                          auth.max_usage_count,
                          auth.hardware_fingerprint.cpu_signature,
                          auth.hardware_fingerprint.cpu_brand_hash,
                          auth.hardware_fingerprint.cpu_serial_number,
                          auth.hardware_fingerprint.system_time,
                          auth.hardware_fingerprint.memory_size,
                          auth.hardware_fingerprint.pci_device_count,
                          auth.hardware_fingerprint.reserved1,
                          auth.hardware_fingerprint.mainboard_serial_hash,
                          auth.hardware_fingerprint.reserved2,
                          auth.hardware_fingerprint.platform_type,
                          auth.hardware_fingerprint.security_features,
                          auth.hardware_fingerprint.virtualization_support,
                          auth.hardware_fingerprint.iommu_support,
                          auth.hardware_fingerprint.tpm_version,
                          auth.hardware_fingerprint.secure_boot_status)
        
        # 计算简单哈希
        checksum = 0
        for byte in data:
            checksum = ((checksum << 5) + checksum) + byte
            checksum ^= (checksum >> 16)
        
        return checksum
    
    def save_authorization(self, auth: UnifiedAuthorization, filename: str):
        """保存授权文件"""
        try:
            # 将授权数据打包为字节
            data = struct.pack('IIIIIIIIQQIIIIIIIIIIII',
                              auth.signature,
                              auth.version,
                              auth.magic,
                              auth.total_size,
                              auth.auth_type,
                              auth.platform,
                              auth.issued_time,
                              auth.expiry_time,
                              auth.usage_count,
                              auth.max_usage_count,
                              auth.hardware_fingerprint.cpu_signature,
                              auth.hardware_fingerprint.cpu_brand_hash,
                              auth.hardware_fingerprint.cpu_serial_number,
                              auth.hardware_fingerprint.system_time,
                              auth.hardware_fingerprint.memory_size,
                              auth.hardware_fingerprint.pci_device_count,
                              auth.hardware_fingerprint.reserved1,
                              auth.hardware_fingerprint.mainboard_serial_hash,
                              auth.hardware_fingerprint.reserved2,
                              auth.hardware_fingerprint.platform_type,
                              auth.hardware_fingerprint.security_features,
                              auth.hardware_fingerprint.virtualization_support,
                              auth.hardware_fingerprint.iommu_support,
                              auth.hardware_fingerprint.tpm_version,
                              auth.hardware_fingerprint.secure_boot_status)
            
            # 添加校验和
            data += struct.pack('I', auth.checksum)
            
            # 添加保留字段
            data += auth.reserved
            
            # 保存到文件
            with open(filename, 'wb') as f:
                f.write(data)
            
            print(f"✅ 授权文件已保存 / Authorization file saved: {filename}")
            
        except Exception as e:
            print(f"❌ 授权文件保存失败 / Authorization file save failed: {e}")
            raise
    
    def display_authorization_info(self, auth: UnifiedAuthorization):
        """显示授权信息"""
        print(f"\n=== 授权信息 / Authorization Information ===")
        print(f"签名 / Signature: 0x{auth.signature:08X}")
        print(f"版本 / Version: 0x{auth.version:04X}")
        print(f"授权类型 / Authorization Type: {auth.auth_type}")
        print(f"平台 / Platform: {self._get_platform_name(auth.platform)}")
        print(f"签发时间 / Issued Time: {datetime.fromtimestamp(auth.issued_time)}")
        print(f"过期时间 / Expiry Time: {datetime.fromtimestamp(auth.expiry_time)}")
        print(f"剩余天数 / Remaining Days: {self._get_remaining_days(auth)}")
        print(f"校验和 / Checksum: 0x{auth.checksum:08X}")
        
        print(f"\n=== 硬件指纹 / Hardware Fingerprint ===")
        print(f"CPU签名 / CPU Signature: 0x{auth.hardware_fingerprint.cpu_signature:08X}")
        print(f"CPU品牌哈希 / CPU Brand Hash: 0x{auth.hardware_fingerprint.cpu_brand_hash:08X}")
        print(f"CPU序列号 / CPU Serial Number: 0x{auth.hardware_fingerprint.cpu_serial_number:016X}")
        print(f"主板序列号哈希 / Mainboard Serial Hash: 0x{auth.hardware_fingerprint.mainboard_serial_hash:08X}")
        print(f"平台类型 / Platform Type: {self._get_platform_name(auth.hardware_fingerprint.platform_type)}")
    
    def _get_platform_name(self, platform_type: int) -> str:
        """获取平台名称"""
        if platform_type == PLATFORM_INTEL:
            return "Intel / Intel"
        elif platform_type == PLATFORM_AMD:
            return "AMD / AMD"
        else:
            return "Unknown / 未知"
    
    def _get_remaining_days(self, auth: UnifiedAuthorization) -> int:
        """获取剩余天数"""
        current_time = int(datetime.now().timestamp())
        remaining_seconds = auth.expiry_time - current_time
        return max(0, remaining_seconds // (24 * 3600))

def main():
    """主函数"""
    print("=== 统一授权生成器 v1.0 / Unified Authorization Generator v1.0 ===")
    print("与统一授权库完全兼容 / Fully compatible with Unified Authorization Library")
    print()
    
    # 检查命令行参数
    if len(sys.argv) < 2:
        print("用法 / Usage: python unified_auth_generator.py <hardware_fingerprint.bin>")
        print("示例 / Example: python unified_auth_generator.py hardware_fingerprint.bin")
        return 1
    
    hardware_file = sys.argv[1]
    
    if not os.path.exists(hardware_file):
        print(f"❌ 硬件指纹文件不存在 / Hardware fingerprint file not found: {hardware_file}")
        return 1
    
    # 创建生成器
    generator = UnifiedAuthGenerator()
    
    try:
        # 读取硬件指纹文件
        print(f"正在读取硬件指纹文件... / Reading hardware fingerprint file...")
        fingerprint = generator.read_hardware_collector_file(hardware_file)
        
        if fingerprint is None:
            print("❌ 无法读取硬件指纹文件 / Failed to read hardware fingerprint file")
            return 1
        
        # 生成授权
        print("\n正在生成授权... / Generating authorization...")
        auth = generator.generate_authorization(fingerprint, AUTH_TYPE_PROFESSIONAL, 365)
        
        # 显示授权信息
        generator.display_authorization_info(auth)
        
        # 保存授权文件 - 严格命名为auth.dat
        filename = "auth.dat"
        generator.save_authorization(auth, filename)
        
        print(f"\n✅ 授权生成完成！/ Authorization generation completed!")
        print(f"授权文件 / Authorization file: {filename}")
        print(f"请将此文件放置在指定位置 / Please place this file in the specified location")
        
        # 显示使用说明
        print(f"\n=== 部署说明 / Deployment Instructions ===")
        print(f"1. 将 {filename} 复制到以下位置之一 / Copy {filename} to one of the following locations:")
        print(f"   - U盘根目录 (推荐) / USB drive root directory (recommended)")
        print(f"   - C盘根目录 / C: drive root directory")
        print(f"2. 根据平台类型选择相应驱动 / Choose appropriate driver based on platform:")
        platform_name = generator._get_platform_name(fingerprint.platform_type)
        if "Intel" in platform_name:
            print(f"   - Intel平台: MiniVisorDxe.efi / Intel platform: MiniVisorDxe.efi")
        elif "AMD" in platform_name:
            print(f"   - AMD平台: MiniVisorSvmDxe.efi / AMD platform: MiniVisorSvmDxe.efi")
        else:
            print(f"   - 根据平台选择相应驱动 / Choose appropriate driver based on platform")
        print(f"3. 驱动将自动在指定位置查找并验证授权文件")
        print(f"   Driver will automatically search and verify authorization file in specified locations")
        
        print(f"\n⚠️  重要要求 / Important Requirements:")
        print(f"- 授权文件必须严格命名为 'auth.dat' / Authorization file must be strictly named 'auth.dat'")
        print(f"- 必须放置在U盘根目录或C盘根目录 / Must be placed in USB drive root or C: drive root")
        print(f"- 不支持其他文件名或路径 / Other filenames or paths are not supported")
        print(f"- 授权文件与硬件指纹绑定 / Authorization file is bound to hardware fingerprint")
        print(f"- 授权有效期为365天 / Authorization valid for 365 days")
        
    except Exception as e:
        print(f"\n❌ 授权生成失败 / Authorization generation failed: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
