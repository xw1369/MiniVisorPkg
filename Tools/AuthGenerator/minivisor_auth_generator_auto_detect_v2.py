#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Dxe授权生成器 v4.0 - 自动检测版
================================

功能特性:
- 自动平台检测
- 统一授权验证系统
- 仅支持时间限制，移除使用次数限制
- 跨平台兼容 (Intel VT-x/VT-d 和 AMD SVM)
- 硬件指纹绑定

作者: Dxe开发团队
版本: 4.0
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

# 授权结构常量 (与驱动完全匹配)
MINI_VISOR_AUTH_SIGNATURE = 0x4D564155  # "MVAU"
MINI_VISOR_AUTH_MAGIC = 0x44584520      # "DXE "
MINI_VISOR_AUTH_VERSION = 0x0400        # v4.0

@dataclass
class HardwareFingerprint:
    """硬件指纹结构 - 与驱动完全匹配"""
    # CPU信息
    cpu_signature: int = 0
    cpu_family: int = 0
    cpu_model: int = 0
    cpu_stepping: int = 0
    cpu_features: int = 0
    
    # 平台信息
    chipset_model_hash: int = 0
    bios_version_hash: int = 0
    mainboard_serial_hash: int = 0
    
    # 系统配置
    memory_config_hash: int = 0
    topology_hash: int = 0
    
    # 安全特性
    security_features: int = 0
    virtualization_support: int = 0
    iommu_support: int = 0
    tpm_version: int = 0
    secure_boot_status: int = 0
    
    # 平台类型
    platform_type: int = PLATFORM_UNKNOWN

@dataclass
class CompatibilityMatrix:
    """兼容性矩阵结构 - 与驱动完全匹配"""
    cpu_family_weight: int = 150
    cpu_model_weight: int = 120
    cpu_feature_weight: int = 100
    chipset_weight: int = 80
    bios_weight: int = 60
    mainboard_weight: int = 70
    vmx_svm_weight: int = 200
    iommu_weight: int = 150
    security_weight: int = 100
    cpu_tolerance: int = 30
    platform_tolerance: int = 25
    config_tolerance: int = 20

@dataclass
class Authorization:
    """授权结构 - 与驱动完全匹配"""
    signature: int = MINI_VISOR_AUTH_SIGNATURE
    version: int = MINI_VISOR_AUTH_VERSION
    magic: int = MINI_VISOR_AUTH_MAGIC
    total_size: int = 0
    auth_type: int = AUTH_TYPE_PROFESSIONAL
    platform: int = PLATFORM_UNKNOWN
    issued_time: int = 0
    expiry_time: int = 0
    activation_limit: int = 0  # 0表示无限制
    current_activations: int = 0
    authorization_period_days: int = 365
    reserved1: int = 0
    
    # 硬件指纹
    hardware_fingerprint: Optional[HardwareFingerprint] = None
    
    # 兼容性矩阵
    compatibility_matrix: Optional[CompatibilityMatrix] = None
    
    # 加密数据
    authorization_payload: bytes = b'\x00' * 512
    digital_signature: bytes = b'\x00' * 256
    integrity_hash: bytes = b'\x00' * 64
    anti_tamper_seal: bytes = b'\x00' * 32
    
    # 扩展数据
    custom_data: bytes = b'\x00' * 1024
    reserved2: bytes = b'\x00' * 256
    
    # 使用分析
    first_activation: int = 0
    last_usage: int = 0
    activation_count: int = 0
    usage_pattern: int = 0
    
    # 安全元数据
    security_level: int = 0x00000001  # 基础安全级别
    crypto_version: int = 0x00000002  # 加密算法版本
    security_flags: int = 0x00000001  # 安全特性标志
    
    # 校验和
    checksum: int = 0
    
    # 向后兼容字段
    authorized_time: int = 0
    max_usage_count: int = 0
    current_usage_count: int = 0
    encrypted_payload: bytes = b'\x00' * 64
    rsa_signature: bytes = b'\x00' * 256
    security_hash: bytes = b'\x00' * 32
    hw_fingerprint: Optional[HardwareFingerprint] = None

    def __post_init__(self):
        if self.hardware_fingerprint is None:
            self.hardware_fingerprint = HardwareFingerprint()
        if self.compatibility_matrix is None:
            self.compatibility_matrix = CompatibilityMatrix()
        if self.hw_fingerprint is None:
            self.hw_fingerprint = HardwareFingerprint()
        
        if self.issued_time == 0:
            self.issued_time = int(datetime.now().timestamp())
        if self.expiry_time == 0:
            # 默认一年有效期
            self.expiry_time = self.issued_time + (365 * 24 * 3600)
        
        # 设置向后兼容字段
        self.authorized_time = self.issued_time
        self.max_usage_count = self.activation_limit
        self.current_usage_count = self.current_activations
        self.encrypted_payload = self.authorization_payload[:64]
        self.rsa_signature = self.digital_signature
        self.security_hash = self.integrity_hash[:32]  # 向后兼容
        self.hw_fingerprint = self.hardware_fingerprint
        
        # 计算总大小
        self.total_size = self._calculate_total_size()
    
    def _calculate_total_size(self) -> int:
        """计算结构体总大小"""
        return (4 * 4 +  # signature, version, magic, total_size
                4 * 4 +  # auth_type, platform, issued_time, expiry_time
                4 * 4 +  # activation_limit, current_activations, authorization_period_days, reserved1
                16 * 4 + # hardware_fingerprint (16个UINT32)
                12 * 4 + # compatibility_matrix (12个UINT32)
                512 +     # authorization_payload
                256 +     # digital_signature
                64 +      # integrity_hash
                32 +      # anti_tamper_seal
                1024 +    # custom_data
                256 +     # reserved2
                8 * 8 +   # first_activation, last_usage (2个UINT64)
                4 * 4 +   # activation_count, usage_pattern, security_level, crypto_version
                8 +       # security_flags (UINT64)
                4 +       # checksum
                8 +       # authorized_time (UINT64)
                4 * 4 +   # max_usage_count, current_usage_count, security_level, crypto_version
                64 +      # encrypted_payload
                256 +     # rsa_signature
                32 +      # security_hash
                16 * 4)   # hw_fingerprint (16个UINT32)
    
    def is_expired(self) -> bool:
        """检查授权是否过期"""
        current_time = int(datetime.now().timestamp())
        return current_time > self.expiry_time
    
    def get_remaining_days(self) -> int:
        """获取剩余天数"""
        current_time = int(datetime.now().timestamp())
        remaining_seconds = self.expiry_time - current_time
        return max(0, remaining_seconds // (24 * 3600))

class DxeAuthGenerator:
    """Dxe授权生成器 - 与驱动完全匹配"""
    
    def __init__(self):
        # 平台特定密钥
        self.platform_key = b'DxeAuthKey2024'
        
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
    
    def collect_hardware_info(self) -> HardwareFingerprint:
        """收集硬件信息"""
        fingerprint = HardwareFingerprint()
        
        try:
            # 检测平台类型
            platform_type = self.detect_platform()
        fingerprint.platform_type = platform_type
        
            # 收集CPU信息
            self._collect_cpu_info(fingerprint)
            
            # 收集平台信息
            self._collect_platform_info(fingerprint)
            
            # 收集系统配置
            self._collect_system_config(fingerprint)
            
            # 收集安全特性
            self._collect_security_features(fingerprint)
            
            print(f"✅ 硬件信息收集完成")
            print(f"   平台类型: {self._get_platform_name(platform_type)}")
            
        except Exception as e:
            print(f"⚠️  硬件信息收集失败: {e}")
            # 使用默认值
            fingerprint.platform_type = PLATFORM_UNKNOWN
        
            return fingerprint
    
    def _collect_cpu_info(self, fingerprint: HardwareFingerprint):
        """收集CPU信息"""
        try:
            # CPU签名 (基于CPU品牌)
            cpu_brand = platform.processor()
            fingerprint.cpu_signature = hash(cpu_brand) & 0xFFFFFFFF
            
            # CPU家族、型号、步进 (简化版本)
        fingerprint.cpu_family = 6  # 默认值
            fingerprint.cpu_model = 142  # 默认值
            fingerprint.cpu_stepping = 10  # 默认值
            
            # CPU特性 (基于平台)
            if fingerprint.platform_type == PLATFORM_INTEL:
                fingerprint.cpu_features = 0x80000000  # VT-x支持
            elif fingerprint.platform_type == PLATFORM_AMD:
                fingerprint.cpu_features = 0x40000000  # SVM支持
            else:
                fingerprint.cpu_features = 0x00000000
            
        except Exception:
            pass
    
    def _collect_platform_info(self, fingerprint: HardwareFingerprint):
        """收集平台信息"""
        try:
            # 芯片组型号哈希
            chipset_info = platform.machine()
            fingerprint.chipset_model_hash = hash(chipset_info) & 0xFFFFFFFF
            
            # BIOS版本哈希
            bios_info = platform.version()
            fingerprint.bios_version_hash = hash(bios_info) & 0xFFFFFFFF
            
            # 主板序列号哈希
            board_info = platform.node()
            fingerprint.mainboard_serial_hash = hash(board_info) & 0xFFFFFFFF
            
        except Exception:
            pass
    
    def _collect_system_config(self, fingerprint: HardwareFingerprint):
        """收集系统配置"""
        try:
            # 内存配置哈希
            memory_info = platform.architecture()
            fingerprint.memory_config_hash = hash(str(memory_info)) & 0xFFFFFFFF
            
            # 系统拓扑哈希
            topology_info = f"{platform.system()}-{platform.release()}-{platform.machine()}"
            fingerprint.topology_hash = hash(topology_info) & 0xFFFFFFFF
            
        except Exception:
            pass
    
    def _collect_security_features(self, fingerprint: HardwareFingerprint):
        """收集安全特性"""
        try:
            # 安全特性
            fingerprint.security_features = 0x00000001  # 基础安全
            
            # 虚拟化支持
            if fingerprint.platform_type == PLATFORM_INTEL:
                fingerprint.virtualization_support = 0x00000001  # VT-x
                fingerprint.iommu_support = 0x00000001  # VT-d
            elif fingerprint.platform_type == PLATFORM_AMD:
                fingerprint.virtualization_support = 0x00000002  # SVM
                fingerprint.iommu_support = 0x00000002  # IOMMU
            
            # TPM版本
            fingerprint.tpm_version = 0x00000002  # TPM 2.0
            
            # 安全启动状态
            fingerprint.secure_boot_status = 0x00000001  # 启用
            
        except Exception:
            pass
    
    def _get_platform_name(self, platform_type: int) -> str:
        """获取平台名称"""
        names = {
            PLATFORM_UNKNOWN: "未知",
            PLATFORM_INTEL: "Intel VT-x/VT-d",
            PLATFORM_AMD: "AMD SVM/IOMMU",
            PLATFORM_UNIVERSAL: "通用"
        }
        return names.get(platform_type, "未知")
    
    def generate_authorization(self, auth_type: int = AUTH_TYPE_PROFESSIONAL, 
                             expiry_days: int = 365) -> Authorization:
        """生成授权"""
        print(f"🚀 开始生成授权文件...")
        
        # 收集硬件信息
        print(f"🔍 正在收集硬件信息...")
        hardware_fingerprint = self.collect_hardware_info()
        
        # 创建授权
        print(f"🏗️  正在创建授权结构...")
        auth = Authorization(
            auth_type=auth_type,
            platform=hardware_fingerprint.platform_type,
            expiry_time=int((datetime.now() + timedelta(days=expiry_days)).timestamp()),
            hardware_fingerprint=hardware_fingerprint
        )
        
        # 生成签名和哈希
        print(f"🔐 正在生成数字签名...")
        auth.digital_signature = self._generate_signature(auth)
        auth.integrity_hash = self._generate_integrity_hash(auth)
        auth.security_hash = auth.integrity_hash[:32]  # 向后兼容
        auth.rsa_signature = auth.digital_signature    # 向后兼容
        
        # 计算校验和
        auth.checksum = self._calculate_checksum(auth)
        
        print(f"✅ 授权生成完成")
        return auth
    
    def _generate_signature(self, auth: Authorization) -> bytes:
        """生成授权签名"""
        # 构建签名数据
        sign_data = struct.pack('<IIIIQQ', 
                               auth.signature, auth.version, auth.magic, auth.auth_type,
                               auth.platform, auth.issued_time, auth.expiry_time)
        
        # 添加硬件指纹
        hw_data = struct.pack('<IIIIIIIIIIIIIIII',
                             auth.hardware_fingerprint.cpu_signature,
                             auth.hardware_fingerprint.cpu_family,
                             auth.hardware_fingerprint.cpu_model,
                             auth.hardware_fingerprint.cpu_stepping,
                             auth.hardware_fingerprint.cpu_features,
                             auth.hardware_fingerprint.chipset_model_hash,
                             auth.hardware_fingerprint.bios_version_hash,
                             auth.hardware_fingerprint.mainboard_serial_hash,
                             auth.hardware_fingerprint.memory_config_hash,
                             auth.hardware_fingerprint.topology_hash,
                             auth.hardware_fingerprint.security_features,
                             auth.hardware_fingerprint.virtualization_support,
                             auth.hardware_fingerprint.iommu_support,
                             auth.hardware_fingerprint.tpm_version,
                             auth.hardware_fingerprint.secure_boot_status,
                             auth.hardware_fingerprint.platform_type)
        
        sign_data += hw_data + self.platform_key
        
        # 生成SHA256签名
        return hashlib.sha256(sign_data).digest()
    
    def _generate_integrity_hash(self, auth: Authorization) -> bytes:
        """生成完整性哈希"""
        # 构建哈希数据 (排除签名和哈希字段)
        hash_data = struct.pack('<IIIIQQII',
                               auth.signature, auth.version, auth.magic, auth.total_size,
                               auth.auth_type, auth.platform, auth.issued_time, auth.expiry_time,
                               auth.activation_limit, auth.current_activations)
        
        # 添加硬件指纹
        hw_data = struct.pack('<IIIIIIIIIIIIIIII',
                             auth.hardware_fingerprint.cpu_signature,
                             auth.hardware_fingerprint.cpu_family,
                             auth.hardware_fingerprint.cpu_model,
                             auth.hardware_fingerprint.cpu_stepping,
                             auth.hardware_fingerprint.cpu_features,
                             auth.hardware_fingerprint.chipset_model_hash,
                             auth.hardware_fingerprint.bios_version_hash,
                             auth.hardware_fingerprint.mainboard_serial_hash,
                             auth.hardware_fingerprint.memory_config_hash,
                             auth.hardware_fingerprint.topology_hash,
                             auth.hardware_fingerprint.security_features,
                             auth.hardware_fingerprint.virtualization_support,
                             auth.hardware_fingerprint.iommu_support,
                             auth.hardware_fingerprint.tpm_version,
                             auth.hardware_fingerprint.secure_boot_status,
                             auth.hardware_fingerprint.platform_type)
        
        hash_data += hw_data
        
        # 生成SHA512哈希
        return hashlib.sha512(hash_data).digest()
    
    def _calculate_checksum(self, auth: Authorization) -> int:
        """计算CRC32校验和"""
        # 简化的校验和计算
        checksum_data = struct.pack('<IIIIQQII',
                                   auth.signature, auth.version, auth.magic, auth.total_size,
                                   auth.auth_type, auth.platform, auth.issued_time, auth.expiry_time,
                                   auth.activation_limit, auth.current_activations)
        
        # 使用简单的哈希作为校验和
        return hash(checksum_data) & 0xFFFFFFFF
    
    def save_authorization(self, auth: Authorization, output_path: str):
        """保存授权文件 - 与驱动完全匹配"""
        print(f"💾 正在保存授权文件...")
        
        # 构建授权数据
        auth_data = struct.pack('<IIIIQQII',
                               auth.signature, auth.version, auth.magic, auth.total_size,
                               auth.auth_type, auth.platform, auth.issued_time, auth.expiry_time,
                               auth.activation_limit, auth.current_activations)
        
        # 添加授权周期和保留字段
        auth_data += struct.pack('<II',
                               auth.authorization_period_days, auth.reserved1)
        
        # 添加硬件指纹
        hw_data = struct.pack('<IIIIIIIIIIIIIIII',
                             auth.hardware_fingerprint.cpu_signature,
                             auth.hardware_fingerprint.cpu_family,
                             auth.hardware_fingerprint.cpu_model,
                             auth.hardware_fingerprint.cpu_stepping,
                             auth.hardware_fingerprint.cpu_features,
                             auth.hardware_fingerprint.chipset_model_hash,
                             auth.hardware_fingerprint.bios_version_hash,
                             auth.hardware_fingerprint.mainboard_serial_hash,
                             auth.hardware_fingerprint.memory_config_hash,
                             auth.hardware_fingerprint.topology_hash,
                             auth.hardware_fingerprint.security_features,
                             auth.hardware_fingerprint.virtualization_support,
                             auth.hardware_fingerprint.iommu_support,
                             auth.hardware_fingerprint.tpm_version,
                             auth.hardware_fingerprint.secure_boot_status,
                             auth.hardware_fingerprint.platform_type)
        
        # 添加兼容性矩阵
        cm_data = struct.pack('<IIIIIIIIIIII',
                             auth.compatibility_matrix.cpu_family_weight,
                             auth.compatibility_matrix.cpu_model_weight,
                             auth.compatibility_matrix.cpu_feature_weight,
                             auth.compatibility_matrix.chipset_weight,
                             auth.compatibility_matrix.bios_weight,
                             auth.compatibility_matrix.mainboard_weight,
                             auth.compatibility_matrix.vmx_svm_weight,
                             auth.compatibility_matrix.iommu_weight,
                             auth.compatibility_matrix.security_weight,
                             auth.compatibility_matrix.cpu_tolerance,
                             auth.compatibility_matrix.platform_tolerance,
                             auth.compatibility_matrix.config_tolerance)
        
        # 添加加密数据
        auth_data += hw_data + cm_data + auth.authorization_payload + auth.digital_signature + auth.integrity_hash + auth.anti_tamper_seal
        
        # 添加扩展数据
        auth_data += auth.custom_data + auth.reserved2
        
        # 添加使用分析
        auth_data += struct.pack('<QQII',
                               auth.first_activation, auth.last_usage,
                               auth.activation_count, auth.usage_pattern)
        
        # 添加安全元数据
        auth_data += struct.pack('<IIQ',
                               auth.security_level, auth.crypto_version, auth.security_flags)
        
        # 添加校验和
        auth_data += struct.pack('<I', auth.checksum)
        
        # 添加向后兼容字段
        auth_data += struct.pack('<QII',
                               auth.authorized_time, auth.max_usage_count, auth.current_usage_count)
        auth_data += auth.encrypted_payload + auth.rsa_signature + auth.security_hash
        
        # 添加向后兼容硬件指纹
        auth_data += struct.pack('<IIIIIIIIIIIIIIII',
                               auth.hw_fingerprint.cpu_signature,
                               auth.hw_fingerprint.cpu_family,
                               auth.hw_fingerprint.cpu_model,
                               auth.hw_fingerprint.cpu_stepping,
                               auth.hw_fingerprint.cpu_features,
                               auth.hw_fingerprint.chipset_model_hash,
                               auth.hw_fingerprint.bios_version_hash,
                               auth.hw_fingerprint.mainboard_serial_hash,
                               auth.hw_fingerprint.memory_config_hash,
                               auth.hw_fingerprint.topology_hash,
                               auth.hw_fingerprint.security_features,
                               auth.hw_fingerprint.virtualization_support,
                               auth.hw_fingerprint.iommu_support,
                               auth.hw_fingerprint.tpm_version,
                               auth.hw_fingerprint.secure_boot_status,
                               auth.hw_fingerprint.platform_type)
        
        # 保存文件
        with open(output_path, 'wb') as f:
            f.write(auth_data)
        
        print(f"✅ 授权文件已保存: {output_path}")
        print(f"   文件大小: {len(auth_data)} 字节")

def main():
    """主函数"""
    print("=" * 70)
    print("Dxe授权生成器 v4.0 - 自动检测版")
    print("=" * 70)
    
    try:
        # 创建生成器
        generator = DxeAuthGenerator()
        
        # 配置参数
        auth_type = AUTH_TYPE_PROFESSIONAL
        expiry_days = 365
        
        # 生成授权
        auth = generator.generate_authorization(
            auth_type=auth_type,
            expiry_days=expiry_days
        )
        
        # 保存授权文件
        output_file = "auth.dat"  # 固定命名为auth.dat
        generator.save_authorization(auth, output_file)
        
        # 显示授权信息
        print("\n" + "=" * 70)
        print("授权信息 / Authorization Information")
        print("=" * 70)
        
        platform_names = ["未知/Unknown", "Intel VT-x/VT-d", "AMD SVM/IOMMU", "通用/Universal"]
        auth_type_names = ["基础版/Basic", "专业版/Professional", "企业版/Enterprise"]
        
        print(f"平台类型 / Platform: {platform_names[auth.platform]}")
        print(f"授权类型 / Auth Type: {auth_type_names[auth.auth_type - 1]}")
        print(f"创建时间 / Created: {datetime.fromtimestamp(auth.issued_time)}")
        print(f"过期时间 / Expires: {datetime.fromtimestamp(auth.expiry_time)}")
        print(f"剩余天数 / Remaining: {auth.get_remaining_days()} 天")
        print(f"输出文件 / Output: {output_file}")
        
        print("\n🎉 授权生成成功完成！")
        print("📋 v4.0 主要改进:")
        print("   - 统一授权验证系统")
        print("   - 仅支持时间限制，移除使用次数限制")
        print("   - 跨平台兼容性增强")
        print("   - 硬件指纹算法优化")
        
    except Exception as e:
        print(f"\n❌ 授权生成失败: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
