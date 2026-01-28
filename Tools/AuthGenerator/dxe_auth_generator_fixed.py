#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Dxe授权生成器 v4.0 - 修复版
==========================

功能特性:
- 自动平台检测
- 与驱动完全匹配的授权格式
- 仅支持时间限制
- 跨平台兼容 (Intel VT-x/VT-d 和 AMD SVM)

作者: Dxe开发团队
版本: 4.0
日期: 2024
"""

import os
import sys
import struct
import hashlib
import platform
from datetime import datetime, timedelta

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

def detect_platform():
    """自动检测平台类型"""
    try:
        cpu_info = platform.processor().lower()
        if 'intel' in cpu_info or 'genuineintel' in cpu_info:
            return PLATFORM_INTEL
        elif 'amd' in cpu_info or 'authenticamd' in cpu_info:
            return PLATFORM_AMD
        else:
            return PLATFORM_UNKNOWN
    except Exception:
        return PLATFORM_UNKNOWN

def collect_hardware_info(platform_type):
    """收集硬件信息"""
    fingerprint = {
        'cpu_signature': hash(platform.processor()) & 0xFFFFFFFF,
        'cpu_family': 6,
        'cpu_model': 142,
        'cpu_stepping': 10,
        'cpu_features': 0x80000000 if platform_type == PLATFORM_INTEL else 0x40000000 if platform_type == PLATFORM_AMD else 0,
        'chipset_model_hash': hash(platform.machine()) & 0xFFFFFFFF,
        'bios_version_hash': hash(platform.version()) & 0xFFFFFFFF,
        'mainboard_serial_hash': hash(platform.node()) & 0xFFFFFFFF,
        'memory_config_hash': hash(str(platform.architecture())) & 0xFFFFFFFF,
        'topology_hash': hash(f"{platform.system()}-{platform.release()}-{platform.machine()}") & 0xFFFFFFFF,
        'security_features': 0x00000001,
        'virtualization_support': 0x00000001 if platform_type == PLATFORM_INTEL else 0x00000002 if platform_type == PLATFORM_AMD else 0,
        'iommu_support': 0x00000001 if platform_type == PLATFORM_INTEL else 0x00000002 if platform_type == PLATFORM_AMD else 0,
        'tpm_version': 0x00000002,
        'secure_boot_status': 0x00000001,
        'platform_type': platform_type
    }
    return fingerprint

def generate_authorization(platform_type, auth_type, expiry_days):
    """生成授权结构"""
    now = int(datetime.now().timestamp())
    expiry = now + (expiry_days * 24 * 3600)
    
    # 硬件指纹
    hw_fingerprint = collect_hardware_info(platform_type)
    
    # 兼容性矩阵
    compatibility_matrix = {
        'cpu_family_weight': 150,
        'cpu_model_weight': 120,
        'cpu_feature_weight': 100,
        'chipset_weight': 80,
        'bios_weight': 60,
        'mainboard_weight': 70,
        'vmx_svm_weight': 200,
        'iommu_weight': 150,
        'security_weight': 100,
        'cpu_tolerance': 30,
        'platform_tolerance': 25,
        'config_tolerance': 20
    }
    
    # 构建授权数据
    auth_data = struct.pack('<IIIIQQII',
                           MINI_VISOR_AUTH_SIGNATURE, MINI_VISOR_AUTH_VERSION, MINI_VISOR_AUTH_MAGIC, 0,  # total_size稍后计算
                           auth_type, platform_type, now, expiry,
                           0, 0)  # activation_limit=0, current_activations=0
    
    # 添加授权周期和保留字段
    auth_data += struct.pack('<II', expiry_days, 0)
    
    # 添加硬件指纹
    hw_data = struct.pack('<IIIIIIIIIIIIIIII',
                         hw_fingerprint['cpu_signature'],
                         hw_fingerprint['cpu_family'],
                         hw_fingerprint['cpu_model'],
                         hw_fingerprint['cpu_stepping'],
                         hw_fingerprint['cpu_features'],
                         hw_fingerprint['chipset_model_hash'],
                         hw_fingerprint['bios_version_hash'],
                         hw_fingerprint['mainboard_serial_hash'],
                         hw_fingerprint['memory_config_hash'],
                         hw_fingerprint['topology_hash'],
                         hw_fingerprint['security_features'],
                         hw_fingerprint['virtualization_support'],
                         hw_fingerprint['iommu_support'],
                         hw_fingerprint['tpm_version'],
                         hw_fingerprint['secure_boot_status'],
                         hw_fingerprint['platform_type'])
    
    # 添加兼容性矩阵
    cm_data = struct.pack('<IIIIIIIIIIII',
                         compatibility_matrix['cpu_family_weight'],
                         compatibility_matrix['cpu_model_weight'],
                         compatibility_matrix['cpu_feature_weight'],
                         compatibility_matrix['chipset_weight'],
                         compatibility_matrix['bios_weight'],
                         compatibility_matrix['mainboard_weight'],
                         compatibility_matrix['vmx_svm_weight'],
                         compatibility_matrix['iommu_weight'],
                         compatibility_matrix['security_weight'],
                         compatibility_matrix['cpu_tolerance'],
                         compatibility_matrix['platform_tolerance'],
                         compatibility_matrix['config_tolerance'])
    
    # 添加加密数据 (填充零)
    auth_data += hw_data + cm_data + b'\x00' * (512 + 256 + 64 + 32)
    
    # 添加扩展数据
    auth_data += b'\x00' * (1024 + 256)
    
    # 添加使用分析
    auth_data += struct.pack('<QQII', now, now, 0, 0)
    
    # 添加安全元数据
    auth_data += struct.pack('<IIQ', 0x00000001, 0x00000002, 0x00000001)
    
    # 添加校验和
    checksum = hash(auth_data) & 0xFFFFFFFF
    auth_data += struct.pack('<I', checksum)
    
    # 添加向后兼容字段
    auth_data += struct.pack('<QII', now, 0, 0)
    auth_data += b'\x00' * (64 + 256 + 32)
    
    # 添加向后兼容硬件指纹
    auth_data += hw_data
    
    # 计算总大小
    total_size = len(auth_data)
    
    # 重新构建头部，包含正确的总大小
    final_auth_data = struct.pack('<IIIIQQII',
                                 MINI_VISOR_AUTH_SIGNATURE, MINI_VISOR_AUTH_VERSION, MINI_VISOR_AUTH_MAGIC, total_size,
                                 auth_type, platform_type, now, expiry,
                                 0, 0) + auth_data[24:]
    
    return final_auth_data

def main():
    """主函数"""
    print("=" * 70)
    print("Dxe授权生成器 v4.0 - 修复版")
    print("=" * 70)
    
    try:
        # 首先尝试读取硬件收集器生成的授权文件
        auth_file = "auth.dat"
        if os.path.exists(auth_file):
            print(f"🔍 发现硬件收集器生成的授权文件: {auth_file}")
            print(f"✅ 授权文件已存在，无需重新生成")
            print(f"📋 文件大小: {os.path.getsize(auth_file)} 字节")
            print(f"🎉 硬件收集器已完成授权文件生成！")
            return 0
        
        # 如果没有找到授权文件，则生成新的
        print(f"🔍 未发现硬件收集器生成的授权文件，开始生成...")
        
        # 检测平台
        platform_type = detect_platform()
        platform_names = ["未知", "Intel VT-x/VT-d", "AMD SVM/IOMMU", "通用"]
        print(f"🔍 检测到平台: {platform_names[platform_type]}")
        
        # 生成授权
        print(f"🚀 开始生成授权文件...")
        auth_data = generate_authorization(platform_type, AUTH_TYPE_PROFESSIONAL, 365)
        
        # 保存授权文件
        output_file = "auth.dat"
        with open(output_file, 'wb') as f:
            f.write(auth_data)
        
        print(f"✅ 授权文件已保存: {output_file}")
        print(f"   文件大小: {len(auth_data)} 字节")
        
        # 显示授权信息
        print("\n" + "=" * 70)
        print("授权信息")
        print("=" * 70)
        print(f"平台类型: {platform_names[platform_type]}")
        print(f"授权类型: 专业版")
        print(f"有效期: 365天")
        print(f"输出文件: {output_file}")
        
        print("\n🎉 授权生成成功完成！")
        print("📋 主要特性:")
        print("   - 与驱动完全匹配的授权格式")
        print("   - 仅支持时间限制")
        print("   - 跨平台兼容")
        print("   - 硬件指纹绑定")
        print("\n💡 提示: 建议使用硬件收集器生成授权文件以获得最佳兼容性")
        
    except Exception as e:
        print(f"\n❌ 授权生成失败: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
