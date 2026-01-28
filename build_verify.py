#!/usr/bin/env python3
"""
MiniVisor Package Build Verification Script
验证 MiniVisor 包的构建配置和依赖关系

This script checks for common build issues and validates the package configuration.
此脚本检查常见的构建问题并验证包配置。
"""

import os
import sys
import re
from pathlib import Path

def check_file_exists(file_path, description):
    """Check if a file exists and report status"""
    if os.path.exists(file_path):
        print(f"✓ {description}: {file_path}")
        return True
    else:
        print(f"✗ {description}: {file_path} (NOT FOUND)")
        return False

def validate_inf_file(inf_path):
    """Validate an INF file for common issues"""
    print(f"\n检查 INF 文件: {inf_path}")
    
    if not os.path.exists(inf_path):
        print(f"✗ INF 文件不存在: {inf_path}")
        return False
    
    required_sections = ['[Defines]', '[Sources]', '[Packages]', '[LibraryClasses]']
    found_sections = []
    
    with open(inf_path, 'r', encoding='utf-8') as f:
        content = f.read()
        for section in required_sections:
            if section in content:
                found_sections.append(section)
                print(f"  ✓ 找到必需段: {section}")
            else:
                print(f"  ✗ 缺少必需段: {section}")
    
    return len(found_sections) == len(required_sections)

def validate_dsc_file(dsc_path):
    """Validate DSC file for build configuration"""
    print(f"\n检查 DSC 文件: {dsc_path}")
    
    if not os.path.exists(dsc_path):
        print(f"✗ DSC 文件不存在: {dsc_path}")
        return False
    
    required_sections = ['[Defines]', '[LibraryClasses]', '[Components]', '[BuildOptions]']
    issues = []
    
    with open(dsc_path, 'r', encoding='utf-8') as f:
        content = f.read()
        
        for section in required_sections:
            if section in content:
                print(f"  ✓ 找到必需段: {section}")
            else:
                print(f"  ✗ 缺少必需段: {section}")
                issues.append(f"Missing section: {section}")
        
        # Check for duplicate PCD definitions
        pcd_lines = [line.strip() for line in content.split('\n') if '|' in line and 'gMiniVisorPkgTokenSpaceGuid' in line]
        pcd_names = [line.split('|')[0].strip() for line in pcd_lines]
        duplicates = [name for name in set(pcd_names) if pcd_names.count(name) > 1]
        
        if duplicates:
            print(f"  ⚠ 发现重复的 PCD 定义: {', '.join(duplicates)}")
            issues.append(f"Duplicate PCDs: {duplicates}")
        else:
            print("  ✓ 没有发现重复的 PCD 定义")
    
    return len(issues) == 0

def check_source_files():
    """Check if all source files referenced in INF files exist"""
    print("\n检查源文件...")
    
    base_path = Path('.')
    inf_files = list(base_path.rglob('*.inf'))
    missing_files = []
    
    for inf_file in inf_files:
        print(f"\n检查 {inf_file} 中引用的源文件:")
        
        with open(inf_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Extract source files from [Sources] section
        sources_match = re.search(r'\[Sources[^\]]*\](.*?)(?=\[|\Z)', content, re.DOTALL)
        if sources_match:
            sources_section = sources_match.group(1)
            source_files = [line.strip() for line in sources_section.split('\n') 
                          if line.strip() and not line.strip().startswith('#')]
            
            for source_file in source_files:
                # Handle [Sources.X64] and other architecture-specific files
                if source_file and not source_file.startswith('['):
                    source_path = inf_file.parent / source_file
                    if source_path.exists():
                        print(f"  ✓ {source_file}")
                    else:
                        print(f"  ✗ {source_file} (NOT FOUND)")
                        missing_files.append(str(source_path))
    
    return len(missing_files) == 0

def validate_build_configuration():
    """Main validation function"""
    print("MiniVisor 包构建验证开始...")
    print("=" * 50)
    
    issues = []
    
    # Check for essential package files
    print("\n1. 检查包文件结构:")
    essential_files = [
        ('MiniVisorPkg.dec', 'Package Declaration'),
        ('MiniVisorPkg.dsc', 'Package Description'),
        ('Drivers/MiniVisorDxe/MiniVisorDxe.inf', 'Main Driver INF'),
        ('Tools/HardwareCollector/HardwareCollector.inf', 'Hardware Collector INF'),
    ]
    
    for file_path, description in essential_files:
        if not check_file_exists(file_path, description):
            issues.append(f"Missing essential file: {file_path}")
    
    # Validate INF files
    print("\n2. 验证 INF 文件:")
    inf_files = [
        'Drivers/MiniVisorDxe/MiniVisorDxe.inf',
        'Tools/HardwareCollector/HardwareCollector.inf',
        'Tools/HardwareCollector/HardwareCollector_Simple.inf'
    ]
    
    for inf_file in inf_files:
        if os.path.exists(inf_file):
            if not validate_inf_file(inf_file):
                issues.append(f"INF validation failed: {inf_file}")
        else:
            issues.append(f"INF file not found: {inf_file}")
    
    # Validate DSC file
    print("\n3. 验证 DSC 文件:")
    if not validate_dsc_file('MiniVisorPkg.dsc'):
        issues.append("DSC validation failed")
    
    # Check source files
    print("\n4. 验证源文件:")
    if not check_source_files():
        issues.append("Source file validation failed")
    
    # Report results
    print("\n" + "=" * 50)
    print("验证结果:")
    
    if len(issues) == 0:
        print("✓ 所有验证通过! 包配置看起来正确。")
        print("✓ All validations passed! Package configuration looks correct.")
        return True
    else:
        print(f"✗ 发现 {len(issues)} 个问题:")
        print(f"✗ Found {len(issues)} issues:")
        for issue in issues:
            print(f"  - {issue}")
        return False

if __name__ == "__main__":
    success = validate_build_configuration()
    sys.exit(0 if success else 1)
