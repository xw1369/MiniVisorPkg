#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Hypervisor授权生成器 v4.0 - 图形界面版
====================================

功能特性:
- 图形用户界面
- 拖拽文件支持
- 自动平台检测
- 实时预览
- 一键生成授权

作者: Hypervisor开发团队
版本: 4.0
日期: 2024
"""

import os
import sys
import struct
import hashlib
import json
import threading
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any
import platform
import subprocess

try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox, scrolledtext
    from tkinter import font as tkfont
except ImportError:
    print("❌ 错误: 需要tkinter支持")
    print("请安装Python的tkinter模块")
    input("按回车键退出...")
    sys.exit(1)

# 平台类型定义
PLATFORM_UNKNOWN = 0
PLATFORM_INTEL = 1
PLATFORM_AMD = 2
PLATFORM_UNIVERSAL = 3

# 授权类型定义
AUTH_TYPE_BASIC = 1
AUTH_TYPE_PROFESSIONAL = 2
AUTH_TYPE_ENTERPRISE = 3

# 兼容性权重定义
COMPAT_WEIGHT_CPU_FAMILY = 150
COMPAT_WEIGHT_CPU_MODEL = 120
COMPAT_WEIGHT_CPU_FEATURES = 100
COMPAT_WEIGHT_CHIPSET = 80
COMPAT_WEIGHT_BIOS = 60
COMPAT_WEIGHT_MAINBOARD = 70
COMPAT_WEIGHT_VMX_SVM = 200
COMPAT_WEIGHT_IOMMU = 150
COMPAT_WEIGHT_SECURITY = 100

@dataclass
class HardwareFingerprint:
    """硬件指纹结构"""
    cpu_signature: int = 0
    cpu_family: int = 0
    cpu_model: int = 0
    cpu_stepping: int = 0
    cpu_features: int = 0
    chipset_model_hash: int = 0
    bios_version_hash: int = 0
    mainboard_serial_hash: int = 0
    memory_config_hash: int = 0
    topology_hash: int = 0
    security_features: int = 0
    virtualization_support: int = 0
    iommu_support: int = 0
    tpm_version: int = 0
    secure_boot_status: int = 0
    platform_type: int = PLATFORM_UNKNOWN

@dataclass
class Authorization:
    """授权结构 - 仅支持时间限制，移除使用次数限制"""
    magic: int = 0x4D564155  # "MVAU"
    version: int = 0x0400    # v4.0
    auth_type: int = AUTH_TYPE_PROFESSIONAL
    platform: int = PLATFORM_UNKNOWN
    creation_time: int = 0
    expiry_time: int = 0
    # 移除 activation_limit 和 current_activations
    # 仅保留时间限制
    hardware_fingerprint: HardwareFingerprint = None
    signature: bytes = b''

    def __post_init__(self):
        if self.hardware_fingerprint is None:
            self.hardware_fingerprint = HardwareFingerprint()
        if self.creation_time == 0:
            self.creation_time = int(datetime.now().timestamp())
        if self.expiry_time == 0:
            # 默认一年有效期
            self.expiry_time = self.creation_time + (365 * 24 * 3600)
    
    def is_expired(self) -> bool:
        """检查授权是否过期"""
        current_time = int(datetime.now().timestamp())
        return current_time > self.expiry_time
    
    def get_remaining_days(self) -> int:
        """获取剩余天数"""
        current_time = int(datetime.now().timestamp())
        remaining_seconds = self.expiry_time - current_time
        return max(0, remaining_seconds // (24 * 3600))

class AuthorizationGenerator:
    """授权生成器 - 统一验证逻辑"""
    
    def __init__(self):
        # 平台特定密钥
        self.platform_key = b'HypervisorAuthKey2024'
        
    def generate_hardware_fingerprint(self, bin_file_path: str) -> HardwareFingerprint:
        """从bin文件生成硬件指纹"""
        try:
            with open(bin_file_path, 'rb') as f:
                data = f.read()
            
            # 解析硬件信息
            if len(data) < 64:
                raise ValueError("硬件信息文件格式无效")
            
            # 解析硬件指纹数据
            fingerprint = HardwareFingerprint()
            
            # 从bin文件解析硬件信息
            # 这里假设bin文件包含硬件信息的二进制数据
            # 实际实现需要根据具体的bin文件格式进行解析
            
            # 示例解析逻辑（需要根据实际格式调整）
            if len(data) >= 64:
                # 解析CPU信息
                fingerprint.cpu_signature = struct.unpack('<I', data[0:4])[0]
                fingerprint.cpu_family = struct.unpack('<I', data[4:8])[0]
                fingerprint.cpu_model = struct.unpack('<I', data[8:12])[0]
                fingerprint.cpu_stepping = struct.unpack('<I', data[12:16])[0]
                fingerprint.cpu_features = struct.unpack('<I', data[16:20])[0]
                
                # 解析平台信息
                fingerprint.chipset_model_hash = struct.unpack('<I', data[20:24])[0]
                fingerprint.bios_version_hash = struct.unpack('<I', data[24:28])[0]
                fingerprint.mainboard_serial_hash = struct.unpack('<I', data[28:32])[0]
                
                # 解析内存和拓扑信息
                fingerprint.memory_config_hash = struct.unpack('<I', data[32:36])[0]
                fingerprint.topology_hash = struct.unpack('<I', data[36:40])[0]
                
                # 解析安全和虚拟化信息
                fingerprint.security_features = struct.unpack('<I', data[40:44])[0]
                fingerprint.virtualization_support = struct.unpack('<I', data[44:48])[0]
                fingerprint.iommu_support = struct.unpack('<I', data[48:52])[0]
                
                # 解析TPM和安全启动信息
                fingerprint.tpm_version = struct.unpack('<I', data[52:56])[0]
                fingerprint.secure_boot_status = struct.unpack('<I', data[56:60])[0]
                fingerprint.platform_type = struct.unpack('<I', data[60:64])[0]
            
            return fingerprint
            
        except Exception as e:
            raise RuntimeError(f"无法解析硬件信息文件: {e}")
    
    def _generate_signature(self, auth: Authorization, bin_data: bytes) -> bytes:
        """生成授权签名 - 统一验证逻辑"""
        # 构建签名数据
        sign_data = struct.pack('<IIIIII', 
                               auth.magic, auth.version, auth.auth_type, auth.platform,
                               auth.creation_time, auth.expiry_time)
        
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
    
    def save_authorization(self, auth: Authorization, output_path: str):
        """保存授权文件 - 统一格式"""
        # 构建授权数据
        auth_data = struct.pack('<IIIIII', 
                               auth.magic, auth.version, auth.auth_type, auth.platform,
                               auth.creation_time, auth.expiry_time)
        
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
        
        # 添加签名
        auth_data += hw_data + auth.signature
        
        # 保存文件
        with open(output_path, 'wb') as f:
            f.write(auth_data)

class HypervisorGUI:
    """Hypervisor图形界面"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Hypervisor授权生成器 v4.0")
        self.root.geometry("800x600")
        self.root.resizable(True, True)
        
        # 设置图标（如果有的话）
        try:
            self.root.iconbitmap("icon.ico")
        except:
            pass
        
        # 初始化变量
        self.bin_file_path = tk.StringVar()
        self.output_file_path = tk.StringVar()
        self.auth_type = tk.StringVar(value="professional")
        self.expiry_days = tk.IntVar(value=365)
        # 移除激活限制相关变量
        
        # 创建界面
        self.create_widgets()
        
        # 支持拖拽
        self.setup_drag_drop()
    
    def create_widgets(self):
        """创建界面组件"""
        # 主框架
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # 配置网格权重
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        
        # 标题
        title_label = ttk.Label(main_frame, text="Hypervisor授权生成器 v4.0", 
                               font=tkfont.Font(size=16, weight="bold"))
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))
        
        # 文件选择区域
        file_frame = ttk.LabelFrame(main_frame, text="文件选择", padding="10")
        file_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        file_frame.columnconfigure(1, weight=1)
        
        ttk.Label(file_frame, text="硬件信息文件:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        ttk.Entry(file_frame, textvariable=self.bin_file_path, width=50).grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 5))
        ttk.Button(file_frame, text="浏览", command=self.browse_bin_file).grid(row=0, column=2)
        
        ttk.Label(file_frame, text="输出文件:").grid(row=1, column=0, sticky=tk.W, padx=(0, 5), pady=(10, 0))
        ttk.Entry(file_frame, textvariable=self.output_file_path, width=50).grid(row=1, column=1, sticky=(tk.W, tk.E), padx=(0, 5), pady=(10, 0))
        ttk.Button(file_frame, text="浏览", command=self.browse_output_file).grid(row=1, column=2, pady=(10, 0))
        
        # 参数设置区域
        param_frame = ttk.LabelFrame(main_frame, text="授权参数", padding="10")
        param_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        param_frame.columnconfigure(1, weight=1)
        
        ttk.Label(param_frame, text="授权类型:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        auth_combo = ttk.Combobox(param_frame, textvariable=self.auth_type, 
                                 values=["basic", "professional", "enterprise"], 
                                 state="readonly", width=15)
        auth_combo.grid(row=0, column=1, sticky=tk.W, padx=(0, 20))
        
        ttk.Label(param_frame, text="有效期(天):").grid(row=0, column=2, sticky=tk.W, padx=(0, 5))
        ttk.Spinbox(param_frame, from_=1, to=3650, textvariable=self.expiry_days, width=10).grid(row=0, column=3, sticky=tk.W)
        
        # 移除激活限制相关控件
        
        # 操作按钮
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=3, column=0, columnspan=3, pady=(0, 10))
        
        ttk.Button(button_frame, text="生成授权", command=self.generate_auth, 
                  style="Accent.TButton").pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(button_frame, text="清空", command=self.clear_all).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(button_frame, text="退出", command=self.root.quit).pack(side=tk.LEFT)
        
        # 日志区域
        log_frame = ttk.LabelFrame(main_frame, text="操作日志", padding="10")
        log_frame.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        main_frame.rowconfigure(4, weight=1)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=15, width=80)
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # 状态栏
        self.status_var = tk.StringVar(value="就绪")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN)
        status_bar.grid(row=5, column=0, columnspan=3, sticky=(tk.W, tk.E))
    
    def setup_drag_drop(self):
        """设置拖拽支持"""
        # 简化版本，不支持拖拽
        pass
    
    def on_drop(self, event):
        """处理文件拖拽"""
        # 简化版本，不支持拖拽
        pass
    
    def browse_bin_file(self):
        """浏览bin文件"""
        file_path = filedialog.askopenfilename(
            title="选择硬件信息文件",
            filetypes=[("Bin文件", "*.bin"), ("所有文件", "*.*")]
        )
        if file_path:
            self.bin_file_path.set(file_path)
            self.update_output_path()
    
    def browse_output_file(self):
        """浏览输出文件"""
        file_path = filedialog.asksaveasfilename(
            title="保存授权文件",
            defaultextension=".dat",
            filetypes=[("授权文件", "*.dat"), ("所有文件", "*.*")]
        )
        if file_path:
            self.output_file_path.set(file_path)
    
    def update_output_path(self):
        """更新输出文件路径"""
        bin_path = self.bin_file_path.get()
        if bin_path:
            base_name = os.path.splitext(os.path.basename(bin_path))[0]
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = f"{base_name}_auth_{timestamp}.dat"
            self.output_file_path.set(output_path)
    
    def log_message(self, message: str):
        """添加日志消息"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        self.log_text.insert(tk.END, log_entry)
        self.log_text.see(tk.END)
        self.root.update_idletasks()
    
    def generate_auth(self):
        """生成授权文件"""
        try:
            # 验证输入
            if not self.bin_file_path.get():
                messagebox.showerror("错误", "请选择硬件信息文件")
                return
            
            if not self.output_file_path.get():
                messagebox.showerror("错误", "请选择输出文件路径")
                return
            
            # 更新状态
            self.status_var.set("正在生成授权...")
            self.log_message("开始生成授权文件...")
            
            # 创建授权生成器
            generator = AuthorizationGenerator()
            
            # 生成硬件指纹
            self.log_message("正在解析硬件信息...")
            fingerprint = generator.generate_hardware_fingerprint(self.bin_file_path.get())
            self.log_message("硬件指纹生成完成")
            
            # 创建授权
            auth = Authorization()
            auth.hardware_fingerprint = fingerprint
            auth.auth_type = {"basic": AUTH_TYPE_BASIC, 
                            "professional": AUTH_TYPE_PROFESSIONAL, 
                            "enterprise": AUTH_TYPE_ENTERPRISE}[self.auth_type.get()]
            
            # 设置时间限制
            auth.creation_time = int(datetime.now().timestamp())
            auth.expiry_time = auth.creation_time + (self.expiry_days.get() * 24 * 3600)
            
            # 生成签名
            self.log_message("正在生成数字签名...")
            auth.signature = generator._generate_signature(auth, b'')
            self.log_message("数字签名生成完成")
            
            # 保存授权文件
            self.log_message("正在保存授权文件...")
            generator.save_authorization(auth, self.output_file_path.get())
            self.log_message(f"授权文件已保存: {self.output_file_path.get()}")
            
            # 显示授权信息
            expiry_date = datetime.fromtimestamp(auth.expiry_time).strftime("%Y-%m-%d %H:%M:%S")
            self.log_message(f"授权有效期至: {expiry_date}")
            self.log_message(f"授权类型: {self.auth_type.get()}")
            
            # 更新状态
            self.status_var.set("授权生成完成")
            messagebox.showinfo("成功", "授权文件生成成功！")
            
        except Exception as e:
            error_msg = f"生成授权失败: {e}"
            self.log_message(f"❌ {error_msg}")
            self.status_var.set("生成失败")
            messagebox.showerror("错误", error_msg)
    
    def clear_all(self):
        """清空所有输入"""
        self.bin_file_path.set("")
        self.output_file_path.set("")
        self.auth_type.set("professional")
        self.expiry_days.set(365)
        self.log_text.delete(1.0, tk.END)
        self.status_var.set("就绪")
        self.log_message("所有输入已清空")
    
    def run(self):
        """运行GUI"""
        self.root.mainloop()

def main():
    """主函数"""
    try:
        app = HypervisorGUI()
        app.run()
    except Exception as e:
        print(f"程序启动失败: {e}")
        input("按回车键退出...")

if __name__ == "__main__":
    main()
