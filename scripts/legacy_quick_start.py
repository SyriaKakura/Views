#!/usr/bin/env python3
"""
恶意URL检测系统快速启动脚本
"""

import os
import sys
import subprocess
import time
from pathlib import Path

def check_python_version():
    """检查Python版本"""
    if sys.version_info < (3, 8):
        print("❌ 需要Python 3.8或更高版本")
        print(f"当前版本: {sys.version}")
        return False
    print(f"✅ Python版本检查通过: {sys.version.split()[0]}")
    return True

def install_dependencies():
    """安装依赖包"""
    print("\n📦 安装依赖包...")
    
    try:
        # 检查requirements.txt是否存在
        if not Path("requirements.txt").exists():
            print("❌ requirements.txt文件不存在")
            return False
        
        # 安装依赖
        print("正在安装依赖包，这可能需要几分钟...")
        result = subprocess.run([
            sys.executable, "-m", "pip", "install", "-r", "requirements.txt"
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            print("✅ 依赖包安装成功")
            return True
        else:
            print("❌ 依赖包安装失败")
            print("错误信息:", result.stderr)
            return False
            
    except Exception as e:
        print(f"❌ 安装依赖时出错: {e}")
        return False

def generate_sample_data():
    """生成示例训练数据"""
    print("\n📊 生成示例训练数据...")
    
    try:
        if Path("enhanced_malicious_url_training_data.csv").exists():
            print("✅ 训练数据已存在，跳过生成")
            return True
        
        print("正在生成训练数据...")
        result = subprocess.run([
            sys.executable, "generate_training_data.py"
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            print("✅ 训练数据生成成功")
            return True
        else:
            print("❌ 训练数据生成失败")
            print("错误信息:", result.stderr)
            return False
            
    except Exception as e:
        print(f"❌ 生成训练数据时出错: {e}")
        return False

def train_model():
    """训练机器学习模型"""
    print("\n🤖 训练机器学习模型...")
    
    try:
        if Path("artifacts/legacy_models/malicious_url_model.pkl").exists():
            print("✅ 训练好的模型已存在，跳过训练")
            return True
        
        print("正在训练模型，这可能需要几分钟...")
        result = subprocess.run([
            sys.executable, "train_model.py"
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            print("✅ 模型训练成功")
            return True
        else:
            print("❌ 模型训练失败")
            print("错误信息:", result.stderr)
            return False
            
    except Exception as e:
        print(f"❌ 训练模型时出错: {e}")
        return False

def run_demo():
    """运行演示脚本"""
    print("\n🎬 运行系统演示...")
    
    try:
        result = subprocess.run([
            sys.executable, "demo.py"
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            print("✅ 演示运行成功")
            return True
        else:
            print("❌ 演示运行失败")
            print("错误信息:", result.stderr)
            return False
            
    except Exception as e:
        print(f"❌ 运行演示时出错: {e}")
        return False

def start_web_service():
    """启动Web服务"""
    print("\n🌐 启动Web服务...")
    
    try:
        print("正在启动Web服务...")
        print("服务启动后，请访问: http://localhost:5000")
        print("按 Ctrl+C 停止服务")
        
        # 启动Web服务
        result = subprocess.run([
            sys.executable, "run.py"
        ])
        
        if result.returncode == 0:
            print("✅ Web服务正常停止")
            return True
        else:
            print("❌ Web服务异常停止")
            return False
            
    except KeyboardInterrupt:
        print("\n✅ Web服务被用户停止")
        return True
    except Exception as e:
        print(f"❌ 启动Web服务时出错: {e}")
        return False

def show_menu():
    """显示菜单"""
    print("\n" + "="*60)
    print("🔒 恶意URL检测系统 - 快速启动菜单")
    print("="*60)
    print("1. 完整安装和启动 (推荐)")
    print("2. 仅安装依赖")
    print("3. 生成训练数据")
    print("4. 训练模型")
    print("5. 运行演示")
    print("6. 启动Web服务")
    print("7. 退出")
    print("="*60)

def full_setup():
    """完整安装和启动"""
    print("\n🚀 开始完整安装和启动...")
    
    steps = [
        ("检查Python版本", check_python_version),
        ("安装依赖包", install_dependencies),
        ("生成训练数据", generate_sample_data),
        ("训练模型", train_model),
        ("运行演示", run_demo),
        ("启动Web服务", start_web_service)
    ]
    
    for step_name, step_func in steps:
        print(f"\n📋 步骤: {step_name}")
        if not step_func():
            print(f"❌ {step_name}失败，停止安装")
            return False
        print(f"✅ {step_name}完成")
    
    print("\n🎉 完整安装和启动完成！")
    return True

def main():
    """主函数"""
    print("🔒 恶意URL检测系统快速启动")
    print("这个脚本将帮助您快速设置和体验系统")
    
    while True:
        show_menu()
        
        try:
            choice = input("\n请选择操作 (1-7): ").strip()
            
            if choice == "1":
                full_setup()
                break
            elif choice == "2":
                if install_dependencies():
                    print("✅ 依赖安装完成")
                break
            elif choice == "3":
                if generate_sample_data():
                    print("✅ 训练数据生成完成")
                break
            elif choice == "4":
                if train_model():
                    print("✅ 模型训练完成")
                break
            elif choice == "5":
                if run_demo():
                    print("✅ 演示运行完成")
                break
            elif choice == "6":
                start_web_service()
                break
            elif choice == "7":
                print("👋 再见！")
                break
            else:
                print("❌ 无效选择，请输入1-7")
                
        except KeyboardInterrupt:
            print("\n\n👋 再见！")
            break
        except Exception as e:
            print(f"❌ 操作失败: {e}")

if __name__ == "__main__":
    main()
