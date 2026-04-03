#!/usr/bin/env python3
"""
恶意URL检测系统启动脚本
"""

import os
import sys
import argparse
import logging
from pathlib import Path
from app.legacy.config import get_config, create_directories, validate_config
from app.legacy.detector import MaliciousURLDetector
import joblib

def setup_logging(config):
    """设置日志系统"""
    log_dir = config.LOG_DIR
    log_dir.mkdir(parents=True, exist_ok=True)
    
    # 配置日志格式
    logging.basicConfig(
        level=getattr(logging, config.LOG_LEVEL),
        format=config.LOG_FORMAT,
        handlers=[
            logging.FileHandler(log_dir / "url_detector.log"),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    logger = logging.getLogger(__name__)
    logger.info("日志系统初始化完成")
    return logger

def initialize_detector(config, logger):
    """初始化检测器"""
    logger.info("正在初始化URL检测器...")
    
    try:
        # 尝试加载预训练模型
        model_path = config.DEFAULT_MODEL_PATH
        
        if model_path.exists():
            logger.info(f"发现预训练模型: {model_path}")
            detector = MaliciousURLDetector(str(model_path))
            logger.info("预训练模型加载成功")
        else:
            logger.warning("未发现预训练模型，将使用基础检测器")
            detector = MaliciousURLDetector()
            
            # 检查是否有其他模型文件
            model_files = list(config.MODEL_DIR.glob("*.pkl"))
            if model_files:
                logger.info(f"发现其他模型文件: {[f.name for f in model_files]}")
                # 尝试加载第一个可用的模型
                try:
                    detector.load_model(str(model_files[0]))
                    logger.info(f"成功加载模型: {model_files[0].name}")
                except Exception as e:
                    logger.warning(f"加载模型失败: {e}")
        
        return detector
        
    except Exception as e:
        logger.error(f"检测器初始化失败: {e}")
        logger.info("将使用基础检测器（无机器学习模型）")
        return MaliciousURLDetector()

def check_dependencies():
    """检查系统依赖"""
    required_packages = [
        'numpy', 'pandas', 'scikit-learn', 'requests', 
        'urllib3', 'tldextract', 'python-whois', 'dnspython',
        'joblib', 'matplotlib', 'seaborn', 'flask', 'flask-cors'
    ]
    
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        print("❌ 缺少以下依赖包:")
        for package in missing_packages:
            print(f"   - {package}")
        print("\n请运行以下命令安装依赖:")
        print("pip install -r requirements.txt")
        return False
    
    print("✅ 所有依赖包检查通过")
    return True

def start_web_service(config, detector, logger):
    """启动Web服务"""
    try:
        from app.legacy.flask_app import app
        
        # 设置全局检测器
        app.detector = detector
        
        logger.info(f"启动Web服务: {config.HOST}:{config.PORT}")
        logger.info(f"调试模式: {config.DEBUG}")
        
        # 启动Flask应用
        app.run(
            host=config.HOST,
            port=config.PORT,
            debug=config.DEBUG,
            threaded=config.THREADED
        )
        
    except ImportError as e:
        logger.error(f"无法导入Flask应用: {e}")
        print("❌ Flask应用启动失败")
        return False
    except Exception as e:
        logger.error(f"Web服务启动失败: {e}")
        print(f"❌ Web服务启动失败: {e}")
        return False

def start_cli_mode(config, detector, logger):
    """启动命令行模式"""
    logger.info("启动命令行模式")
    
    print("\n🔒 恶意URL检测系统 - 命令行模式")
    print("=" * 50)
    print("输入 'help' 查看可用命令")
    print("输入 'quit' 退出系统")
    print("=" * 50)
    
    while True:
        try:
            command = input("\n> ").strip().lower()
            
            if command == 'quit' or command == 'exit':
                print("再见！")
                break
            elif command == 'help':
                print_help()
            elif command == 'detect':
                url = input("请输入要检测的URL: ").strip()
                if url:
                    result = detector.predict(url)
                    if "error" not in result:
                        status = "恶意" if result["is_malicious"] else "安全"
                        confidence = result["confidence"] * 100
                        print(f"检测结果: {status} (置信度: {confidence:.2f}%)")
                    else:
                        print(f"检测错误: {result['error']}")
                else:
                    print("URL不能为空")
            elif command == 'features':
                url = input("请输入要分析特征的URL: ").strip()
                if url:
                    features = detector.extract_features(url)
                    print("URL特征:")
                    for name, value in features.items():
                        print(f"  {name}: {value}")
                else:
                    print("URL不能为空")
            elif command == 'stats':
                print(f"模型状态: {'已加载' if detector.model else '未加载'}")
                print(f"特征数量: {len(detector.feature_names)}")
                print(f"支持的特征: {', '.join(detector.feature_names)}")
            elif command == 'test':
                run_quick_test(detector)
            else:
                print("未知命令，输入 'help' 查看可用命令")
                
        except KeyboardInterrupt:
            print("\n\n再见！")
            break
        except Exception as e:
            print(f"命令执行错误: {e}")

def print_help():
    """打印帮助信息"""
    print("\n可用命令:")
    print("  detect   - 检测单个URL")
    print("  features - 提取URL特征")
    print("  stats    - 显示系统状态")
    print("  test     - 运行快速测试")
    print("  help     - 显示此帮助信息")
    print("  quit     - 退出系统")

def run_quick_test(detector):
    """运行快速测试"""
    print("\n🔍 运行快速测试...")
    
    test_urls = [
        'https://www.google.com',
        'http://malware.tk/download',
        'https://www.microsoft.com',
        'http://phishing.ml/login'
    ]
    
    for url in test_urls:
        try:
            result = detector.predict(url)
            if "error" not in result:
                status = "恶意" if result["is_malicious"] else "安全"
                confidence = result["confidence"] * 100
                print(f"✅ {url}: {status} (置信度: {confidence:.2f}%)")
            else:
                print(f"❌ {url}: {result['error']}")
        except Exception as e:
            print(f"❌ {url}: 测试失败 - {e}")

def main():
    """主函数"""
    parser = argparse.ArgumentParser(description="恶意URL检测系统")
    parser.add_argument('--mode', choices=['web', 'cli'], default='web',
                       help='运行模式: web(Web服务) 或 cli(命令行)')
    parser.add_argument('--config', default=None,
                       help='配置文件环境 (development, production, testing)')
    parser.add_argument('--port', type=int, default=None,
                       help='Web服务端口')
    parser.add_argument('--host', default=None,
                       help='Web服务主机')
    parser.add_argument('--debug', action='store_true',
                       help='启用调试模式')
    
    args = parser.parse_args()
    
    # 设置环境变量
    if args.config:
        os.environ['FLASK_ENV'] = args.config
    
    # 获取配置
    try:
        config = get_config()
        
        # 覆盖配置参数
        if args.port:
            config.PORT = args.port
        if args.host:
            config.HOST = args.host
        if args.debug:
            config.DEBUG = args.debug
        
        # 创建必要目录
        create_directories()
        
        # 验证配置
        validate_config()
        
    except Exception as e:
        print(f"❌ 配置错误: {e}")
        sys.exit(1)
    
    # 检查依赖
    if not check_dependencies():
        sys.exit(1)
    
    # 设置日志
    logger = setup_logging(config)
    
    # 初始化检测器
    detector = initialize_detector(config, logger)
    
    # 根据模式启动
    if args.mode == 'web':
        start_web_service(config, detector, logger)
    else:
        start_cli_mode(config, detector, logger)

if __name__ == "__main__":
    main()
