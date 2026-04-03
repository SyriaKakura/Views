# 恶意URL检测系统配置文件

import os
from pathlib import Path

# 基础配置
class Config:
    """基础配置类"""
    
    # 项目根目录
    BASE_DIR = Path(__file__).parent
    
    # 模型文件路径
    MODEL_DIR = BASE_DIR / "models"
    DEFAULT_MODEL_PATH = MODEL_DIR / "malicious_url_model.pkl"
    
    # 数据文件路径
    DATA_DIR = BASE_DIR / "data"
    TRAINING_DATA_PATH = DATA_DIR / "enhanced_malicious_url_training_data.csv"
    
    # 日志配置
    LOG_DIR = BASE_DIR / "logs"
    LOG_LEVEL = "INFO"
    LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    
    # Web服务配置
    HOST = "0.0.0.0"
    PORT = 5000
    DEBUG = True
    THREADED = True
    
    # 数据库配置 (如果使用)
    DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///url_detector.db")
    
    # 缓存配置
    CACHE_TYPE = "simple"
    CACHE_DEFAULT_TIMEOUT = 300
    
    # 安全配置
    SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-here")
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB
    
    # 模型配置
    MODEL_CONFIG = {
        "random_forest": {
            "n_estimators": 100,
            "max_depth": None,
            "min_samples_split": 2,
            "min_samples_leaf": 1,
            "random_state": 42
        },
        "gradient_boosting": {
            "n_estimators": 100,
            "learning_rate": 0.1,
            "max_depth": 3,
            "random_state": 42
        },
        "logistic_regression": {
            "max_iter": 1000,
            "random_state": 42
        }
    }
    
    # 特征提取配置
    FEATURE_CONFIG = {
        "suspicious_words": [
            "login", "signin", "bank", "secure", "account", 
            "update", "verify", "download", "install", "update",
            "password", "credit", "card", "pay", "money"
        ],
        "suspicious_tlds": [".tk", ".ml", ".ga", ".cf", ".gq"],
        "suspicious_extensions": [".exe", ".bat", ".cmd", ".scr", ".pif", ".vbs"],
        "shortened_services": [
            "bit.ly", "goo.gl", "tinyurl.com", "is.gd", "v.gd", 
            "t.co", "ow.ly", "su.pr", "twurl.nl", "snipurl.com"
        ]
    }
    
    # 检测阈值配置
    DETECTION_THRESHOLDS = {
        "malicious_confidence": 0.7,  # 恶意检测置信度阈值
        "safe_confidence": 0.8,       # 安全检测置信度阈值
        "suspicious_score": 0.5       # 可疑分数阈值
    }
    
    # 性能配置
    PERFORMANCE_CONFIG = {
        "max_urls_per_batch": 100,    # 批量检测最大URL数量
        "request_timeout": 10,        # 请求超时时间(秒)
        "max_redirects": 5,           # 最大重定向次数
        "cache_ttl": 3600,           # 缓存生存时间(秒)
        "rate_limit": 100             # 每分钟请求限制
    }
    
    # 外部API配置
    EXTERNAL_APIS = {
        "virustotal": {
            "enabled": False,
            "api_key": os.getenv("VIRUSTOTAL_API_KEY", ""),
            "base_url": "https://www.virustotal.com/vtapi/v2/",
            "rate_limit": 4  # 每分钟请求限制
        },
        "phishtank": {
            "enabled": False,
            "api_key": os.getenv("PHISHTANK_API_KEY", ""),
            "base_url": "https://checkurl.phishtank.com/",
            "rate_limit": 10
        },
        "google_safebrowsing": {
            "enabled": False,
            "api_key": os.getenv("GOOGLE_SAFEBROWSING_API_KEY", ""),
            "base_url": "https://safebrowsing.googleapis.com/v4/",
            "rate_limit": 100
        }
    }
    
    # 通知配置
    NOTIFICATIONS = {
        "email": {
            "enabled": False,
            "smtp_server": os.getenv("SMTP_SERVER", ""),
            "smtp_port": int(os.getenv("SMTP_PORT", "587")),
            "username": os.getenv("SMTP_USERNAME", ""),
            "password": os.getenv("SMTP_PASSWORD", ""),
            "from_email": os.getenv("FROM_EMAIL", ""),
            "to_emails": os.getenv("TO_EMAILS", "").split(",") if os.getenv("TO_EMAILS") else []
        },
        "slack": {
            "enabled": False,
            "webhook_url": os.getenv("SLACK_WEBHOOK_URL", ""),
            "channel": os.getenv("SLACK_CHANNEL", "#security-alerts")
        }
    }

class DevelopmentConfig(Config):
    """开发环境配置"""
    DEBUG = True
    LOG_LEVEL = "DEBUG"
    
    # 开发环境特定配置
    MODEL_CONFIG = {
        "random_forest": {
            "n_estimators": 50,  # 减少树的数量以加快训练
            "max_depth": 10,
            "min_samples_split": 5,
            "min_samples_leaf": 2,
            "random_state": 42
        }
    }

class ProductionConfig(Config):
    """生产环境配置"""
    DEBUG = False
    LOG_LEVEL = "WARNING"
    HOST = "0.0.0.0"
    PORT = int(os.getenv("PORT", 5000))
    
    # 生产环境安全配置
    SECRET_KEY = os.getenv("SECRET_KEY", "default-secret-key-for-development")
    
    # 生产环境性能配置
    PERFORMANCE_CONFIG = {
        "max_urls_per_batch": 50,
        "request_timeout": 5,
        "max_redirects": 3,
        "cache_ttl": 1800,
        "rate_limit": 50
    }

class TestingConfig(Config):
    """测试环境配置"""
    TESTING = True
    DEBUG = True
    LOG_LEVEL = "DEBUG"
    
    # 测试环境使用内存数据库
    DATABASE_URL = "sqlite:///:memory:"
    
    # 测试环境模型配置
    MODEL_CONFIG = {
        "random_forest": {
            "n_estimators": 10,
            "max_depth": 5,
            "min_samples_split": 2,
            "min_samples_leaf": 1,
            "random_state": 42
        }
    }

# 配置映射
config_map = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
    "default": DevelopmentConfig
}

def get_config(config_name=None):
    """获取配置实例"""
    if config_name is None:
        config_name = os.getenv("FLASK_ENV", "default")
    
    config_class = config_map.get(config_name, DevelopmentConfig)
    return config_class()

def create_directories():
    """创建必要的目录"""
    config = get_config()
    
    directories = [
        config.MODEL_DIR,
        config.DATA_DIR,
        config.LOG_DIR
    ]
    
    for directory in directories:
        directory.mkdir(parents=True, exist_ok=True)
        print(f"目录已创建: {directory}")

def validate_config():
    """验证配置有效性"""
    config = get_config()
    
    # 检查必要的环境变量
    if config.DEBUG is False:
        if not config.SECRET_KEY or config.SECRET_KEY == "your-secret-key-here":
            raise ValueError("生产环境必须设置有效的SECRET_KEY")
    
    # 检查外部API配置
    for api_name, api_config in config.EXTERNAL_APIS.items():
        if api_config["enabled"] and not api_config["api_key"]:
            print(f"警告: {api_name} API已启用但未设置API密钥")
    
    print("配置验证通过")

if __name__ == "__main__":
    # 创建目录
    create_directories()
    
    # 验证配置
    validate_config()
    
    # 显示当前配置
    config = get_config()
    print(f"\n当前配置:")
    print(f"环境: {os.getenv('FLASK_ENV', 'development')}")
    print(f"主机: {config.HOST}")
    print(f"端口: {config.PORT}")
    print(f"调试模式: {config.DEBUG}")
    print(f"模型目录: {config.MODEL_DIR}")
    print(f"数据目录: {config.DATA_DIR}")
