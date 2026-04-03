from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import json
from app.legacy.detector import MaliciousURLDetector
import logging
from datetime import datetime
import os

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__, template_folder="../../templates")
CORS(app)

# 全局检测器实例
detector = None

@app.route('/')
def index():
    """主页 - 显示恶意URL检测界面"""
    return render_template('legacy_index.html')

def init_detector():
    """初始化检测器"""
    global detector
    try:
        # 尝试加载预训练模型
        if os.path.exists('artifacts/legacy_models/malicious_url_model.pkl'):
            detector = MaliciousURLDetector('artifacts/legacy_models/malicious_url_model.pkl')
            logger.info("预训练模型加载成功")
        else:
            detector = MaliciousURLDetector()
            logger.info("检测器初始化成功（无预训练模型）")
    except Exception as e:
        logger.error(f"检测器初始化失败: {e}")
        detector = MaliciousURLDetector()

@app.route('/health', methods=['GET'])
def health_check():
    """健康检查接口"""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "model_loaded": detector.model is not None
    })

@app.route('/detect', methods=['POST'])
def detect_url():
    """单个URL检测接口"""
    try:
        data = request.get_json()
        
        if not data or 'url' not in data:
            return jsonify({
                "error": "缺少URL参数",
                "status": "error"
            }), 400
        
        url = data['url']
        
        if not url or not isinstance(url, str):
            return jsonify({
                "error": "URL参数无效",
                "status": "error"
            }), 400
        
        logger.info(f"检测URL: {url}")
        
        # 执行检测
        result = detector.predict(url)
        
        if "error" in result:
            return jsonify({
                "error": result["error"],
                "status": "error"
            }), 500
        
        return jsonify({
            "status": "success",
            "result": result
        })
        
    except Exception as e:
        logger.error(f"URL检测错误: {e}")
        return jsonify({
            "error": f"服务器内部错误: {str(e)}",
            "status": "error"
        }), 500

@app.route('/batch_detect', methods=['POST'])
def batch_detect():
    """批量URL检测接口"""
    try:
        data = request.get_json()
        
        if not data or 'urls' not in data:
            return jsonify({
                "error": "缺少URLs参数",
                "status": "error"
            }), 400
        
        urls = data['urls']
        
        if not isinstance(urls, list) or len(urls) == 0:
            return jsonify({
                "error": "URLs参数必须是非空列表",
                "status": "error"
            }), 400
        
        if len(urls) > 100:  # 限制批量检测数量
            return jsonify({
                "error": "批量检测URL数量不能超过100",
                "status": "error"
            }), 400
        
        logger.info(f"批量检测 {len(urls)} 个URL")
        
        # 执行批量检测
        results = detector.batch_predict(urls)
        
        return jsonify({
            "status": "success",
            "total_urls": len(urls),
            "results": results
        })
        
    except Exception as e:
        logger.error(f"批量检测错误: {e}")
        return jsonify({
            "error": f"服务器内部错误: {str(e)}",
            "status": "error"
        }), 500

@app.route('/features', methods=['POST'])
def extract_features():
    """提取URL特征接口"""
    try:
        data = request.get_json()
        
        if not data or 'url' not in data:
            return jsonify({
                "error": "缺少URL参数",
                "status": "error"
            }), 400
        
        url = data['url']
        
        if not url or not isinstance(url, str):
            return jsonify({
                "error": "URL参数无效",
                "status": "error"
            }), 400
        
        logger.info(f"提取URL特征: {url}")
        
        # 提取特征
        features = detector.extract_features(url)
        
        return jsonify({
            "status": "success",
            "url": url,
            "features": features,
            "timestamp": datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"特征提取错误: {e}")
        return jsonify({
            "error": f"服务器内部错误: {str(e)}",
            "status": "error"
        }), 500

@app.route('/train', methods=['POST'])
def train_model():
    """模型训练接口"""
    try:
        data = request.get_json()
        
        if not data or 'training_data_path' not in data:
            return jsonify({
                "error": "缺少训练数据路径参数",
                "status": "error"
            }), 400
        
        training_data_path = data['training_data_path']
        
        if not os.path.exists(training_data_path):
            return jsonify({
                "error": "训练数据文件不存在",
                "status": "error"
            }), 400
        
        logger.info(f"开始训练模型，数据文件: {training_data_path}")
        
        # 训练模型
        detector.train_model(training_data_path)
        
        return jsonify({
            "status": "success",
            "message": "模型训练完成",
            "timestamp": datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"模型训练错误: {e}")
        return jsonify({
            "error": f"模型训练失败: {str(e)}",
            "status": "error"
        }), 500

@app.route('/stats', methods=['GET'])
def get_stats():
    """获取系统统计信息"""
    try:
        stats = {
            "status": "success",
            "timestamp": datetime.now().isoformat(),
            "model_loaded": detector.model is not None,
            "feature_count": len(detector.feature_names),
            "features": detector.feature_names
        }
        
        return jsonify(stats)
        
    except Exception as e:
        logger.error(f"获取统计信息错误: {e}")
        return jsonify({
            "error": f"获取统计信息失败: {str(e)}",
            "status": "error"
        }), 500

@app.errorhandler(404)
def not_found(error):
    """404错误处理"""
    return jsonify({
        "error": "接口不存在",
        "status": "error"
    }), 404

@app.errorhandler(500)
def internal_error(error):
    """500错误处理"""
    return jsonify({
        "error": "服务器内部错误",
        "status": "error"
    }), 500

if __name__ == '__main__':
    # 初始化检测器
    init_detector()
    
    # 启动Flask应用
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=True,
        threaded=True
    )
