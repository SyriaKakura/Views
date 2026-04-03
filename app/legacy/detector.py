import re
import numpy as np
import pandas as pd
from urllib.parse import urlparse, parse_qs
import tldextract
import whois
import dns.resolver
import socket
import requests
from datetime import datetime
import time
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import warnings
warnings.filterwarnings('ignore')

class MaliciousURLDetector:
    def __init__(self, model_path=None):
        """
        初始化恶意URL检测器
        
        Args:
            model_path: 预训练模型的路径
        """
        self.model = None
        self.feature_names = [
            'url_length', 'domain_length', 'path_length', 'query_length',
            'fragment_length', 'subdomain_count', 'special_char_count',
            'digit_count', 'letter_count', 'suspicious_words_count',
            'ip_in_domain', 'shortened_url', 'suspicious_tld',
            'domain_age_days', 'ssl_certificate', 'redirect_count',
            'suspicious_extension', 'url_depth', 'avg_word_length',
            'entropy', 'suspicious_patterns'
        ]
        
        if model_path:
            self.load_model(model_path)
    
    def extract_features(self, url):
        """
        从URL中提取特征
        
        Args:
            url: 要分析的URL
            
        Returns:
            dict: 特征字典
        """
        try:
            parsed = urlparse(url)
            extracted = tldextract.extract(url)
            
            features = {}
            
            # 基本长度特征
            features['url_length'] = len(url)
            features['domain_length'] = len(extracted.domain)
            features['path_length'] = len(parsed.path)
            features['query_length'] = len(parsed.query)
            features['fragment_length'] = len(parsed.fragment)
            
            # 子域名特征
            features['subdomain_count'] = len(extracted.subdomain.split('.')) if extracted.subdomain else 0
            
            # 字符特征
            features['special_char_count'] = len(re.findall(r'[^a-zA-Z0-9]', url))
            features['digit_count'] = len(re.findall(r'\d', url))
            features['letter_count'] = len(re.findall(r'[a-zA-Z]', url))
            
            # 可疑词汇检测
            suspicious_words = ['login', 'signin', 'bank', 'secure', 'account', 'update', 'verify']
            features['suspicious_words_count'] = sum(1 for word in suspicious_words if word.lower() in url.lower())
            
            # IP地址检测
            features['ip_in_domain'] = 1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0
            
            # 短链接检测
            features['shortened_url'] = 1 if any(service in url.lower() for service in ['bit.ly', 'goo.gl', 'tinyurl']) else 0
            
            # 可疑顶级域名
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq']
            features['suspicious_tld'] = 1 if any(tld in url.lower() for tld in suspicious_tlds) else 0
            
            # 域名年龄
            try:
                domain_info = whois.whois(extracted.domain + '.' + extracted.suffix)
                if domain_info.creation_date:
                    if isinstance(domain_info.creation_date, list):
                        creation_date = domain_info.creation_date[0]
                    else:
                        creation_date = domain_info.creation_date
                    age_days = (datetime.now() - creation_date).days
                    features['domain_age_days'] = age_days
                else:
                    features['domain_age_days'] = 0
            except:
                features['domain_age_days'] = 0
            
            # SSL证书检测
            try:
                if parsed.scheme == 'https':
                    features['ssl_certificate'] = 1
                else:
                    features['ssl_certificate'] = 0
            except:
                features['ssl_certificate'] = 0
            
            # 重定向检测
            try:
                response = requests.head(url, timeout=5, allow_redirects=False)
                features['redirect_count'] = len(response.history)
            except:
                features['redirect_count'] = 0
            
            # 可疑扩展名
            suspicious_extensions = ['.exe', '.bat', '.cmd', '.scr', '.pif']
            features['suspicious_extension'] = 1 if any(ext in url.lower() for ext in suspicious_extensions) else 0
            
            # URL深度
            features['url_depth'] = len([x for x in parsed.path.split('/') if x])
            
            # 平均词长度
            words = re.findall(r'[a-zA-Z]+', url)
            if words:
                features['avg_word_length'] = np.mean([len(word) for word in words])
            else:
                features['avg_word_length'] = 0
            
            # 熵值计算
            features['entropy'] = self._calculate_entropy(url)
            
            # 可疑模式
            suspicious_patterns = [
                r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP地址
                r'[0-9a-fA-F]{32}',  # MD5哈希
                r'[0-9a-fA-F]{40}',  # SHA1哈希
                r'[0-9a-fA-F]{64}'   # SHA256哈希
            ]
            features['suspicious_patterns'] = sum(1 for pattern in suspicious_patterns if re.search(pattern, url))
            
            return features
            
        except Exception as e:
            print(f"特征提取错误: {e}")
            return {name: 0 for name in self.feature_names}
    
    def _calculate_entropy(self, text):
        """计算字符串的熵值"""
        if not text:
            return 0
        
        # 计算字符频率
        freq = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1
        
        # 计算熵值
        entropy = 0
        length = len(text)
        for count in freq.values():
            probability = count / length
            entropy -= probability * np.log2(probability)
        
        return entropy
    
    def prepare_features(self, url):
        """准备模型输入特征"""
        features = self.extract_features(url)
        feature_vector = [features[name] for name in self.feature_names]
        return np.array(feature_vector).reshape(1, -1)
    
    def train_model(self, training_data_path):
        """
        训练机器学习模型
        
        Args:
            training_data_path: 训练数据文件路径
        """
        try:
            # 加载训练数据
            data = pd.read_csv(training_data_path)
            
            # 分离特征和标签
            X = data[self.feature_names]
            y = data['label']  # 假设标签列名为'label'
            
            # 分割训练集和测试集
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
            
            # 训练随机森林模型
            self.model = RandomForestClassifier(n_estimators=100, random_state=42)
            self.model.fit(X_train, y_train)
            
            # 评估模型
            y_pred = self.model.predict(X_test)
            print("✅ 模型训练完成!")
            print("\n📊 分类报告:")
            print(classification_report(y_test, y_pred, target_names=['安全', '恶意']))
            
            # 保存模型
            joblib.dump(self.model, 'malicious_url_model.pkl')
            print("💾 模型已保存到 'malicious_url_model.pkl'")
            
        except Exception as e:
            print(f"模型训练错误: {e}")
    
    def load_model(self, model_path):
        """加载预训练模型"""
        try:
            self.model = joblib.load(model_path)
            print(f"模型已从 {model_path} 加载")
        except Exception as e:
            print(f"模型加载错误: {e}")
    
    def predict(self, url):
        """
        预测URL是否为恶意URL
        
        Args:
            url: 要检测的URL
            
        Returns:
            dict: 预测结果和置信度
        """
        if self.model is None:
            return {"error": "模型未加载，请先训练或加载模型"}
        
        try:
            features = self.prepare_features(url)
            prediction = self.model.predict(features)[0]
            probability = self.model.predict_proba(features)[0]
            
            result = {
                "url": url,
                "is_malicious": bool(prediction),
                "confidence": float(max(probability)),
                "features": dict(zip(self.feature_names, features[0])),
                "timestamp": datetime.now().isoformat()
            }
            
            return result
            
        except Exception as e:
            return {"error": f"预测错误: {e}"}
    
    def batch_predict(self, urls):
        """
        批量预测多个URL
        
        Args:
            urls: URL列表
            
        Returns:
            list: 预测结果列表
        """
        results = []
        for url in urls:
            result = self.predict(url)
            results.append(result)
        return results

def main():
    """主函数 - 演示系统使用"""
    print("恶意URL检测系统")
    print("=" * 50)
    
    # 创建检测器实例
    detector = MaliciousURLDetector()
    
    # 示例URL
    test_urls = [
        "https://www.google.com",
        "http://malicious-site.tk/login",
        "https://bit.ly/suspicious-link",
        "http://192.168.1.1/admin",
        "https://www.microsoft.com/update"
    ]
    
    print("\n🔍 测试URL检测:")
    for url in test_urls:
        result = detector.predict(url)
        if "error" not in result:
            status = "恶意" if result["is_malicious"] else "安全"
            confidence = result["confidence"] * 100
            print(f"🌐 URL: {url}")
            print(f"📊 状态: {status} (置信度: {confidence:.2f}%)")
            print("-" * 30)
        else:
            print(f"URL: {url}")
            print(f"错误: {result['error']}")
            print("-" * 30)

if __name__ == "__main__":
    main()
