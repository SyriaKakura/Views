#!/usr/bin/env python3
"""
恶意URL检测系统演示脚本
"""

import time
from app.legacy.detector import MaliciousURLDetector

def demo_basic_detection():
    """演示基本检测功能"""
    print("🔒 恶意URL检测系统演示")
    print("=" * 50)
    
    # 创建检测器实例
    detector = MaliciousURLDetector()
    
    # 测试URL列表
    test_urls = [
        ("https://www.google.com", "安全URL"),
        ("https://www.microsoft.com", "安全URL"),
        ("https://www.github.com", "安全URL"),
        ("http://malware.tk/download", "恶意URL"),
        ("https://phishing.ml/login", "恶意URL"),
        ("http://scam.ga/verify", "恶意URL"),
        ("http://192.168.1.100/admin", "恶意URL"),
        ("https://bit.ly/suspicious-link", "可疑URL"),
        ("http://malware.com/file.exe", "恶意URL"),
        ("https://www.example.com", "安全URL")
    ]
    
    print("开始URL检测演示...\n")
    
    for i, (url, expected) in enumerate(test_urls, 1):
        print(f"测试 {i}: {url}")
        print(f"预期: {expected}")
        
        try:
            # 提取特征
            features = detector.extract_features(url)
            print(f"特征数量: {len(features)}")
            
            # 显示几个关键特征
            key_features = ['url_length', 'domain_length', 'ssl_certificate', 'suspicious_words_count']
            for feature in key_features:
                if feature in features:
                    print(f"  {feature}: {features[feature]}")
            
            # 如果有模型，进行预测
            if detector.model:
                result = detector.predict(url)
                if "error" not in result:
                    status = "恶意" if result["is_malicious"] else "安全"
                    confidence = result["confidence"] * 100
                    print(f"预测结果: {status} (置信度: {confidence:.2f}%)")
                else:
                    print(f"预测错误: {result['error']}")
            else:
                print("未加载模型，无法进行预测")
            
            print("-" * 40)
            time.sleep(0.5)  # 添加延迟以便观察
            
        except Exception as e:
            print(f"处理错误: {e}")
            print("-" * 40)

def demo_feature_analysis():
    """演示特征分析功能"""
    print("\n🔬 URL特征分析演示")
    print("=" * 50)
    
    detector = MaliciousURLDetector()
    
    # 分析一个复杂的URL
    complex_url = "https://login-bank-secure-verify.tk/download/update.exe?redirect=malware.com&id=12345"
    
    print(f"分析URL: {complex_url}")
    print("\n详细特征分析:")
    
    try:
        features = detector.extract_features(complex_url)
        
        # 按类别分组显示特征
        feature_categories = {
            "长度特征": ['url_length', 'domain_length', 'path_length', 'query_length'],
            "字符特征": ['special_char_count', 'digit_count', 'letter_count'],
            "域名特征": ['subdomain_count', 'suspicious_tld', 'domain_age_days'],
            "安全特征": ['ssl_certificate', 'redirect_count', 'suspicious_extension'],
            "模式特征": ['suspicious_words_count', 'ip_in_domain', 'shortened_url', 'suspicious_patterns']
        }
        
        for category, feature_list in feature_categories.items():
            print(f"\n{category}:")
            for feature in feature_list:
                if feature in features:
                    value = features[feature]
                    # 添加描述性说明
                    if feature == 'suspicious_tld' and value == 1:
                        print(f"  {feature}: {value} (可疑顶级域名)")
                    elif feature == 'ssl_certificate' and value == 1:
                        print(f"  {feature}: {value} (使用HTTPS)")
                    elif feature == 'suspicious_words_count' and value > 0:
                        print(f"  {feature}: {value} (包含可疑词汇)")
                    elif feature == 'ip_in_domain' and value == 1:
                        print(f"  {feature}: {value} (域名包含IP地址)")
                    else:
                        print(f"  {feature}: {value}")
        
        # 计算风险评分
        risk_score = 0
        risk_factors = []
        
        if features.get('suspicious_tld', 0) == 1:
            risk_score += 30
            risk_factors.append("可疑顶级域名")
        
        if features.get('ip_in_domain', 0) == 1:
            risk_score += 25
            risk_factors.append("域名包含IP地址")
        
        if features.get('suspicious_words_count', 0) > 0:
            risk_score += features['suspicious_words_count'] * 10
            risk_factors.append("包含可疑词汇")
        
        if features.get('shortened_url', 0) == 1:
            risk_score += 20
            risk_factors.append("短链接服务")
        
        if features.get('suspicious_extension', 0) == 1:
            risk_score += 35
            risk_factors.append("可疑文件扩展名")
        
        risk_score = min(risk_score, 100)  # 限制最大分数
        
        print(f"\n风险评估:")
        print(f"风险评分: {risk_score}/100")
        if risk_factors:
            print(f"风险因素: {', '.join(risk_factors)}")
        
        if risk_score >= 70:
            print("风险等级: 🔴 高风险")
        elif risk_score >= 40:
            print("风险等级: 🟡 中等风险")
        else:
            print("风险等级: 🟢 低风险")
            
    except Exception as e:
        print(f"特征分析错误: {e}")

def demo_performance():
    """演示性能测试"""
    print("\n⚡ 性能测试演示")
    print("=" * 50)
    
    detector = MaliciousURLDetector()
    
    # 生成测试URL
    test_urls = [f"https://example{i}.com/path?param={i}" for i in range(100)]
    
    print(f"测试 {len(test_urls)} 个URL的检测性能...")
    
    start_time = time.time()
    
    for i, url in enumerate(test_urls):
        try:
            features = detector.extract_features(url)
            if i % 20 == 0:  # 每20个显示进度
                print(f"处理进度: {i}/{len(test_urls)}")
        except Exception as e:
            print(f"处理URL {i} 时出错: {e}")
    
    end_time = time.time()
    total_time = end_time - start_time
    avg_time = total_time / len(test_urls) * 1000  # 转换为毫秒
    
    print(f"\n性能测试结果:")
    print(f"总处理时间: {total_time:.2f} 秒")
    print(f"平均处理时间: {avg_time:.2f} 毫秒/URL")
    print(f"处理速度: {len(test_urls)/total_time:.1f} URL/秒")

def main():
    """主演示函数"""
    print("🚀 恶意URL检测系统完整演示")
    print("=" * 60)
    
    try:
        # 1. 基本检测演示
        demo_basic_detection()
        
        # 2. 特征分析演示
        demo_feature_analysis()
        
        # 3. 性能测试演示
        demo_performance()
        
        print("\n" + "=" * 60)
        print("🎉 演示完成！")
        print("\n系统功能总结:")
        print("✅ URL特征提取 (21种特征)")
        print("✅ 机器学习检测 (支持多种算法)")
        print("✅ 实时风险评估")
        print("✅ 高性能处理")
        print("✅ Web界面和API接口")
        print("✅ 完整的训练和测试工具")
        
        print("\n下一步:")
        print("1. 运行 'python generate_training_data.py' 生成训练数据")
        print("2. 运行 'python train_model.py' 训练模型")
        print("3. 运行 'python run.py' 启动Web服务")
        print("4. 访问 http://localhost:5000 使用Web界面")
        
    except KeyboardInterrupt:
        print("\n\n演示被用户中断")
    except Exception as e:
        print(f"\n演示过程中出现错误: {e}")

if __name__ == "__main__":
    main()
