import pandas as pd
import numpy as np
from app.legacy.detector import MaliciousURLDetector
import random
import time
from datetime import datetime, timedelta

def generate_safe_urls():
    """生成安全的URL示例"""
    safe_domains = [
        'google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'facebook.com',
        'twitter.com', 'linkedin.com', 'github.com', 'stackoverflow.com', 'wikipedia.org',
        'youtube.com', 'netflix.com', 'spotify.com', 'dropbox.com', 'slack.com',
        'zoom.us', 'salesforce.com', 'adobe.com', 'oracle.com', 'ibm.com'
    ]
    
    safe_paths = [
        '', '/', '/about', '/contact', '/help', '/support', '/privacy', '/terms',
        '/products', '/services', '/blog', '/news', '/download', '/login', '/signup'
    ]
    
    safe_urls = []
    for _ in range(500):  # 生成500个安全URL
        domain = random.choice(safe_domains)
        path = random.choice(safe_paths)
        scheme = random.choice(['https://', 'http://'])
        
        # 随机添加查询参数
        if random.random() > 0.7:
            params = ['id', 'page', 'category', 'lang', 'ref']
            param = random.choice(params)
            value = random.randint(1, 1000)
            path += f'?{param}={value}'
        
        url = f"{scheme}www.{domain}{path}"
        safe_urls.append(url)
    
    return safe_urls

def generate_malicious_urls():
    """生成恶意URL示例"""
    malicious_patterns = [
        # 可疑的顶级域名
        'malware.tk', 'phishing.ml', 'scam.ga', 'virus.cf', 'trojan.gq',
        'malicious.tk', 'dangerous.ml', 'infected.ga', 'hacked.cf',
        
        # IP地址直接访问
        '192.168.1.100', '10.0.0.1', '172.16.0.1', '8.8.8.8',
        
        # 可疑的子域名
        'login.bank-secure.com', 'verify.account-update.com', 'secure.banking.com',
        'update.software.com', 'download.file.com', 'install.program.com',
        
        # 短链接服务
        'bit.ly/malicious', 'goo.gl/suspicious', 'tinyurl.com/dangerous',
        'is.gd/evil', 'v.gd/malware', 't.co/harmful',
        
        # 可疑的路径
        'malware.com/download.exe', 'virus.com/install.bat', 'trojan.com/run.cmd',
        'phishing.com/login.php', 'scam.com/verify.html', 'hack.com/admin.php',
        
        # 包含哈希的URL
        'malware.com/file/abc123def456', 'virus.com/download/1234567890abcdef',
        'trojan.com/install/a1b2c3d4e5f6',
        
        # 可疑的查询参数
        'malware.com?redirect=evil.com', 'virus.com?goto=malicious.com',
        'trojan.com?url=phishing.com', 'scam.com?link=dangerous.com'
    ]
    
    malicious_urls = []
    for _ in range(500):  # 生成500个恶意URL
        base = random.choice(malicious_patterns)
        
        # 随机添加更多可疑元素
        if random.random() > 0.5:
            suspicious_words = ['secure', 'bank', 'login', 'verify', 'update', 'download']
            word = random.choice(suspicious_words)
            base = f"{word}.{base}"
        
        if random.random() > 0.6:
            base = f"http://{base}"  # 使用HTTP而不是HTTPS
        
        if random.random() > 0.7:
            base += f"?id={random.randint(1000, 9999)}"
        
        malicious_urls.append(base)
    
    return malicious_urls

def create_training_dataset():
    """创建完整的训练数据集"""
    print("正在生成训练数据...")
    
    # 生成URL
    safe_urls = generate_safe_urls()
    malicious_urls = generate_malicious_urls()
    
    print(f"生成了 {len(safe_urls)} 个安全URL")
    print(f"生成了 {len(malicious_urls)} 个恶意URL")
    
    # 创建检测器实例
    detector = MaliciousURLDetector()
    
    # 提取特征
    all_urls = safe_urls + malicious_urls
    all_labels = [0] * len(safe_urls) + [1] * len(malicious_urls)  # 0=安全, 1=恶意
    
    print("正在提取URL特征...")
    print(f"总共需要处理 {len(all_urls)} 个URL")
    
    features_list = []
    start_time = time.time()
    
    for i, url in enumerate(all_urls):
        # 每10个URL显示一次进度
        if i % 10 == 0:
            elapsed_time = time.time() - start_time
            if i > 0:
                avg_time_per_url = elapsed_time / i
                remaining_urls = len(all_urls) - i
                estimated_time = remaining_urls * avg_time_per_url
                print(f"处理进度: {i}/{len(all_urls)} ({i/len(all_urls)*100:.1f}%) - "
                      f"已用时间: {elapsed_time:.1f}秒 - "
                      f"预计剩余时间: {estimated_time:.1f}秒")
            else:
                print(f"处理进度: {i}/{len(all_urls)} ({i/len(all_urls)*100:.1f}%) - 开始处理...")
        
        try:
            features = detector.extract_features(url)
            features_list.append(features)
        except Exception as e:
            print(f"⚠️  处理URL时出错: {url[:50]}..., 错误: {e}")
            # 使用默认特征
            features = {name: 0 for name in detector.feature_names}
            features_list.append(features)
    
    total_time = time.time() - start_time
    print(f"✅ 特征提取完成！总用时: {total_time:.1f}秒，平均每个URL: {total_time/len(all_urls):.3f}秒")
    
    # 创建DataFrame
    df = pd.DataFrame(features_list)
    df['label'] = all_labels
    df['url'] = all_urls
    
    # 重新排列列顺序
    columns = ['url'] + detector.feature_names + ['label']
    df = df[columns]
    
    # 保存数据集
    filename = 'data/legacy/malicious_url_training_data.csv'
    df.to_csv(filename, index=False)
    
    print(f"\n训练数据集已保存到: {filename}")
    print(f"数据集形状: {df.shape}")
    print(f"安全URL数量: {len(safe_urls)}")
    print(f"恶意URL数量: {len(malicious_urls)}")
    
    # 显示数据集统计信息
    print("\n数据集统计信息:")
    print(df.describe())
    
    return filename

def generate_realistic_malicious_urls():
    """生成更真实的恶意URL示例"""
    realistic_malicious = [
        # 钓鱼网站
        'http://login-bank-secure.com/verify',
        'https://account-update-microsoft.com/login',
        'http://secure-paypal-verify.com/account',
        'https://amazon-secure-login.com/verify',
        
        # 恶意软件下载
        'http://download-software-update.com/install.exe',
        'https://system-update-required.com/download.bat',
        'http://security-patch-urgent.com/update.cmd',
        'https://driver-update-required.com/install.scr',
        
        # 可疑的短链接
        'https://bit.ly/2xK9mN3',
        'http://goo.gl/abc123',
        'https://tinyurl.com/suspicious-link',
        'http://is.gd/malicious-redirect',
        
        # 包含IP地址的恶意URL
        'http://192.168.1.100/admin',
        'https://10.0.0.1/login',
        'http://172.16.0.1/verify',
        'https://8.8.8.8/secure',
        
        # 可疑的顶级域名
        'http://malware-detection.tk/scan',
        'https://virus-removal.ml/clean',
        'http://trojan-removal.ga/remove',
        'https://phishing-protection.cf/check',
        
        # 包含哈希的恶意URL
        'http://malware.com/file/a1b2c3d4e5f6',
        'https://virus.com/download/1234567890abcdef',
        'http://trojan.com/install/abcdef1234567890',
        
        # 重定向到恶意网站
        'http://legitimate-site.com/redirect?url=malware.com',
        'https://safe-website.com/goto?link=phishing.com',
        'http://trusted-site.com/forward?to=scam.com'
    ]
    
    return realistic_malicious

def create_enhanced_training_dataset():
    """创建增强的训练数据集"""
    print("正在创建增强的训练数据集...")
    
    # 生成基础URL
    safe_urls = generate_safe_urls()
    basic_malicious = generate_malicious_urls()
    realistic_malicious = generate_realistic_malicious_urls()
    
    # 合并恶意URL
    all_malicious = basic_malicious + realistic_malicious
    
    print(f"生成了 {len(safe_urls)} 个安全URL")
    print(f"生成了 {len(all_malicious)} 个恶意URL")
    
    # 创建检测器实例
    detector = MaliciousURLDetector()
    
    # 提取特征
    all_urls = safe_urls + all_malicious
    all_labels = [0] * len(safe_urls) + [1] * len(all_malicious)
    
    print("正在提取URL特征...")
    print(f"总共需要处理 {len(all_urls)} 个URL")
    
    features_list = []
    start_time = time.time()
    
    for i, url in enumerate(all_urls):
        # 每10个URL显示一次进度
        if i % 10 == 0:
            elapsed_time = time.time() - start_time
            if i > 0:
                avg_time_per_url = elapsed_time / i
                remaining_urls = len(all_urls) - i
                estimated_time = remaining_urls * avg_time_per_url
                print(f"处理进度: {i}/{len(all_urls)} ({i/len(all_urls)*100:.1f}%) - "
                      f"已用时间: {elapsed_time:.1f}秒 - "
                      f"预计剩余时间: {estimated_time:.1f}秒")
            else:
                print(f"处理进度: {i}/{len(all_urls)} ({i/len(all_urls)*100:.1f}%) - 开始处理...")
        
        try:
            features = detector.extract_features(url)
            features_list.append(features)
        except Exception as e:
            print(f"⚠️  处理URL时出错: {url[:50]}..., 错误: {e}")
            features = {name: 0 for name in detector.feature_names}
            features_list.append(features)
    
    total_time = time.time() - start_time
    print(f"✅ 特征提取完成！总用时: {total_time:.1f}秒，平均每个URL: {total_time/len(all_urls):.3f}秒")
    
    # 创建DataFrame
    df = pd.DataFrame(features_list)
    df['label'] = all_labels
    df['url'] = all_urls
    
    # 重新排列列顺序
    columns = ['url'] + detector.feature_names + ['label']
    df = df[columns]
    
    # 保存数据集
    filename = 'data/legacy/enhanced_malicious_url_training_data.csv'
    df.to_csv(filename, index=False)
    
    print(f"\n增强训练数据集已保存到: {filename}")
    print(f"数据集形状: {df.shape}")
    print(f"安全URL数量: {len(safe_urls)}")
    print(f"恶意URL数量: {len(all_malicious)}")
    
    return filename

if __name__ == "__main__":
    print("恶意URL检测系统 - 训练数据生成器")
    print("=" * 50)
    
    # 创建基础训练数据集
    basic_file = create_training_dataset()
    
    print("\n" + "=" * 50)
    
    # 创建增强训练数据集
    enhanced_file = create_enhanced_training_dataset()
    
    print("\n训练数据生成完成!")
    print(f"基础数据集: {basic_file}")
    print(f"增强数据集: {enhanced_file}")
    print("\n现在可以使用这些数据集来训练模型了!")
