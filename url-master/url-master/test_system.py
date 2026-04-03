import requests
import json
import time
from url_detector import MaliciousURLDetector
import pandas as pd

class MaliciousURLTester:
    def __init__(self, api_base="http://localhost:5000"):
        """初始化测试器"""
        self.api_base = api_base
        self.detector = MaliciousURLDetector()
        
        # 测试URL集合
        self.test_urls = {
            'safe': [
                'https://www.google.com',
                'https://www.microsoft.com',
                'https://www.apple.com',
                'https://www.amazon.com',
                'https://www.github.com',
                'https://www.stackoverflow.com',
                'https://www.wikipedia.org',
                'https://www.youtube.com',
                'https://www.netflix.com',
                'https://www.spotify.com'
            ],
            'malicious': [
                'http://malware.tk/download',
                'https://phishing.ml/login',
                'http://scam.ga/verify',
                'https://virus.cf/install',
                'http://trojan.gq/update',
                'http://192.168.1.100/admin',
                'https://bit.ly/suspicious-link',
                'http://malware.com/file.exe',
                'https://phishing.com/login.php',
                'http://scam.com/verify.html'
            ],
            'edge_cases': [
                'https://www.example.com',
                'http://localhost:8080',
                'ftp://files.example.com',
                'mailto:test@example.com',
                'javascript:alert("test")',
                'data:text/html,<script>alert("test")</script>',
                'file:///etc/passwd',
                'about:blank',
                'chrome://settings/',
                'moz-extension://test'
            ]
        }
    
    def test_api_health(self):
        """测试API健康状态"""
        print("🔍 测试API健康状态...")
        try:
            response = requests.get(f"{self.api_base}/health", timeout=10)
            if response.status_code == 200:
                data = response.json()
                print(f"✅ API健康检查通过")
                print(f"   状态: {data['status']}")
                print(f"   模型加载: {data['model_loaded']}")
                return True
            else:
                print(f"❌ API健康检查失败: {response.status_code}")
                return False
        except Exception as e:
            print(f"❌ API健康检查异常: {e}")
            return False
    
    def test_single_detection(self):
        """测试单个URL检测"""
        print("\n🔍 测试单个URL检测...")
        
        test_cases = [
            ('https://www.google.com', '安全URL'),
            ('http://malware.tk/download', '恶意URL'),
            ('https://www.microsoft.com', '安全URL'),
            ('http://phishing.ml/login', '恶意URL')
        ]
        
        results = []
        for url, expected in test_cases:
            try:
                response = requests.post(
                    f"{self.api_base}/detect",
                    json={'url': url},
                    timeout=10
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if data['status'] == 'success':
                        result = data['result']
                        status = "恶意" if result['is_malicious'] else "安全"
                        confidence = result['confidence']
                        
                        print(f"✅ {url}")
                        print(f"   预期: {expected}")
                        print(f"   结果: {status} (置信度: {confidence:.2f})")
                        
                        results.append({
                            'url': url,
                            'expected': expected,
                            'actual': status,
                            'confidence': confidence,
                            'success': True
                        })
                    else:
                        print(f"❌ {url}: API返回错误")
                        results.append({
                            'url': url,
                            'expected': expected,
                            'actual': 'error',
                            'confidence': 0,
                            'success': False
                        })
                else:
                    print(f"❌ {url}: HTTP {response.status_code}")
                    results.append({
                        'url': url,
                        'expected': expected,
                        'actual': 'http_error',
                        'confidence': 0,
                        'success': False
                    })
                    
            except Exception as e:
                print(f"❌ {url}: 异常 {e}")
                results.append({
                    'url': url,
                    'expected': expected,
                    'actual': 'exception',
                    'confidence': 0,
                    'success': False
                })
        
        return results
    
    def test_batch_detection(self):
        """测试批量URL检测"""
        print("\n🔍 测试批量URL检测...")
        
        # 混合安全和不安全的URL
        test_urls = self.test_urls['safe'][:5] + self.test_urls['malicious'][:5]
        
        try:
            response = requests.post(
                f"{self.api_base}/batch_detect",
                json={'urls': test_urls},
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                if data['status'] == 'success':
                    results = data['results']
                    print(f"✅ 批量检测成功，处理了 {len(results)} 个URL")
                    
                    # 统计结果
                    safe_count = sum(1 for r in results if not r.get('is_malicious', False))
                    malicious_count = sum(1 for r in results if r.get('is_malicious', False))
                    error_count = sum(1 for r in results if 'error' in r)
                    
                    print(f"   安全URL: {safe_count}")
                    print(f"   恶意URL: {malicious_count}")
                    print(f"   错误: {error_count}")
                    
                    return True
                else:
                    print(f"❌ 批量检测失败: {data.get('error', '未知错误')}")
                    return False
            else:
                print(f"❌ 批量检测HTTP错误: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"❌ 批量检测异常: {e}")
            return False
    
    def test_feature_extraction(self):
        """测试特征提取"""
        print("\n🔍 测试特征提取...")
        
        test_url = 'https://www.example.com/path?param=value'
        
        try:
            response = requests.post(
                f"{self.api_base}/features",
                json={'url': test_url},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                if data['status'] == 'success':
                    features = data['features']
                    print(f"✅ 特征提取成功")
                    print(f"   URL: {test_url}")
                    print(f"   特征数量: {len(features)}")
                    
                    # 显示几个关键特征
                    key_features = ['url_length', 'domain_length', 'ssl_certificate', 'suspicious_words_count']
                    for feature in key_features:
                        if feature in features:
                            print(f"   {feature}: {features[feature]}")
                    
                    return True
                else:
                    print(f"❌ 特征提取失败: {data.get('error', '未知错误')}")
                    return False
            else:
                print(f"❌ 特征提取HTTP错误: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"❌ 特征提取异常: {e}")
            return False
    
    def test_system_stats(self):
        """测试系统统计信息"""
        print("\n🔍 测试系统统计信息...")
        
        try:
            response = requests.get(f"{self.api_base}/stats", timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if data['status'] == 'success':
                    print(f"✅ 系统统计获取成功")
                    print(f"   模型加载: {data['model_loaded']}")
                    print(f"   特征数量: {data['feature_count']}")
                    print(f"   更新时间: {data['timestamp']}")
                    return True
                else:
                    print(f"❌ 系统统计获取失败: {data.get('error', '未知错误')}")
                    return False
            else:
                print(f"❌ 系统统计HTTP错误: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"❌ 系统统计异常: {e}")
            return False
    
    def test_local_detector(self):
        """测试本地检测器"""
        print("\n🔍 测试本地检测器...")
        
        if self.detector.model is None:
            print("⚠️  本地检测器没有加载模型，跳过测试")
            return False
        
        test_results = []
        for category, urls in self.test_urls.items():
            print(f"\n   测试 {category} URL:")
            for url in urls[:3]:  # 每个类别测试前3个
                try:
                    result = self.detector.predict(url)
                    if "error" not in result:
                        status = "恶意" if result["is_malicious"] else "安全"
                        confidence = result["confidence"]
                        print(f"     ✅ {url}: {status} (置信度: {confidence:.2f})")
                        test_results.append({
                            'url': url,
                            'category': category,
                            'status': status,
                            'confidence': confidence,
                            'success': True
                        })
                    else:
                        print(f"     ❌ {url}: {result['error']}")
                        test_results.append({
                            'url': url,
                            'category': category,
                            'status': 'error',
                            'confidence': 0,
                            'success': False
                        })
                except Exception as e:
                    print(f"     ❌ {url}: 异常 {e}")
                    test_results.append({
                        'url': url,
                        'category': category,
                        'status': 'exception',
                        'confidence': 0,
                        'success': False
                    })
        
        return test_results
    
    def test_performance(self):
        """测试性能"""
        print("\n🔍 测试系统性能...")
        
        # 测试单个URL检测性能
        test_url = 'https://www.example.com'
        times = []
        
        print("   测试单个URL检测响应时间...")
        for i in range(10):
            start_time = time.time()
            try:
                response = requests.post(
                    f"{self.api_base}/detect",
                    json={'url': test_url},
                    timeout=10
                )
                end_time = time.time()
                response_time = (end_time - start_time) * 1000  # 转换为毫秒
                times.append(response_time)
                
                if i < 5:  # 只显示前5次的结果
                    print(f"     第{i+1}次: {response_time:.2f}ms")
                    
            except Exception as e:
                print(f"     第{i+1}次: 失败 - {e}")
        
        if times:
            avg_time = sum(times) / len(times)
            min_time = min(times)
            max_time = max(times)
            
            print(f"   平均响应时间: {avg_time:.2f}ms")
            print(f"   最快响应时间: {min_time:.2f}ms")
            print(f"   最慢响应时间: {max_time:.2f}ms")
            
            return {
                'avg_response_time': avg_time,
                'min_response_time': min_time,
                'max_response_time': max_time,
                'test_count': len(times)
            }
        
        return None
    
    def run_all_tests(self):
        """运行所有测试"""
        print("🚀 开始运行恶意URL检测系统测试")
        print("=" * 60)
        
        test_results = {}
        
        # 1. API健康检查
        test_results['api_health'] = self.test_api_health()
        
        # 2. 单个URL检测
        test_results['single_detection'] = self.test_single_detection()
        
        # 3. 批量URL检测
        test_results['batch_detection'] = self.test_batch_detection()
        
        # 4. 特征提取
        test_results['feature_extraction'] = self.test_feature_extraction()
        
        # 5. 系统统计
        test_results['system_stats'] = self.test_system_stats()
        
        # 6. 本地检测器
        test_results['local_detector'] = self.test_local_detector()
        
        # 7. 性能测试
        test_results['performance'] = self.test_performance()
        
        # 生成测试报告
        self.generate_test_report(test_results)
        
        return test_results
    
    def generate_test_report(self, test_results):
        """生成测试报告"""
        print("\n" + "=" * 60)
        print("📊 测试报告")
        print("=" * 60)
        
        # 统计测试结果
        total_tests = 0
        passed_tests = 0
        
        for test_name, result in test_results.items():
            if isinstance(result, bool):
                total_tests += 1
                if result:
                    passed_tests += 1
                    print(f"✅ {test_name}: 通过")
                else:
                    print(f"❌ {test_name}: 失败")
            elif isinstance(result, list):
                if result:
                    total_tests += 1
                    success_count = sum(1 for r in result if r.get('success', False))
                    if success_count > 0:
                        passed_tests += 1
                        print(f"✅ {test_name}: 通过 ({success_count}/{len(result)})")
                    else:
                        print(f"❌ {test_name}: 失败")
                else:
                    print(f"⚠️  {test_name}: 无结果")
            elif isinstance(result, dict):
                total_tests += 1
                passed_tests += 1
                print(f"✅ {test_name}: 通过")
            else:
                print(f"⚠️  {test_name}: 未知结果类型")
        
        print(f"\n测试总结: {passed_tests}/{total_tests} 通过")
        
        if passed_tests == total_tests:
            print("🎉 所有测试通过！系统运行正常。")
        else:
            print("⚠️  部分测试失败，请检查系统配置。")

def main():
    """主函数"""
    print("恶意URL检测系统 - 系统测试器")
    print("请确保Web API服务正在运行 (python app.py)")
    print("=" * 60)
    
    # 创建测试器实例
    tester = MaliciousURLTester()
    
    # 运行所有测试
    results = tester.run_all_tests()
    
    print("\n测试完成！")

if __name__ == "__main__":
    main()
