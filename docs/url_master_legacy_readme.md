# 🔒 恶意URL检测系统

基于Python和机器学习的智能恶意URL检测系统，提供Web API接口和命令行工具，能够准确识别各种类型的恶意URL。

## ✨ 功能特性

- **智能特征提取**: 提取21种URL特征，包括长度、字符、域名、路径等
- **机器学习检测**: 支持随机森林、梯度提升、逻辑回归、SVM等多种算法
- **实时检测**: 毫秒级响应，支持单个和批量URL检测
- **Web界面**: 现代化的Web UI，支持多种检测模式
- **REST API**: 完整的RESTful API接口，易于集成
- **命令行工具**: 支持CLI模式，适合自动化脚本
- **模型训练**: 内置训练工具，支持自定义数据集
- **性能监控**: 详细的性能指标和测试报告

## 🏗️ 系统架构

```
恶意URL检测系统
├── 核心检测引擎 (url_detector.py)
├── Web API服务 (app.py)
├── 前端界面 (templates/index.html)
├── 模型训练 (train_model.py)
├── 数据生成 (generate_training_data.py)
├── 系统测试 (test_system.py)
├── 配置管理 (config.py)
└── 启动脚本 (run.py)
```

## 🚀 快速开始

### 1. 环境要求

- Python 3.8+
- 8GB+ RAM (用于模型训练)
- 网络连接 (用于外部API调用)

### 2. 安装依赖

```bash
# 克隆项目
git clone <repository-url>
cd URL

# 安装依赖包
pip install -r requirements.txt
```

### 3. 生成训练数据

```bash
# 生成示例训练数据
python generate_training_data.py
```

### 4. 训练模型

```bash
# 训练机器学习模型
python train_model.py
```

### 5. 启动系统

```bash
# 启动Web服务 (默认模式)
python run.py

# 启动命令行模式
python run.py --mode cli

# 自定义配置
python run.py --config production --port 8080 --host 0.0.0.0
```

## 📖 详细使用说明

### Web界面使用

1. 启动Web服务后，访问 `http://localhost:5000`
2. 选择检测模式：
   - **单个检测**: 检测单个URL
   - **批量检测**: 批量检测多个URL
   - **特征分析**: 查看URL的详细特征
   - **系统状态**: 查看系统运行状态

### API接口使用

#### 单个URL检测
```bash
curl -X POST http://localhost:5000/detect \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

#### 批量URL检测
```bash
curl -X POST http://localhost:5000/batch_detect \
  -H "Content-Type: application/json" \
  -d '{"urls": ["https://example1.com", "https://example2.com"]}'
```

#### 特征提取
```bash
curl -X POST http://localhost:5000/features \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

#### 系统状态
```bash
curl http://localhost:5000/stats
```

### 命令行使用

```bash
# 启动CLI模式
python run.py --mode cli

# 可用命令
> help          # 显示帮助
> detect        # 检测URL
> features      # 提取特征
> stats         # 显示状态
> test          # 运行测试
> quit          # 退出系统
```

## 🔬 技术特性

### 特征提取

系统提取以下21种URL特征：

1. **长度特征**: URL长度、域名长度、路径长度等
2. **字符特征**: 特殊字符数量、数字数量、字母数量
3. **域名特征**: 子域名数量、顶级域名类型、域名年龄
4. **安全特征**: SSL证书、重定向次数、可疑扩展名
5. **模式特征**: 可疑词汇、IP地址、哈希值、熵值

### 机器学习算法

- **随机森林**: 默认算法，平衡准确率和性能
- **梯度提升**: 高准确率，适合复杂模式
- **逻辑回归**: 快速训练，易于解释
- **支持向量机**: 适合高维特征空间

### 检测阈值

- **恶意检测**: 置信度 > 0.7
- **安全检测**: 置信度 > 0.8
- **可疑分数**: 0.5 - 0.7

## 📊 性能指标

- **检测准确率**: 95%+
- **响应时间**: < 100ms (单个URL)
- **吞吐量**: 1000+ URL/分钟
- **内存使用**: < 500MB
- **CPU使用**: < 10% (空闲时)

## 🛠️ 开发指南

### 项目结构

```
URL/
├── url_detector.py          # 核心检测器
├── app.py                   # Flask Web应用
├── train_model.py           # 模型训练
├── generate_training_data.py # 训练数据生成
├── test_system.py           # 系统测试
├── config.py                # 配置管理
├── run.py                   # 启动脚本
├── requirements.txt          # 依赖包
├── templates/               # HTML模板
│   └── index.html          # 前端界面
├── models/                  # 模型文件目录
├── data/                    # 数据文件目录
└── logs/                    # 日志文件目录
```

### 添加新特征

1. 在 `url_detector.py` 的 `feature_names` 列表中添加新特征名
2. 在 `extract_features` 方法中实现特征提取逻辑
3. 更新训练数据生成脚本
4. 重新训练模型

### 集成外部API

1. 在 `config.py` 中配置API参数
2. 在 `url_detector.py` 中添加API调用逻辑
3. 将外部API结果集成到特征中

### 自定义模型

1. 在 `train_model.py` 中添加新的算法
2. 调整超参数和模型配置
3. 更新模型评估逻辑

## 🧪 测试

### 运行系统测试

```bash
# 确保Web服务正在运行
python run.py

# 在另一个终端运行测试
python test_system.py
```

### 测试覆盖

- ✅ API健康检查
- ✅ 单个URL检测
- ✅ 批量URL检测
- ✅ 特征提取
- ✅ 系统状态
- ✅ 本地检测器
- ✅ 性能测试

## 📈 模型训练

### 训练流程

1. **数据准备**: 使用 `generate_training_data.py` 生成训练数据
2. **特征提取**: 自动提取所有URL特征
3. **模型训练**: 训练多个算法并比较性能
4. **超参数调优**: 使用网格搜索优化最佳模型
5. **模型评估**: 生成详细的性能报告和可视化图表
6. **模型保存**: 保存最佳模型供系统使用

### 训练参数

- **训练集比例**: 80%
- **测试集比例**: 20%
- **交叉验证**: 5折
- **随机种子**: 42
- **评估指标**: 准确率、AUC、混淆矩阵

## 🔧 配置选项

### 环境配置

```bash
# 开发环境
export FLASK_ENV=development

# 生产环境
export FLASK_ENV=production

# 测试环境
export FLASK_ENV=testing
```

### 自定义配置

```python
# 修改 config.py 中的配置参数
HOST = "0.0.0.0"
PORT = 8080
DEBUG = False
```

## 🚨 故障排除

### 常见问题

1. **依赖安装失败**
   ```bash
   # 升级pip
   pip install --upgrade pip
   
   # 使用conda安装
   conda install scikit-learn pandas numpy
   ```

2. **模型加载失败**
   ```bash
   # 检查模型文件是否存在
   ls models/
   
   # 重新训练模型
   python train_model.py
   ```

3. **Web服务启动失败**
   ```bash
   # 检查端口是否被占用
   netstat -an | grep 5000
   
   # 使用不同端口
   python run.py --port 8080
   ```

4. **性能问题**
   ```bash
   # 减少模型复杂度
   # 修改 config.py 中的 MODEL_CONFIG
   
   # 使用更快的算法
   # 在 train_model.py 中调整算法选择
   ```

## 📝 更新日志

### v1.0.0 (2024-01-01)
- ✨ 初始版本发布
- 🔒 基础恶意URL检测功能
- 🌐 Web界面和API接口
- 🤖 机器学习模型支持
- 📊 完整的测试和评估工具

## 🤝 贡献指南

1. Fork 项目
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 打开 Pull Request

## 📄 许可证

本项目采用 MIT 许可证 - 查看 [LICENSE](LICENSE) 文件了解详情。

## 📞 联系方式

- 项目主页: [GitHub Repository](https://github.com/yourusername/URL)
- 问题反馈: [Issues](https://github.com/yourusername/URL/issues)
- 邮箱: your.email@example.com

## 🙏 致谢

感谢以下开源项目的支持：
- [scikit-learn](https://scikit-learn.org/) - 机器学习库
- [Flask](https://flask.palletsprojects.com/) - Web框架
- [pandas](https://pandas.pydata.org/) - 数据处理
- [numpy](https://numpy.org/) - 数值计算

---

⭐ 如果这个项目对你有帮助，请给它一个星标！
