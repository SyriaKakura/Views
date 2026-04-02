# Python 恶意 URL 检测系统（闭环版）

本项目实现了完整闭环：
- URL 文本特征 + 结构特征
- TF-IDF（char n-gram）
- 双模型训练（Logistic / LightGBM）
- FastAPI 在线服务
- Streamlit 仪表盘
- 跨源泛化/时间漂移/固定低 FPR 点 TPR 对比实验
- 误报分析与再训练闭环

## 1. 安装依赖

```bash
pip install -r requirements.txt
```

## 2. 训练模型

Logistic：
```bash
python -m app.train --input data/sample_urls.csv --model-type logistic --model-path artifacts/url_detector.joblib
```

LightGBM：
```bash
python -m app.train --input data/sample_urls.csv --model-type lightgbm --model-path artifacts/url_detector.joblib
```

输出：
- `artifacts/url_detector.joblib`
- `artifacts/train_metrics.json`

## 3. 启动 API

```bash
uvicorn app.api:app --host 0.0.0.0 --port 8000
```

接口：
- `POST /api/v1/predict`
- `POST /api/v1/predict_batch`
- `GET /api/v1/model_info`

## 4. 系统性实验（跨源 + 时间切分 + 固定低 FPR）

```bash
python -m app.experiments --input data/experiment_urls.csv --target-fpr 0.01 --train-ratio 0.7
```

输出：
- `artifacts/experiment_report.json`
- `artifacts/false_positive_cases.csv`

## 5. 启动仪表盘

```bash
streamlit run dashboard.py
```

仪表盘同时展示：
- API 在线预测监控
- 实验报告中的跨源泛化结果
- 漂移指标（PSI）
- 误报样本
- 再训练闭环前后对比

## 6. Docker Compose（可选）

```bash
docker compose up --build
```
