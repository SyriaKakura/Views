# Python 恶意 URL 检测系统（MVP）

基于 `malicious_url_detection_design_cn.md` 实现的最小可运行系统，包含：
- 训练管道（TF-IDF + 结构特征 + LogisticRegression）
- 在线推理 API（FastAPI）
- 预测日志存储（SQLite）
- 可视化仪表盘（Streamlit）

## 1. 安装依赖

```bash
pip install -r requirements.txt
```

## 2. 训练模型

```bash
python -m app.train --input data/sample_urls.csv
```

输出：
- `artifacts/url_detector_logistic.joblib`
- `artifacts/train_metrics.json`

## 3. 启动 API

```bash
uvicorn app.api:app --host 0.0.0.0 --port 8000
```

接口：
- `POST /api/v1/predict`
- `POST /api/v1/predict_batch`
- `GET /api/v1/model_info`

## 4. 启动仪表盘

```bash
streamlit run dashboard.py
```

## 5. Docker Compose（可选）

```bash
docker compose up --build
```
