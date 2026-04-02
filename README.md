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


## 6. 在 VSCode 上运行整个系统（推荐流程）

### 6.1 打开项目并准备 Python 环境
1. 用 VSCode 打开项目根目录 `Views`。
2. 安装扩展：
   - Python（ms-python.python）
   - Pylance（ms-python.vscode-pylance）
3. 在 VSCode 终端执行：

```bash
python -m venv .venv
source .venv/bin/activate  # Windows 请用 .venv\Scripts\activate
pip install -r requirements.txt
```

> 然后用 `Python: Select Interpreter` 选择 `.venv` 解释器。

### 6.2 训练模型（生成 artifacts）
在 VSCode 终端执行：

```bash
python -m app.train --input data/sample_urls.csv
```

期望生成：
- `artifacts/url_detector_logistic.joblib`
- `artifacts/train_metrics.json`

### 6.3 启动 API 服务（终端 A）
在第一个终端执行：

```bash
uvicorn app.api:app --host 0.0.0.0 --port 8000 --reload
```

可在浏览器访问：
- `http://127.0.0.1:8000/docs`（Swagger 文档）
- `http://127.0.0.1:8000/api/v1/model_info`

### 6.4 启动 Dashboard（终端 B）
新开第二个终端（同样激活 `.venv`）执行：

```bash
streamlit run dashboard.py --server.port 8501
```

浏览器访问：
- `http://127.0.0.1:8501`

### 6.5 验证一次预测请求
在第三个终端执行：

```bash
curl -X POST 'http://127.0.0.1:8000/api/v1/predict' \
  -H 'Content-Type: application/json' \
  -d '{"url":"http://example.com/login"}'
```

执行后可在 dashboard 中看到新增预测记录（来自 SQLite）。

### 6.6 使用 Docker Compose 一键运行（可选）
如果你希望不依赖本地 Python 环境，可直接在 VSCode 终端执行：

```bash
docker compose up --build
```

默认端口：
- API: `8000`
- Dashboard: `8501`

停止服务：

```bash
docker compose down
```
