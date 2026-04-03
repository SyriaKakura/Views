# url-master 融合映射说明

为满足“将 `url-master` 融合到主系统，且不再以独立目录存在”的要求，原 `url-master/url-master` 内容已拆分到主工程各模块：

- 旧 `url_detector.py` -> `app/legacy/detector.py`
- 旧 `config.py` -> `app/legacy/config.py`
- 旧 `app.py` -> `app/legacy/flask_app.py`
- 旧 `run.py` -> `scripts/legacy_run.py`
- 旧 `quick_start.py` -> `scripts/legacy_quick_start.py`
- 旧 `demo.py` -> `scripts/legacy_demo.py`
- 旧 `test_system.py` -> `scripts/legacy_test_system.py`
- 旧 `generate_training_data.py` -> `scripts/legacy_generate_training_data.py`
- 旧 `train_model.py` -> `scripts/legacy_train_model.py`
- 旧模板 -> `templates/legacy_index.html`
- 旧模型产物（`.pkl`）-> `artifacts/legacy_models/`
- 旧训练数据（`.csv`）-> `data/legacy/`
- 旧评估图 -> `artifacts/legacy_reports/model_evaluation_results.png`
- 旧日志 -> `artifacts/legacy_logs/url_detector.log`
- 旧文档 -> `docs/url_master_legacy_readme.md`
- 旧依赖清单 -> `docs/url_master_legacy_requirements.txt`

> 同时，主系统保留并增强了 FastAPI 架构（`/api/v1/*`），并提供 url-master 风格兼容接口（`/detect`、`/batch_detect`、`/features`、`/stats`）。
