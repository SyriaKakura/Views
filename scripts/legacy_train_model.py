import pandas as pd
import numpy as np
from app.legacy.detector import MaliciousURLDetector
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, roc_curve
from sklearn.preprocessing import StandardScaler
import matplotlib.pyplot as plt
import seaborn as sns
import joblib
import warnings
warnings.filterwarnings('ignore')

def load_and_prepare_data(data_path):
    """加载和准备训练数据"""
    print(f"📂 正在加载训练数据: {data_path}")
    
    try:
        data = pd.read_csv(data_path)
        print(f"✅ 数据加载成功，形状: {data.shape}")
        
        # 检查必要的列
        required_columns = ['label'] + MaliciousURLDetector().feature_names
        missing_columns = [col for col in required_columns if col not in data.columns]
        
        if missing_columns:
            print(f"⚠️  警告: 缺少以下列: {missing_columns}")
            return None
        
        # 分离特征和标签
        X = data[MaliciousURLDetector().feature_names]
        y = data['label']
        
        print(f"🔍 特征数量: {X.shape[1]}")
        print(f"📊 样本数量: {X.shape[0]}")
        print(f"🏷️  标签分布:\n{y.value_counts()}")
        
        return X, y
        
    except Exception as e:
        print(f"❌ 数据加载失败: {e}")
        return None

def evaluate_model(model, X_test, y_test, model_name):
    """评估模型性能"""
    print(f"\n{'='*50}")
    print(f"🔍 模型评估: {model_name}")
    print(f"{'='*50}")
    
    # 预测
    y_pred = model.predict(X_test)
    y_pred_proba = model.predict_proba(X_test)[:, 1]
    
    # 计算指标
    accuracy = (y_pred == y_test).mean()
    auc = roc_auc_score(y_test, y_pred_proba)
    
    print(f"📊 准确率: {accuracy:.4f}")
    print(f"📈 AUC: {auc:.4f}")
    
    # 分类报告
    print("\n📋 分类报告:")
    print(classification_report(y_test, y_pred, target_names=['安全', '恶意']))
    
    # 混淆矩阵
    cm = confusion_matrix(y_test, y_pred)
    print("\n📊 混淆矩阵:")
    print(cm)
    
    return {
        'accuracy': accuracy,
        'auc': auc,
        'y_pred': y_pred,
        'y_pred_proba': y_pred_proba,
        'confusion_matrix': cm
    }

def plot_results(results_dict, X_test, y_test):
    """绘制结果图表"""
    # 设置中文字体
    plt.rcParams['font.sans-serif'] = ['SimHei', 'Microsoft YaHei', 'DejaVu Sans']
    plt.rcParams['axes.unicode_minus'] = False
    
    fig, axes = plt.subplots(2, 2, figsize=(15, 12))
    fig.suptitle('恶意URL检测模型评估结果', fontsize=16, fontweight='bold')
    
    # 1. ROC曲线
    ax1 = axes[0, 0]
    for name, result in results_dict.items():
        fpr, tpr, _ = roc_curve(y_test, result['y_pred_proba'])
        ax1.plot(fpr, tpr, label=f'{name} (AUC = {result["auc"]:.3f})')
    
    ax1.plot([0, 1], [0, 1], 'k--', alpha=0.5)
    ax1.set_xlabel('假阳性率 (FPR)', fontsize=12)
    ax1.set_ylabel('真阳性率 (TPR)', fontsize=12)
    ax1.set_title('ROC曲线', fontsize=14, fontweight='bold')
    ax1.legend(fontsize=10)
    ax1.grid(True, alpha=0.3)
    
    # 2. 准确率比较
    ax2 = axes[0, 1]
    names = list(results_dict.keys())
    accuracies = [results_dict[name]['accuracy'] for name in names]
    
    bars = ax2.bar(names, accuracies, color=['#667eea', '#764ba2', '#f093fb', '#f5576c'])
    ax2.set_ylabel('准确率', fontsize=12)
    ax2.set_title('模型准确率比较', fontsize=14, fontweight='bold')
    ax2.set_ylim(0, 1)
    
    # 在柱状图上添加数值标签
    for bar, acc in zip(bars, accuracies):
        height = bar.get_height()
        ax2.text(bar.get_x() + bar.get_width()/2., height + 0.01,
                f'{acc:.3f}', ha='center', va='bottom', fontsize=10)
    
    # 3. AUC比较
    ax3 = axes[1, 0]
    aucs = [results_dict[name]['auc'] for name in names]
    
    bars = ax3.bar(names, aucs, color=['#4facfe', '#00f2fe', '#43e97b', '#38f9d7'])
    ax3.set_ylabel('AUC值', fontsize=12)
    ax3.set_title('模型AUC比较', fontsize=14, fontweight='bold')
    ax3.set_ylim(0, 1)
    
    for bar, auc in zip(bars, aucs):
        height = bar.get_height()
        ax3.text(bar.get_x() + bar.get_width()/2., height + 0.01,
                f'{auc:.3f}', ha='center', va='bottom', fontsize=10)
    
    # 4. 混淆矩阵热力图 (使用最佳模型)
    ax4 = axes[1, 1]
    best_model = max(results_dict.keys(), key=lambda x: results_dict[x]['auc'])
    cm = results_dict[best_model]['confusion_matrix']
    
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                xticklabels=['安全', '恶意'], yticklabels=['安全', '恶意'], ax=ax4)
    ax4.set_title(f'混淆矩阵 - {best_model}', fontsize=14, fontweight='bold')
    ax4.set_xlabel('预测标签', fontsize=12)
    ax4.set_ylabel('真实标签', fontsize=12)
    
    plt.tight_layout()
    plt.savefig('model_evaluation_results.png', dpi=300, bbox_inches='tight')
    plt.show()
    
    print(f"\n结果图表已保存为: model_evaluation_results.png")

def train_models(X_train, X_test, y_train, y_test):
    """训练多个模型并比较性能"""
    print("🚀 开始训练模型...")
    
    # 数据标准化
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # 保存标准化器
    joblib.dump(scaler, 'artifacts/legacy_models/url_scaler.pkl')
    print("💾 标准化器已保存为: url_scaler.pkl")
    
    # 定义模型
    models = {
        '随机森林': RandomForestClassifier(n_estimators=100, random_state=42),
        '梯度提升': GradientBoostingClassifier(random_state=42),
        '逻辑回归': LogisticRegression(random_state=42, max_iter=1000),
        '支持向量机': SVC(probability=True, random_state=42)
    }
    
    # 训练和评估模型
    results = {}
    
    for name, model in models.items():
        print(f"\n🤖 训练模型: {name}")
        
        try:
            if name in ['逻辑回归', '支持向量机']:
                # 使用标准化后的数据
                model.fit(X_train_scaled, y_train)
                y_pred = model.predict(X_test_scaled)
                y_pred_proba = model.predict_proba(X_test_scaled)[:, 1]
            else:
                # 使用原始数据
                model.fit(X_train, y_train)
                y_pred = model.predict(X_test)
                y_pred_proba = model.predict_proba(X_test)[:, 1]
            
            # 评估模型
            result = evaluate_model(model, X_test, y_test, name)
            results[name] = result
            
            # 保存模型
            # 将中文名称转换为英文文件名
            name_mapping = {
                '随机森林': 'random_forest',
                '梯度提升': 'gradient_boosting', 
                '逻辑回归': 'logistic_regression',
                '支持向量机': 'svm'
            }
            model_filename = f'{name_mapping.get(name, name.lower())}_model.pkl'
            joblib.dump(model, model_filename)
            print(f"💾 模型已保存为: {model_filename}")
            
        except Exception as e:
            print(f"❌ 模型 {name} 训练失败: {e}")
            continue
    
    return results

def hyperparameter_tuning(X_train, y_train):
    """超参数调优"""
    print("\n🔧 开始超参数调优...")
    
    # 随机森林超参数调优
    rf_param_grid = {
        'n_estimators': [50, 100, 200],
        'max_depth': [10, 20, None],
        'min_samples_split': [2, 5, 10],
        'min_samples_leaf': [1, 2, 4]
    }
    
    rf_grid = GridSearchCV(
        RandomForestClassifier(random_state=42),
        rf_param_grid,
        cv=5,
        scoring='roc_auc',
        n_jobs=-1,
        verbose=1
    )
    
    print("🌲 随机森林超参数调优...")
    rf_grid.fit(X_train, y_train)
    
    print(f"🎯 最佳参数: {rf_grid.best_params_}")
    print(f"🏆 最佳交叉验证分数: {rf_grid.best_score_:.4f}")
    
    # 保存最佳模型
    best_rf = rf_grid.best_estimator_
    joblib.dump(best_rf, 'best_random_forest_model.pkl')
    print("💾 最佳随机森林模型已保存为: best_random_forest_model.pkl")
    
    return best_rf

def main():
    """主函数"""
    print("🔒 恶意URL检测系统 - 模型训练器")
    print("=" * 60)
    
    # 数据路径
    data_path = 'data/legacy/enhanced_malicious_url_training_data.csv'
    
    # 加载数据
    data = load_and_prepare_data(data_path)
    if data is None:
        print("❌ 数据加载失败，程序退出")
        return
    
    X, y = data
    
    # 分割训练集和测试集
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"\n训练集大小: {X_train.shape}")
    print(f"测试集大小: {X_test.shape}")
    
    # 训练多个模型
    results = train_models(X_train, X_test, y_train, y_test)
    
    if not results:
        print("没有成功训练的模型")
        return
    
    # 超参数调优
    best_model = hyperparameter_tuning(X_train, y_train)
    
    # 评估最佳模型
    best_result = evaluate_model(best_model, X_test, y_test, "最佳随机森林")
    results['BestRandomForest'] = best_result
    
    # 绘制结果
    plot_results(results, X_test, y_test)
    
    # 保存最佳模型到主检测器
    detector = MaliciousURLDetector()
    detector.model = best_model
    joblib.dump(detector, 'artifacts/legacy_models/malicious_url_model.pkl')
    print("\n最佳模型已保存到主检测器: malicious_url_model.pkl")
    
    # 模型性能总结
    print("\n" + "="*60)
    print("模型性能总结")
    print("="*60)
    
    for name, result in results.items():
        print(f"{name:20} | 准确率: {result['accuracy']:.4f} | AUC: {result['auc']:.4f}")
    
    # 找出最佳模型
    best_model_name = max(results.keys(), key=lambda x: results[x]['auc'])
    print(f"\n最佳模型: {best_model_name}")
    print(f"准确率: {results[best_model_name]['accuracy']:.4f}")
    print(f"AUC: {results[best_model_name]['auc']:.4f}")
    
    print("\n训练完成! 现在可以使用训练好的模型进行URL检测了。")

if __name__ == "__main__":
    main()
