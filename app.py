import os
import json
import csv
import io
import re
import shutil  # <--- 新增，用于复制文件
import glob    # <--- 新增，用于查找文件
from flask import make_response
# 其他 import 保持不变
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Dataset, QueryLog

import pandas as pd
import os
from werkzeug.utils import secure_filename
from datetime import datetime

from sqlalchemy import text  # <--- 新增这行，用于执行 DROP TABLE

app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev-key-for-project'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///dataset_house.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'uploads')

db.init_app(app)

# --- 1. 初始化 Flask-Login ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # 如果未登录访问受限页面，跳转到这里

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- 2. 路由定义 ---

@app.route('/')
def index():
    # 如果已登录，去 Dashboard；否则去登录页
    if current_user.is_authenticated:
        return redirect(url_for('dataset_list'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dataset_list'))
        
    if request.method == 'POST':
        full_name = request.form.get('full_name')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # 简单校验
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('register'))
        
        user_exists = User.query.filter_by(email=email).first()
        if user_exists:
            flash('Email already registered.', 'error')
            return redirect(url_for('register'))

        # 创建新用户 (Hash 密码)
        hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(full_name=full_name, email=email, password_hash=hashed_pw)
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Account created! Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dataset_list'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()

        # 验证 Hash 密码
        if not user or not check_password_hash(user.password_hash, password):
            flash('Invalid email or password.', 'error')
            return redirect(url_for('login'))

        login_user(user)
        return redirect(url_for('dataset_list'))

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# --- 在 app.py 中更新/替换这两个函数 ---
# --- Updated Step 3: Dataset Creation with Samples ---

@app.route('/dataset/create', methods=['GET', 'POST'])
@login_required
def dataset_create():
    # 1. 定义样本文件夹路径
    sample_folder = os.path.join(os.getcwd(), 'sample_data')
    
    # 2. 获取样本文件列表 (支持 .csv 和 .txt)
    # 使用 glob 获取路径，然后用 os.path.basename 取文件名
    sample_files = []
    if os.path.exists(sample_folder):
        paths = glob.glob(os.path.join(sample_folder, '*.csv')) + \
                glob.glob(os.path.join(sample_folder, '*.txt'))
        sample_files = [os.path.basename(p) for p in paths]
    
    if request.method == 'POST':
        name = request.form.get('name')
        table_name = request.form.get('table_name')
        description = request.form.get('description')
        tags = request.form.get('tags')
        visibility = request.form.get('visibility')
        
        # 获取用户选择的样本文件名
        selected_sample = request.form.get('sample_file')
        
        # 逻辑分支：是选择样本，还是上传文件？
        file_path = None
        
        # A. 如果用户选了样本
        if selected_sample and selected_sample != "":
            source_path = os.path.join(sample_folder, selected_sample)
            if os.path.exists(source_path):
                # 生成新的文件名 (避免冲突)
                unique_filename = f"sample_{int(datetime.now().timestamp())}_{selected_sample}"
                dest_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                
                # 关键：把样本文件 COPY 到 uploads 文件夹
                shutil.copy(source_path, dest_path)
                file_path = dest_path
            else:
                flash('Selected sample file not found.', 'error')
                return redirect(request.url)

        # B. 如果用户上传了文件 (且没选样本)
        elif 'file' in request.files:
            file = request.files['file']
            if file and file.filename != '':
                filename = secure_filename(file.filename)
                unique_filename = f"{int(datetime.now().timestamp())}_{filename}"
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                file.save(file_path)
        
        if not file_path:
            flash('Please upload a file OR select a sample.', 'error')
            return redirect(request.url)

        # --- 以下逻辑和之前一样 (解析 & 入库) ---
        try:
            df = pd.read_csv(file_path)
            rows_count = df.shape[0]
            columns_count = df.shape[1]
            
            # 计算 Types
            type_list = []
            for dtype in df.dtypes:
                d_str = str(dtype)
                if 'int' in d_str: type_list.append('int')
                elif 'float' in d_str: type_list.append('float')
                else: type_list.append('str')
            types_str = ", ".join(sorted(set(type_list)))

            # === 修改开始 ===
            # 1. 清洗特殊字符
            clean_table_name = "".join([c for c in table_name if c.isalnum() or c == '_'])
            
            # 2. 如果清洗后为空，或者以数字开头，强制加前缀
            if not clean_table_name:
                # 如果用户乱填导致为空
                clean_table_name = f"ds_{current_user.id}_{int(datetime.now().timestamp())}"
            elif clean_table_name[0].isdigit():
                # 关键修复：如果以数字开头 (例如 "2")，自动改为 "ds_2"
                clean_table_name = f"ds_{clean_table_name}"

            df.to_sql(clean_table_name, con=db.engine, if_exists='replace', index=False)

            new_dataset = Dataset(
                name=name,
                table_name=clean_table_name,
                description=description,
                tags=tags,
                rows=rows_count,
                columns=columns_count,
                types=types_str,
                visibility=visibility,
                file_path=file_path,
                owner_id=current_user.id
            )

            db.session.add(new_dataset)
            db.session.commit()
            flash(f'Dataset saved successfully.', 'success')
            return redirect(url_for('dataset_list'))

        except Exception as e:
            flash(f'Error processing file: {str(e)}', 'error')
            return redirect(request.url)

    # GET 请求：渲染页面，并把 sample_files 传给前端
    return render_template('dataset-create.html', sample_files=sample_files)


# 2. 实现真正的 Dashboard (列表页)
@app.route('/datasets')
@login_required
def dataset_list():
    # 获取我的数据集
    my_datasets = Dataset.query.filter_by(owner_id=current_user.id).order_by(Dataset.created_at.desc()).all()
    
    # 获取其他人的公开数据集
    other_datasets = Dataset.query.filter(
        Dataset.owner_id != current_user.id, 
        Dataset.visibility == 'public'
    ).order_by(Dataset.created_at.desc()).all()
    
    return render_template('datasets.html', my_datasets=my_datasets, other_datasets=other_datasets)

# --- 在 app.py 末尾补充这个命令 ---

@app.cli.command("init-db")
def init_db_command():
    """Clear the existing data and create new tables."""
    with app.app_context():
        db.drop_all()  # 删除所有旧表
        db.create_all() # 根据最新的 models.py 创建新表
        print("Initialized the database successfully.")


# --- Step 5: Edit & Delete Logic ---

@app.route('/dataset/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def dataset_edit(id):
    dataset = Dataset.query.get_or_404(id)

    # 权限检查：只有 Owner 能编辑
    if dataset.owner_id != current_user.id:
        flash('You do not have permission to edit this dataset.', 'error')
        return redirect(url_for('dataset_list'))

    if request.method == 'POST':
        dataset.name = request.form.get('name')
        dataset.description = request.form.get('description')
        dataset.tags = request.form.get('tags')
        dataset.visibility = request.form.get('visibility')
        
        # 更新时间
        dataset.updated_at = datetime.utcnow()
        
        db.session.commit()
        flash(f'Dataset "{dataset.name}" updated successfully.', 'success')
        return redirect(url_for('dataset_list'))

    return render_template('dataset-edit.html', dataset=dataset)

@app.route('/dataset/delete/<int:id>')
@login_required
def dataset_delete(id):
    dataset = Dataset.query.get_or_404(id)

    # 权限检查
    if dataset.owner_id != current_user.id:
        flash('You do not have permission to delete this dataset.', 'error')
        return redirect(url_for('dataset_list'))

    try:
        # 1. 删除动态生成的 SQL 表 (使用 raw SQL)
        # 注意：这里我们信任系统生成的 table_name，但生产环境需更谨慎
        drop_query = text(f"DROP TABLE IF EXISTS {dataset.table_name}")
        db.session.execute(drop_query)
        
        # 2. 删除 DATASETS 表里的记录
        db.session.delete(dataset)
        db.session.commit()
        
        # (可选) 3. 如果你想删除对应的 CSV 文件，也可以在这里用 os.remove(dataset.file_path)
        
        flash(f'Dataset "{dataset.name}" deleted.', 'success')
    except Exception as e:
        flash(f'Error deleting dataset: {str(e)}', 'error')

    return redirect(url_for('dataset_list'))



@app.route('/query', methods=['GET', 'POST'])
@login_required
def dataset_query():
    results = None
    error = None

    if request.method == 'POST':
        sql = request.form.get('sql')
        result_format = request.form.get('format') # 'json' or 'csv'

        # 1. 安全检查：只允许 SELECT
        if not sql.strip().lower().startswith('select'):
            flash('Only SELECT statements are allowed.', 'error')
            return render_template('dataset-query.html')

        try:
            # 2. 执行 SQL
            # 使用 db.session.execute 执行原生 SQL
            query_result = db.session.execute(text(sql))
            
            # 获取列名 (keys) 和 数据 (fetchall)
            columns = query_result.keys() 
            rows = query_result.fetchall()

            # 3. 记录日志 (QueryLog) - 尝试解析表名
            # 简单的正则：找 FROM 后面那个词
            match = re.search(r'from\s+(\w+)', sql, re.IGNORECASE)
            if match:
                table_found = match.group(1)
                # 查找对应的 Dataset
                target_ds = Dataset.query.filter_by(table_name=table_found).first()
                if target_ds:
                    log = QueryLog(
                        sql_text=sql,
                        result_count=len(rows),
                        dataset_id=target_ds.id,
                        user_id=current_user.id
                    )
                    db.session.add(log)
                    db.session.commit()

            # 4. 格式化输出
            if result_format == 'csv':
                # 生成 CSV 下载
                si = io.StringIO()
                cw = csv.writer(si)
                cw.writerow(columns) # 写入表头
                cw.writerows(rows)   # 写入数据
                output = make_response(si.getvalue())
                output.headers["Content-Disposition"] = "attachment; filename=query_result.csv"
                output.headers["Content-type"] = "text/csv"
                return output
            
            else:
                # 默认 JSON 格式：转为字典列表以便前端展示
                # rows 是 tuple，需要转为 dict
                data_list = [dict(zip(columns, row)) for row in rows]
                results = json.dumps(data_list, indent=4, default=str) # default=str 处理 datetime 对象
                flash(f'Query executed successfully. {len(rows)} rows returned.', 'success')

        except Exception as e:
            error = str(e)
            flash(f'SQL Error: {error}', 'error')

    return render_template('dataset-query.html', results=results)

# --- Feature 1: Auto-EDA Statistics ---

@app.route('/dataset/stats/<int:id>')
@login_required
def dataset_stats(id):
    dataset = Dataset.query.get_or_404(id)
    
    # 1. 读取数据
    try:
        df = pd.read_sql(f"SELECT * FROM {dataset.table_name}", db.session.connection())
    except Exception as e:
        flash(f"Error reading table: {e}", "error")
        return redirect(url_for('dataset_list'))

    # 2. 计算统计指标
    summary = []
    
    for col in df.columns:
        col_data = df[col]
        
        # 基础指标
        col_stat = {
            'name': col,
            'type': str(col_data.dtype),
            'count': len(col_data),
            'missing': int(col_data.isnull().sum()),
            'unique': col_data.nunique(),
            'mean': '-',
            'min': '-',
            'max': '-'
        }
        
        # 数值型指标 (只有数字才有平均值)
        # 简单的判断方法：看类型是否包含 int 或 float
        if 'int' in str(col_data.dtype) or 'float' in str(col_data.dtype):
            try:
                col_stat['mean'] = round(col_data.mean(), 2)
                col_stat['min'] = col_data.min()
                col_stat['max'] = col_data.max()
            except:
                pass # 如果数据有脏数据导致计算失败，保持 '-'
        else:
            # 字符串类型：Min/Max 通常是字母顺序，也可以显示
            try:
                col_stat['min'] = col_data.min()
                col_stat['max'] = col_data.max()
            except:
                pass

        summary.append(col_stat)

    return render_template('dataset-stats.html', dataset=dataset, summary=summary)


# --- Admin Tool: Database Reset Route ---

@app.route('/admin/reset-db')
def admin_reset_db():
    # 1. 安全检查 (Security Check)
    # 只有 URL 里带了 ?secret=my_super_secret_key 才能执行
    secret = request.args.get('secret')
    
    # 你可以把这个 key 改成你自己想设的密码
    ADMIN_SECRET = "123456" 
    
    if secret != ADMIN_SECRET:
        # 如果密码不对，直接拒绝
        return "<h3 style='color:red;'>403 Forbidden: Invalid Secret Key</h3>", 403

    try:
        # 2. 执行重置 (Reset Logic)
        # db.drop_all() 会删除所有表 (Users, Datasets, QueryLogs)
        db.drop_all()
        
        # db.create_all() 会根据 models.py 重新创建空表
        db.create_all()
        
        # 3. (可选) 自动创建一个默认管理员账号
        # 这样重置后你不用每次都手动注册，直接就能登录
        from werkzeug.security import generate_password_hash
        admin_user = User(
            full_name="Admin User",
            email="admin@example.com",
            password_hash=generate_password_hash("123456", method='pbkdf2:sha256')
        )
        db.session.add(admin_user)
        db.session.commit()

        return """
        <h1 style='color:green;'>Database has been reset successfully!</h1>
        <p>All tables dropped and recreated.</p>
        <p>Default user created: <b>admin@example.com / 123456</b></p>
        <p><a href='/login'>Go to Login</a></p>
        """
        
    except Exception as e:
        return f"<h3 style='color:red;'>Error resetting database: {str(e)}</h3>"

if __name__ == '__main__':
    app.run(debug=True, port=5000)