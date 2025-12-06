import os
import json
import csv
import io
import re
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

# 1. 更新 Create 逻辑：增加 Types 计算
@app.route('/dataset/create', methods=['GET', 'POST'])
@login_required
def dataset_create():
    if request.method == 'POST':
        name = request.form.get('name')
        table_name = request.form.get('table_name')
        description = request.form.get('description')
        tags = request.form.get('tags')
        visibility = request.form.get('visibility')
        
        if 'file' not in request.files:
            flash('No file part', 'error')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file', 'error')
            return redirect(request.url)

        if file:
            filename = secure_filename(file.filename)
            unique_filename = f"{int(datetime.now().timestamp())}_{filename}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            file.save(file_path)

            try:
                df = pd.read_csv(file_path)
                rows_count = df.shape[0]
                columns_count = df.shape[1]
                
                # --- 新增：计算 Types ---
                # 将 pandas 的 dtype (int64, float64, object) 简化为 (int, float, str)
                type_list = []
                for dtype in df.dtypes:
                    d_str = str(dtype)
                    if 'int' in d_str: type_list.append('int')
                    elif 'float' in d_str: type_list.append('float')
                    else: type_list.append('str')
                # 去重并转字符串，例如 "int, str"
                types_str = ", ".join(sorted(set(type_list)))
                # ---------------------

                clean_table_name = "".join([c for c in table_name if c.isalnum() or c == '_'])
                if not clean_table_name:
                    clean_table_name = f"ds_{current_user.id}_{int(datetime.now().timestamp())}"

                df.to_sql(clean_table_name, con=db.engine, if_exists='replace', index=False)

                new_dataset = Dataset(
                    name=name,
                    table_name=clean_table_name,
                    description=description,
                    tags=tags,
                    rows=rows_count,
                    columns=columns_count,
                    types=types_str,  # 保存计算出的 Types
                    visibility=visibility,
                    file_path=file_path,
                    owner_id=current_user.id
                )

                db.session.add(new_dataset)
                db.session.commit()
                flash(f'Dataset saved.', 'success')
                return redirect(url_for('dataset_list'))

            except Exception as e:
                flash(f'Error: {str(e)}', 'error')
                return redirect(request.url)

    return render_template('dataset-create.html')


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

if __name__ == '__main__':
    app.run(debug=True, port=5000)