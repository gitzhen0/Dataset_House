import os
import json
import csv
import io
import re
import shutil 
import glob    
from flask import make_response

from flask import Flask, render_template, redirect, url_for, flash, request, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Dataset, QueryLog

import pandas as pd
import os
from werkzeug.utils import secure_filename
from datetime import datetime

from sqlalchemy import text  

app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev-key-for-project'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///dataset_house.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'uploads')

db.init_app(app)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' 

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



@app.route('/')
def index():

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


        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('register'))
        
        user_exists = User.query.filter_by(email=email).first()
        if user_exists:
            flash('Email already registered.', 'error')
            return redirect(url_for('register'))


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



@app.route('/dataset/create', methods=['GET', 'POST'])
@login_required
def dataset_create():

    sample_folder = os.path.join(os.getcwd(), 'sample_data')
    

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
        

        selected_sample = request.form.get('sample_file')
        

        file_path = None
        

        if selected_sample and selected_sample != "":
            source_path = os.path.join(sample_folder, selected_sample)
            if os.path.exists(source_path):

                unique_filename = f"sample_{int(datetime.now().timestamp())}_{selected_sample}"
                dest_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                

                shutil.copy(source_path, dest_path)
                file_path = dest_path
            else:
                flash('Selected sample file not found.', 'error')
                return redirect(request.url)


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


        try:
            df = pd.read_csv(file_path)
            rows_count = df.shape[0]
            columns_count = df.shape[1]
            

            type_list = []
            for dtype in df.dtypes:
                d_str = str(dtype)
                if 'int' in d_str: type_list.append('int')
                elif 'float' in d_str: type_list.append('float')
                else: type_list.append('str')
            types_str = ", ".join(sorted(set(type_list)))


            clean_table_name = "".join([c for c in table_name if c.isalnum() or c == '_'])
            

            if not clean_table_name:

                clean_table_name = f"ds_{current_user.id}_{int(datetime.now().timestamp())}"
            elif clean_table_name[0].isdigit():

                clean_table_name = f"ds_{clean_table_name}"

            existing_dataset = Dataset.query.filter_by(table_name=clean_table_name).first()
            if existing_dataset:
                flash(f'Error: The Table Name "{clean_table_name}" is already taken. Please choose a different one.', 'error')
                return redirect(request.url) # 直接打回，让用户重填

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


    return render_template('dataset-create.html', sample_files=sample_files)



@app.route('/datasets')
@login_required
def dataset_list():

    my_datasets = Dataset.query.filter_by(owner_id=current_user.id).order_by(Dataset.created_at.desc()).all()
    

    other_datasets = Dataset.query.filter(
        Dataset.owner_id != current_user.id, 
        Dataset.visibility == 'public'
    ).order_by(Dataset.created_at.desc()).all()
    
    return render_template('datasets.html', my_datasets=my_datasets, other_datasets=other_datasets)



@app.cli.command("init-db")
def init_db_command():
    """Clear the existing data and create new tables."""
    with app.app_context():
        db.drop_all()  
        db.create_all() 
        print("Initialized the database successfully.")




@app.route('/dataset/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def dataset_edit(id):
    dataset = Dataset.query.get_or_404(id)


    if dataset.owner_id != current_user.id:
        flash('You do not have permission to edit this dataset.', 'error')
        return redirect(url_for('dataset_list'))

    if request.method == 'POST':
        dataset.name = request.form.get('name')
        dataset.description = request.form.get('description')
        dataset.tags = request.form.get('tags')
        dataset.visibility = request.form.get('visibility')
        

        dataset.updated_at = datetime.utcnow()
        
        db.session.commit()
        flash(f'Dataset "{dataset.name}" updated successfully.', 'success')
        return redirect(url_for('dataset_list'))

    return render_template('dataset-edit.html', dataset=dataset)

@app.route('/dataset/delete/<int:id>')
@login_required
def dataset_delete(id):
    dataset = Dataset.query.get_or_404(id)


    if dataset.owner_id != current_user.id:
        flash('You do not have permission to delete this dataset.', 'error')
        return redirect(url_for('dataset_list'))

    try:

        drop_query = text(f"DROP TABLE IF EXISTS {dataset.table_name}")
        db.session.execute(drop_query)
        

        db.session.delete(dataset)
        db.session.commit()
        

        
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
        result_format = request.form.get('format') 

        
  
        sql_lower = sql.strip().lower()


        if not sql_lower.startswith('select'):
            flash('Only SELECT statements are allowed.', 'error')
            return render_template('dataset-query.html')


        forbidden_keywords = ['union', 'delete', 'drop', 'update', 'insert', 'alter', 'users', 'sqlite_master']
        
        for kw in forbidden_keywords:
         
            if kw in sql_lower: 
                flash(f'Security Alert: The keyword "{kw}" is strictly forbidden.', 'error')
                return render_template('dataset-query.html')
    

        try:
    
            query_result = db.session.execute(text(sql))
            
  
            columns = query_result.keys() 
            rows = query_result.fetchall()

            match = re.search(r'from\s+(\w+)', sql, re.IGNORECASE)
            if match:
                table_found = match.group(1)

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


            if result_format == 'csv':

                si = io.StringIO()
                cw = csv.writer(si)
                cw.writerow(columns) 
                cw.writerows(rows)   
                output = make_response(si.getvalue())
                output.headers["Content-Disposition"] = "attachment; filename=query_result.csv"
                output.headers["Content-type"] = "text/csv"
                return output
            
            else:
  
                data_list = [dict(zip(columns, row)) for row in rows]
                results = json.dumps(data_list, indent=4, default=str) 
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
    

    try:
        df = pd.read_sql(f"SELECT * FROM {dataset.table_name}", db.session.connection())
    except Exception as e:
        flash(f"Error reading table: {e}", "error")
        return redirect(url_for('dataset_list'))


    summary = []
    
    for col in df.columns:
        col_data = df[col]
        

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
        

        if 'int' in str(col_data.dtype) or 'float' in str(col_data.dtype):
            try:
                col_stat['mean'] = round(col_data.mean(), 2)
                col_stat['min'] = col_data.min()
                col_stat['max'] = col_data.max()
            except:
                pass 
        else:

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

    secret = request.args.get('secret')
    

    ADMIN_SECRET = "123456" 
    
    if secret != ADMIN_SECRET:

        return "<h3 style='color:red;'>403 Forbidden: Invalid Secret Key</h3>", 403

    try:

        db.drop_all()
        

        db.create_all()
        

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



@app.route('/dataset/preview/<int:id>')
@login_required
def dataset_preview(id):
    dataset = Dataset.query.get_or_404(id)
    
    try:

        query = f"SELECT * FROM {dataset.table_name} LIMIT 10"
        df = pd.read_sql(query, db.session.connection())
        

        table_html = df.to_html(classes='table table-striped table-hover', index=False, border=0)
        
    except Exception as e:
        flash(f"Error loading preview: {str(e)}", 'error')
        return redirect(url_for('dataset_list'))

    return render_template('dataset-preview.html', dataset=dataset, table_html=table_html)


@app.route('/dataset/download/<int:id>')
@login_required
def dataset_download(id):
    dataset = Dataset.query.get_or_404(id)

    
    try:

        filename = f"{dataset.name.replace(' ', '_')}.csv"
        
        return send_file(
            dataset.file_path, 
            as_attachment=True, 
            download_name=filename
        )
    except Exception as e:
        flash(f"Error finding file: {str(e)}", "error")
        return redirect(url_for('dataset_list'))


if __name__ == '__main__':
    app.run(debug=True, port=5000)