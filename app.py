import os
import json
import csv
import io
import re
import shutil 
import glob    
from flask import make_response

# Flask Core and extensions
from flask import Flask, render_template, redirect, url_for, flash, request, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Dataset, QueryLog

# Pandas for data manipulation and analysis
import pandas as pd
from werkzeug.utils import secure_filename
from datetime import datetime

# SQLAlchemy text needed for executing raw SQL queries
from sqlalchemy import text  

# Initialize Flask Application
app = Flask(__name__)

# Configuration
# SECRET_KEY is used to sign session cookies for security
app.config['SECRET_KEY'] = 'dev-key-for-project'
# Path to the SQLite database file
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///dataset_house.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# Define the folder where uploaded CSV/TXT files will be stored
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'uploads')

# Initialize the Database with the App
db.init_app(app)

# --- Authentication Setup ---
login_manager = LoginManager()
login_manager.init_app(app)
# Redirect users to 'login' view if they try to access protected routes
login_manager.login_view = 'login' 

@login_manager.user_loader
def load_user(user_id):
    """
    Callback function for Flask-Login to reload the user object 
    from the user ID stored in the session.
    """
    return User.query.get(int(user_id))


# --- Main Routes ---

@app.route('/')
def index():
    """
    Root route. Redirects authenticated users to the dashboard,
    and anonymous users to the login page.
    """
    if current_user.is_authenticated:
        return redirect(url_for('dataset_list'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    """
    Handle user registration.
    GET: Render registration form.
    POST: Process form data, hash password, and create new user.
    """
    if current_user.is_authenticated:
        return redirect(url_for('dataset_list'))
        
    if request.method == 'POST':
        full_name = request.form.get('full_name')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # Simple validation
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('register'))
        
        # Check if user already exists in DB
        user_exists = User.query.filter_by(email=email).first()
        if user_exists:
            flash('Email already registered.', 'error')
            return redirect(url_for('register'))

        # Security: Never store plain text passwords. Use PBKDF2 hashing.
        hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(full_name=full_name, email=email, password_hash=hashed_pw)
        
        # Save to database
        db.session.add(new_user)
        db.session.commit()
        
        flash('Account created! Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Handle user login.
    GET: Render login form.
    POST: Validate credentials and establish session.
    """
    if current_user.is_authenticated:
        return redirect(url_for('dataset_list'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()

        # Validate password hash
        if not user or not check_password_hash(user.password_hash, password):
            flash('Invalid email or password.', 'error')
            return redirect(url_for('login'))

        # Log the user in (creates session)
        login_user(user)
        return redirect(url_for('dataset_list'))

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """End the user session."""
    logout_user()
    return redirect(url_for('login'))


# --- Dataset Management Routes ---

@app.route('/dataset/create', methods=['GET', 'POST'])
@login_required
def dataset_create():
    """
    Complex route to handle Dataset creation.
    1. Supports choosing from 'Sample Data' OR uploading a new file.
    2. Parses the CSV using Pandas.
    3. Dynamically creates a new SQL table for the data.
    4. Saves metadata to the 'datasets' table.
    """
    # Define path to sample data folder
    sample_folder = os.path.join(os.getcwd(), 'sample_data')
    
    # Get list of available sample files for the dropdown menu
    sample_files = []
    if os.path.exists(sample_folder):
        paths = glob.glob(os.path.join(sample_folder, '*.csv')) + \
                glob.glob(os.path.join(sample_folder, '*.txt'))
        sample_files = [os.path.basename(p) for p in paths]
    
    if request.method == 'POST':
        # Get metadata from form
        name = request.form.get('name')
        table_name = request.form.get('table_name')
        description = request.form.get('description')
        tags = request.form.get('tags')
        visibility = request.form.get('visibility')
        
        # Check if user selected a sample file
        selected_sample = request.form.get('sample_file')
        
        file_path = None
        
        # Scenario A: User selected a sample file
        if selected_sample and selected_sample != "":
            source_path = os.path.join(sample_folder, selected_sample)
            if os.path.exists(source_path):
                # Copy the sample to uploads folder to allow independent modification/deletion
                unique_filename = f"sample_{int(datetime.now().timestamp())}_{selected_sample}"
                dest_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                
                shutil.copy(source_path, dest_path)
                file_path = dest_path
            else:
                flash('Selected sample file not found.', 'error')
                return redirect(request.url)

        # Scenario B: User uploaded a new file
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
            # Step 1: Use Pandas to read the file (CSV/TXT)
            df = pd.read_csv(file_path)
            rows_count = df.shape[0]
            columns_count = df.shape[1]
            
            # Step 2: Infer data types for display
            type_list = []
            for dtype in df.dtypes:
                d_str = str(dtype)
                if 'int' in d_str: type_list.append('int')
                elif 'float' in d_str: type_list.append('float')
                else: type_list.append('str')
            types_str = ", ".join(sorted(set(type_list)))

            # Step 3: Sanitize the SQL Table Name
            # Remove special characters to prevent SQL injection or errors
            clean_table_name = "".join([c for c in table_name if c.isalnum() or c == '_'])
            
            # Handle empty or invalid names (e.g., starting with a digit)
            if not clean_table_name:
                clean_table_name = f"ds_{current_user.id}_{int(datetime.now().timestamp())}"
            elif clean_table_name[0].isdigit():
                # SQL tables cannot start with numbers, prepend 'ds_'
                clean_table_name = f"ds_{clean_table_name}"

            # Step 4: Check if table name is already taken to avoid crashes
            existing_dataset = Dataset.query.filter_by(table_name=clean_table_name).first()
            if existing_dataset:
                flash(f'Error: The Table Name "{clean_table_name}" is already taken. Please choose a different one.', 'error')
                return redirect(request.url) 

            # Step 5: Write the DataFrame to a new SQL Table (Dynamic Schema)
            df.to_sql(clean_table_name, con=db.engine, if_exists='replace', index=False)

            # Step 6: Create Metadata entry in 'datasets' table
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

    # Render template with sample files list
    return render_template('dataset-create.html', sample_files=sample_files)


@app.route('/datasets')
@login_required
def dataset_list():
    """
    Dashboard route.
    Fetches two lists of datasets:
    1. Datasets owned by the current user.
    2. Datasets owned by others that are marked as 'public'.
    """
    my_datasets = Dataset.query.filter_by(owner_id=current_user.id).order_by(Dataset.created_at.desc()).all()
    
    other_datasets = Dataset.query.filter(
        Dataset.owner_id != current_user.id, 
        Dataset.visibility == 'public'
    ).order_by(Dataset.created_at.desc()).all()
    
    return render_template('datasets.html', my_datasets=my_datasets, other_datasets=other_datasets)


@app.cli.command("init-db")
def init_db_command():
    """
    CLI Command to reset the database.
    Run via terminal: `flask init-db`
    Warning: This deletes all data!
    """
    with app.app_context():
        db.drop_all()  
        db.create_all() 
        print("Initialized the database successfully.")


@app.route('/dataset/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def dataset_edit(id):
    """
    Edit dataset metadata (Name, Description, Visibility).
    Includes ownership check to prevent IDOR (Insecure Direct Object Reference).
    """
    dataset = Dataset.query.get_or_404(id)

    # Security: Verify ownership
    if dataset.owner_id != current_user.id:
        flash('You do not have permission to edit this dataset.', 'error')
        return redirect(url_for('dataset_list'))

    if request.method == 'POST':
        dataset.name = request.form.get('name')
        dataset.description = request.form.get('description')
        dataset.tags = request.form.get('tags')
        dataset.visibility = request.form.get('visibility')
        
        # Update timestamp
        dataset.updated_at = datetime.utcnow()
        
        db.session.commit()
        flash(f'Dataset "{dataset.name}" updated successfully.', 'success')
        return redirect(url_for('dataset_list'))

    return render_template('dataset-edit.html', dataset=dataset)

@app.route('/dataset/delete/<int:id>')
@login_required
def dataset_delete(id):
    """
    Delete a dataset.
    Requires deleting TWO things:
    1. The dynamic SQL table containing the actual data.
    2. The metadata row in the 'datasets' table.
    """
    dataset = Dataset.query.get_or_404(id)

    # Security: Verify ownership
    if dataset.owner_id != current_user.id:
        flash('You do not have permission to delete this dataset.', 'error')
        return redirect(url_for('dataset_list'))

    try:
        # 1. Drop the actual data table using raw SQL
        drop_query = text(f"DROP TABLE IF EXISTS {dataset.table_name}")
        db.session.execute(drop_query)
        
        # 2. Delete the metadata record using ORM
        db.session.delete(dataset)
        db.session.commit()
        
        # Note: We are currently keeping the uploaded file on disk, 
        # but it could be deleted here using os.remove(dataset.file_path)
        
        flash(f'Dataset "{dataset.name}" deleted.', 'success')
    except Exception as e:
        flash(f'Error deleting dataset: {str(e)}', 'error')

    return redirect(url_for('dataset_list'))


# --- SQL Query Interface ---

@app.route('/query', methods=['GET', 'POST'])
@login_required
def dataset_query():
    """
    Interactive SQL Console.
    Includes Security Blocklist to prevent Injection attacks.
    Supports exporting results to JSON or CSV.
    """
    results = None
    error = None

    if request.method == 'POST':
        sql = request.form.get('sql')
        result_format = request.form.get('format') 

        # --- Security: Input Sanitization ---
        # Normalize input
        sql_lower = sql.strip().lower()

        # 1. Allow only SELECT statements (Read-only intent)
        if not sql_lower.startswith('select'):
            flash('Only SELECT statements are allowed.', 'error')
            return render_template('dataset-query.html')

        # 2. Blocklist: Prevent UNION injection and access to sensitive tables
        forbidden_keywords = ['union', 'delete', 'drop', 'update', 'insert', 'alter', 'users', 'sqlite_master']
        
        for kw in forbidden_keywords:
            # Check if forbidden keyword exists in query
            if kw in sql_lower: 
                flash(f'Security Alert: The keyword "{kw}" is strictly forbidden.', 'error')
                return render_template('dataset-query.html')
    
        try:
            # Execute Raw SQL
            query_result = db.session.execute(text(sql))
            
            # Extract headers and rows
            columns = query_result.keys() 
            rows = query_result.fetchall()

            # Logging: Attempt to extract table name to link query to a dataset
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

            # Handle Export Format
            if result_format == 'csv':
                # Create CSV in memory
                si = io.StringIO()
                cw = csv.writer(si)
                cw.writerow(columns) 
                cw.writerows(rows)   
                output = make_response(si.getvalue())
                output.headers["Content-Disposition"] = "attachment; filename=query_result.csv"
                output.headers["Content-type"] = "text/csv"
                return output
            
            else:
                # Default: JSON for frontend display
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
    """
    Automated Exploratory Data Analysis (EDA).
    Uses Pandas to calculate summary statistics (mean, min, max, nulls)
    for every column in the dataset.
    """
    dataset = Dataset.query.get_or_404(id)
    
    try:
        # Load data into Pandas DataFrame from SQL
        df = pd.read_sql(f"SELECT * FROM {dataset.table_name}", db.session.connection())
    except Exception as e:
        flash(f"Error reading table: {e}", "error")
        return redirect(url_for('dataset_list'))

    summary = []
    
    # Iterate through columns to calculate metrics
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
        
        # Calculate numerical statistics if applicable
        if 'int' in str(col_data.dtype) or 'float' in str(col_data.dtype):
            try:
                col_stat['mean'] = round(col_data.mean(), 2)
                col_stat['min'] = col_data.min()
                col_stat['max'] = col_data.max()
            except:
                pass 
        else:
            # For strings, Min/Max represents alphabetical order
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
    """
    Development Utility: Completely resets the database.
    Protected by a secret query parameter (Token).
    """
    secret = request.args.get('secret')
    
    # Hardcoded secret for demo purposes. In prod, use environment variables.
    ADMIN_SECRET = "123456" 
    
    if secret != ADMIN_SECRET:
        return "<h3 style='color:red;'>403 Forbidden: Invalid Secret Key</h3>", 403

    try:
        # Drop all tables (Schema + Data)
        db.drop_all()
        
        # Recreate empty tables based on models.py
        db.create_all()
        
        # Create a default admin user for quick access
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


# --- Feature 2: Data Preview ---

@app.route('/dataset/preview/<int:id>')
@login_required
def dataset_preview(id):
    """
    Displays a quick preview of the dataset.
    Optimized for performance by using 'LIMIT 10'.
    """
    dataset = Dataset.query.get_or_404(id)
    
    try:
        # Only fetch the first 10 rows to minimize I/O and memory usage
        query = f"SELECT * FROM {dataset.table_name} LIMIT 10"
        df = pd.read_sql(query, db.session.connection())
        
        # Convert DataFrame directly to HTML table with Bootstrap classes
        table_html = df.to_html(classes='table table-striped table-hover', index=False, border=0)
        
    except Exception as e:
        flash(f"Error loading preview: {str(e)}", 'error')
        return redirect(url_for('dataset_list'))

    return render_template('dataset-preview.html', dataset=dataset, table_html=table_html)


# --- Feature 3: Direct Download ---

@app.route('/dataset/download/<int:id>')
@login_required
def dataset_download(id):
    """
    Allows users to download the original CSV/TXT file.
    """
    dataset = Dataset.query.get_or_404(id)

    try:
        # Ensure the filename has a proper extension
        filename = f"{dataset.name.replace(' ', '_')}.csv"
        
        # Serve the file from the uploads folder
        return send_file(
            dataset.file_path, 
            as_attachment=True, 
            download_name=filename
        )
    except Exception as e:
        flash(f"Error finding file: {str(e)}", "error")
        return redirect(url_for('dataset_list'))


if __name__ == '__main__':
    # Run the Flask app
    app.run(debug=True, port=5000)