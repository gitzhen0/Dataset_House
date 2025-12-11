





# Dataset House

## Installation & Setup

Follow these steps to get the project running on your local machine.

### 1\. Navigate to the Project Directory

```bash
cd path/to/Dataset_House
```

### 2\. Create and Activate a Virtual Environment


  * **macOS / Linux:**

    ```bash
    python3 -m venv .venv
    source .venv/bin/activate
    ```

  * **Windows:**

    ```bash
    python -m venv .venv
    .venv\Scripts\activate
    ```

### 3\. Install Dependencies

Install all required Python libraries (Flask, Pandas, SQLAlchemy, etc.) using `requirements.txt`.

```bash
pip install -r requirements.txt
```

### 4\. Initialize the Database(optional)

* you can skip this step, since for convenience i didn't delete existing db data

This command will create the `instance/dataset_house.db` file and set up the necessary tables (`users`, `datasets`, `querylogs`).

```bash
flask init-db
```

*(You should see the message: "Initialized the database successfully.")*

-----

## 🏃‍♂️ Running the Application

Once the setup is complete, run the application:

```bash
python app.py
```

  * You should see output indicating the server is running (usually `Running on http://127.0.0.1:5000`).
  * Open your web browser and go to: **[http://127.0.0.1:5000](https://www.google.com/url?sa=E&source=gmail&q=http://127.0.0.1:5000)**

---
## Debug

* DB Reset link: http://127.0.0.1:5000/admin/reset-db?secret=123456


