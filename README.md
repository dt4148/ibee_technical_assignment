# ibee_technical_assignment

Data Upload and Query API


Simple backend system built with FastAPI that allows users to upload CSV files, validates the data, stores it in an SQLite database, and exposes REST API endpoints to query the stored data. All API activity is logged to a file.


Features
CSV File Upload: Upload CSV files to dynamically named tables in an SQLite database.

Data Validation: Basic validation for missing values and incorrect row lengths during CSV upload. Empty cells are stored as NULL.

SQLite Database: Uses a file-based SQLite database (data.db) for data storage.


REST API Endpoints:

POST /upload_csv/{table_name}: Uploads a CSV file and stores its data in a new or existing table.

GET /tables: Lists all tables created from CSV uploads.

GET /data/{table_name}: Retrieves all data from a specified table.

GET /data/{table_name}/query: Allows filtering, limiting, and offsetting data from a specified table using query parameters.

API Activity Logging: Logs all API requests (method, path, client IP) and response statuses to api_activity.log and the console.

Automatic API Documentation (Swagger UI): Interactive API documentation is automatically generated and available at /docs.


Technologies Used

Backend Framework: FastAPI (Python)

Web Server: Uvicorn

Database: SQLite

File Handling: python-multipart

Data Processing: Standard Python csv module


Setup and Installation

Clone or Download the Project:
If you have the main.py file, simply save it to a directory of your choice (e.g., my_api_project).

Create a Virtual Environment (Recommended):
It's good practice to use a virtual environment to manage project dependencies.

python -m venv venv

Activate the Virtual Environment:

Windows:

.\venv\Scripts\activate

Install Dependencies:
Navigate to your project directory (where main.py is located) in your terminal and install the required packages:

pip install fastapi uvicorn python-multipart

If pip doesn't work, try pip3.

Running the Application
Start the FastAPI Server:
From your project directory in the activated virtual environment, run:

uvicorn main:app --reload

main: Refers to the main.py file.

app: Refers to the FastAPI() instance named app inside main.py.

--reload: This flag automatically restarts the server when you make changes to your code, which is useful for development.



Access the API Documentation:
Once the server starts, open your web browser and go to:

http://127.0.0.1:8000/docs

This will display the interactive Swagger UI, where you can explore and test all the API endpoints.

API Endpoints and Usage
1. Upload CSV File
Endpoint: POST /upload_csv/{table_name}

Description: Uploads a CSV file and stores its data in a new or existing SQLite table. The table name is derived from the path parameter.

Parameters:

table_name (Path Parameter): The desired name for the database table (e.g., users, products, orders). It will be sanitized to be a valid SQL name.

file (File Upload): The CSV file to upload.

Example (using Swagger UI):

Go to http://127.0.0.1:8000/docs.

Expand the POST /upload_csv/{table_name} endpoint.

Click "Try it out".

In the table_name field, enter a name like my_data.

Click "Choose File" and select your CSV file.

Click "Execute".

Sample my_data.csv content:

name,age,city
Dk,40,Banglore
Vk,37,Chennai
Sd,42,Delhi

2. List All Tables
Endpoint: GET /tables

Description: Retrieves a list of all user-defined tables currently stored in the database.

Example (using Swagger UI):

Go to http://127.0.0.1:8000/docs.

Expand the GET /tables endpoint.

Click "Try it out".

Click "Execute".

Expected Response: {"tables": ["my_data"]} (if you uploaded my_data.csv)

3. Retrieve All Data from a Table
Endpoint: GET /data/{table_name}

Description: Retrieves all data from the specified table.

Parameters:

table_name (Path Parameter): The name of the table to retrieve data from (e.g., my_data).

Example (using Swagger UI):

Go to http://127.0.0.1:8000/docs.

Expand the GET /data/{table_name} endpoint.

Click "Try it out".

In the table_name field, enter my_data.

Click "Execute".

Expected Response (JSON): All rows from your my_data table.

4. Query Data from a Table with Filters
Endpoint: GET /data/{table_name}/query

Description: Queries data from the specified table with optional filters, limit, and offset. Filters are applied as key=value pairs.

Parameters:

table_name (Path Parameter): The name of the table to query (e.g., my_data).

limit (Query Parameter, Optional): Maximum number of rows to return (default: 100).

offset (Query Parameter, Optional): Number of rows to skip (default: 0) for pagination.

filters (Query Parameter, Optional): A comma-separated string of key=value pairs for filtering (e.g., city=New York,age=30).

Example (using Swagger UI):

Go to http://127.0.0.1:8000/docs.

Expand the GET /data/{table_name}/query endpoint.

Click "Try it out".

In the table_name field, enter my_data.

In the filters input field, enter your desired filters as key=value pairs separated by commas.

To filter by city: city=New York

To filter by age: age=30

To combine filters: city=New York,age=30

Optionally, adjust limit and offset.

Click "Execute".

Example (Direct URL in browser):
You can also construct the URL directly in your browser's address bar for more direct testing of dynamic filters (even though the filters parameter in Swagger UI now works):

http://127.0.0.1:8000/data/my_data/query?city=New%20York&age=30&limit=1

(Note: %20 is the URL encoding for a space).

Logging
All API requests and their responses are logged to a file named api_activity.log in the same directory as main.py. Logs are also printed to the console where the uvicorn server is running.

Database File
The SQLite database file data.db will be created automatically in the same directory as main.py when the application starts for the first time or when you upload your first CSV.
