import sqlite3
import csv
import logging
import os
from fastapi import FastAPI, UploadFile, File, HTTPException, status, Request, Query
from fastapi.responses import JSONResponse
from typing import List, Dict, Any, Optional

# --- Configuration ---
DATABASE_FILE = "data.db"
LOG_FILE = "api_activity.log"

# --- Logging Setup ---
# Configure logging to write to a file and also output to the console
logging.basicConfig(
    level=logging.INFO, # Set the logging level to INFO
    format='%(asctime)s - %(levelname)s - %(message)s', # Define the log message format
    handlers=[
        logging.FileHandler(LOG_FILE), # Handler to write logs to a file
        logging.StreamHandler() # Handler to output logs to the console
    ]
)
logger = logging.getLogger(__name__) # Get a logger instance for this module

# --- FastAPI App Initialization ---
app = FastAPI(
    title="Data Upload and Query API",
    description="A simple backend system to upload CSV data, validate it, store it in SQLite, and query it via REST API endpoints, with basic logging.",
    version="1.0.0"
)

# --- Database Functions ---
def get_db_connection():
    """
    Establishes and returns a SQLite database connection.
    Configures the connection to return rows as dictionary-like objects.
    """
    conn = sqlite3.connect(DATABASE_FILE)
    conn.row_factory = sqlite3.Row # Allows accessing columns by name (e.g., row['column_name'])
    return conn

def initialize_db():
    """
    Initializes the database. For this dynamic schema approach,
    no fixed tables are created at startup. Tables are created
    on the fly when CSV files are uploaded.
    """
    # Simply connect and close to ensure the database file is created if it doesn't exist
    conn = get_db_connection()
    conn.close()
    logger.info("Database initialized (or already exists).")

# Run DB initialization when the application starts
initialize_db()

# --- Middleware for Logging API Activity ---
@app.middleware("http")
async def log_requests(request: Request, call_next):
    """
    Middleware to log details of every incoming API request and its response.
    Logs include client IP, HTTP method, request path, query parameters, and response status code.
    """
    client_ip = request.client.host # Get the client's IP address
    method = request.method # Get the HTTP method (GET, POST, etc.)
    path = request.url.path # Get the request path (e.g., /upload_csv/users)
    query_params = dict(request.query_params) # Get query parameters as a dictionary

    # Log the incoming request details
    log_message = f"Request: IP={client_ip}, Method={method}, Path={path}, QueryParams={query_params}"
    logger.info(log_message)

    response = await call_next(request) # Process the request and get the response

    response_status = response.status_code # Get the HTTP status code of the response
    # Log the response status
    logger.info(f"Response: Path={path}, Status={response_status}")
    return response

# --- Helper Functions for Data Handling ---
def sanitize_table_name(name: str) -> str:
    """
    Sanitizes a string to be a valid SQL table or column name.
    Replaces non-alphanumeric characters with underscores and ensures it's not empty.
    """
    # Replace any character that is not alphanumeric with an underscore
    sanitized = ''.join(c if c.isalnum() else '_' for c in name).strip('_')
    # If the name becomes empty after sanitization, provide a default
    if not sanitized:
        return "default_table"
    return sanitized

def validate_csv_row(row: List[str], expected_columns: int) -> bool:
    """
    Validates if a CSV row has the correct number of columns and is not entirely empty.
    Returns True if valid, False otherwise.
    """
    # Check if the number of columns in the row matches the expected number from the header
    if len(row) != expected_columns:
        return False
    # Check if all cells in the row are empty strings after stripping whitespace
    if all(not cell.strip() for cell in row):
        return False
    return True

# --- API Endpoints ---

@app.post("/upload_csv/{table_name}", summary="Upload a CSV file and store its data")
async def upload_csv(table_name: str, file: UploadFile = File(...)):
    """
    Uploads a CSV file, validates its content, and stores it in a new or existing SQLite table.
    The table name is derived from the path parameter.
    
    - **table_name**: The desired name for the database table (will be sanitized).
    - **file**: The CSV file to upload.
    """
    # Check if the uploaded file has a .csv extension
    if not file.filename.endswith(".csv"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only CSV files are allowed."
        )

    sanitized_table_name = sanitize_table_name(table_name) # Sanitize the table name from the URL
    logger.info(f"Attempting to upload CSV to table: {sanitized_table_name}")

    conn = None # Initialize connection to None for finally block
    try:
        contents = await file.read() # Read the content of the uploaded file
        # Decode the content from bytes to UTF-8 string and split into lines
        decoded_content = contents.decode('utf-8').splitlines()
        csv_reader = csv.reader(decoded_content) # Create a CSV reader object

        # Read the header row from the CSV
        header = next(csv_reader)
        if not header:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="CSV file is empty or has no header."
            )

        # Sanitize header names to be valid SQL column names
        sanitized_header = [sanitize_table_name(col) for col in header]
        
        # Prepare SQL column definitions for table creation (all columns as TEXT for simplicity)
        column_definitions = []
        for col_name in sanitized_header:
            column_definitions.append(f"`{col_name}` TEXT") # Use backticks for column names to handle spaces/keywords

        # SQL statement to create the table if it doesn't already exist
        create_table_sql = f"CREATE TABLE IF NOT EXISTS `{sanitized_table_name}` ({', '.join(column_definitions)})"
        
        # SQL template for inserting data into the table
        # Uses '?' as placeholders for values to prevent SQL injection
        insert_sql_template = f"INSERT INTO `{sanitized_table_name}` ({', '.join([f'`{col}`' for col in sanitized_header])}) VALUES ({', '.join(['?' for _ in sanitized_header])})"

        conn = get_db_connection() # Get a database connection
        cursor = conn.cursor() # Get a cursor object

        # Execute the CREATE TABLE statement
        cursor.execute(create_table_sql)
        conn.commit() # Commit the transaction to save table creation
        logger.info(f"Table `{sanitized_table_name}` ensured to exist.")

        # Insert data row by row
        rows_inserted = 0
        validation_errors = [] # List to store any validation warnings
        for i, row in enumerate(csv_reader):
            # Validate the current row against the expected number of columns
            if not validate_csv_row(row, len(header)):
                validation_errors.append(f"Row {i+2} (1-indexed, including header) has incorrect number of columns or is empty: {row}")
                continue # Skip to the next row if validation fails

            # Process the row: convert empty strings to None, which SQLite stores as NULL
            processed_row = [value if value.strip() != '' else None for value in row]

            try:
                # Execute the INSERT statement with the processed row data
                cursor.execute(insert_sql_template, processed_row)
                rows_inserted += 1
            except sqlite3.Error as e:
                # Catch specific SQLite errors during insertion
                validation_errors.append(f"Database insertion error for row {i+2}: {e} - Row: {row}")
                logger.error(f"DB insertion error for row {i+2}: {e}")

        conn.commit() # Commit all inserted rows
        logger.info(f"Successfully inserted {rows_inserted} rows into `{sanitized_table_name}`.")

        # Prepare the response detail
        response_detail = {
            "message": f"CSV uploaded successfully to table '{sanitized_table_name}'.",
            "rows_inserted": rows_inserted
        }
        if validation_errors:
            response_detail["validation_warnings"] = validation_errors
            response_detail["message"] += " Some rows had validation warnings."

        return JSONResponse(status_code=status.HTTP_200_OK, content=response_detail)

    except StopIteration:
        # This error occurs if next(csv_reader) is called on an empty iterator
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="CSV file is empty or malformed (no header found)."
        )
    except Exception as e:
        # Catch any other unexpected errors during file processing or database operations
        logger.exception(f"Error during CSV upload to {sanitized_table_name}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred during file processing: {e}"
        )
    finally:
        if conn:
            conn.close() # Ensure the database connection is closed

@app.get("/tables", summary="List all available data tables")
async def list_tables():
    """
    Retrieves a list of all tables currently stored in the database.
    Excludes internal SQLite tables (those starting with 'sqlite_').
    """
    conn = None # Initialize connection to None for finally block
    try:
        conn = get_db_connection() # Get a database connection
        cursor = conn.cursor() # Get a cursor object
        # Query sqlite_master to get names of all user-defined tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
        tables = [row["name"] for row in cursor.fetchall()] # Extract table names
        logger.info(f"Listed tables: {tables}")
        return {"tables": tables}
    except Exception as e:
        logger.exception(f"Error listing tables: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An unexpected error occurred: {e}"
        )
    finally:
        if conn:
            conn.close() # Ensure the database connection is closed

@app.get("/data/{table_name}", summary="Retrieve all data from a specific table")
async def get_table_data(table_name: str):
    """
    Retrieves all data from the specified table.
    
    - **table_name**: The name of the table to retrieve data from.
    """
    sanitized_table_name = sanitize_table_name(table_name) # Sanitize the table name
    conn = None # Initialize connection to None for finally block
    try:
        conn = get_db_connection() # Get a database connection
        cursor = conn.cursor() # Get a cursor object

        # Execute a SELECT all query on the specified table
        cursor.execute(f"SELECT * FROM `{sanitized_table_name}`")
        # Get column names from the cursor description
        columns = [description[0] for description in cursor.description]
        # Fetch all rows and convert them into a list of dictionaries
        data = [dict(zip(columns, row)) for row in cursor.fetchall()]
        logger.info(f"Retrieved {len(data)} rows from table `{sanitized_table_name}`.")
        return {"table_name": sanitized_table_name, "data": data}
    except sqlite3.OperationalError as e:
        # Catch specific error if the table does not exist or is inaccessible
        logger.error(f"Error querying table `{sanitized_table_name}`: {e}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Table '{sanitized_table_name}' not found or inaccessible."
        )
    except Exception as e:
        # Catch any other unexpected errors
        logger.exception(f"Unexpected error retrieving data from {sanitized_table_name}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An unexpected error occurred: {e}"
        )
    finally:
        if conn:
            conn.close() # Ensure the database connection is closed

@app.get("/data/{table_name}/query", summary="Query data from a table with filters")
async def query_table_data(
    table_name: str,
    limit: Optional[int] = 100, # Optional limit for the number of rows returned
    offset: Optional[int] = 0, # Optional offset for pagination
    filters_string: Optional[str] = Query(None, alias="filters", description="Comma-separated key=value pairs for filtering (e.g., category=Electronics,price=100)"), # Added for Swagger UI
):
    """
    Queries data from the specified table with optional filters, limit, and offset.
    Filters can be applied as key=value pairs in the 'filters' query parameter (e.g., category=Electronics,price=100)
    or as individual query parameters (e.g., /data/mytable/query?category=Electronics&price=100).
    
    - **table_name**: The name of the table to query.
    - **limit**: Maximum number of rows to return (default: 100).
    - **offset**: Number of rows to skip (default: 0).
    - **filters_string**: A comma-separated string of key=value pairs for filtering (e.g., `category=Electronics,price=100`).
    - **Any other query parameters**: Will also be treated as column=value filters.
    """
    sanitized_table_name = sanitize_table_name(table_name) # Sanitize the table name
    conn = None # Initialize connection to None for finally block
    try:
        conn = get_db_connection() # Get a database connection
        cursor = conn.cursor() # Get a cursor object

        # Get column names from the table to validate incoming filters
        cursor.execute(f"PRAGMA table_info(`{sanitized_table_name}`)")
        table_columns = [row["name"] for row in cursor.fetchall()]

        where_clauses = [] # List to store WHERE clause conditions
        params = [] # List to store parameters for the WHERE clause (to prevent SQL injection)
        
        # Start with filters from the filters_string (if provided)
        parsed_filters = {}
        if filters_string:
            # Split the string by comma to get individual key=value pairs
            filter_pairs = filters_string.split(',')
            for pair in filter_pairs:
                if '=' in pair:
                    key, value = pair.split('=', 1) # Split only on the first '='
                    parsed_filters[key.strip()] = value.strip()
                else:
                    logger.warning(f"Invalid filter format in filters_string: {pair}. Expected key=value.")

        # Combine with any other dynamic query parameters (from the Request object, if needed in the future)
        # For now, we'll primarily rely on filters_string for Swagger UI.
        # If you were making direct API calls, you could still use individual query params.
        
        # Iterate through the parsed filters
        for col, val in parsed_filters.items():
            sanitized_col = sanitize_table_name(col) # Sanitize the column name from the filter
            if sanitized_col in table_columns:
                # Add a condition for the column and its value
                where_clauses.append(f"`{sanitized_col}` = ?")
                params.append(val)
            else:
                logger.warning(f"Ignoring invalid filter column: {col} for table {sanitized_table_name}")

        # Construct the WHERE clause if filters are present
        where_sql = " WHERE " + " AND ".join(where_clauses) if where_clauses else ""
        
        # Add LIMIT and OFFSET clauses
        limit_offset_sql = f" LIMIT ? OFFSET ?"
        params.extend([limit, offset]) # Add limit and offset values to parameters

        # Construct the final SQL query
        query_sql = f"SELECT * FROM `{sanitized_table_name}`{where_sql}{limit_offset_sql}"
        logger.info(f"Executing query: {query_sql} with params: {params}")

        # Execute the query
        cursor.execute(query_sql, params)
        # Get column names from the cursor description
        columns = [description[0] for description in cursor.description]
        # Fetch all rows and convert them into a list of dictionaries
        data = [dict(zip(columns, row)) for row in cursor.fetchall()]
        logger.info(f"Retrieved {len(data)} filtered rows from table `{sanitized_table_name}`.")
        return {"table_name": sanitized_table_name, "data": data, "filters_applied": parsed_filters} # Return parsed_filters here
    except sqlite3.OperationalError as e:
        # Catch specific error if the table does not exist or is inaccessible
        logger.error(f"Error querying table `{sanitized_table_name}` with filters: {e}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Table '{sanitized_table_name}' not found or inaccessible."
        )
    except Exception as e:
        # Catch any other unexpected errors
        logger.exception(f"Unexpected error querying data from {sanitized_table_name}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An unexpected error occurred: {e}"
        )
    finally:
        if conn:
            conn.close() # Ensure the database connection is closed

