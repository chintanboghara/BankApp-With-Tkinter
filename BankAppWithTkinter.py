import os
import pickle
import re
import logging
import hashlib
import sqlite3
from datetime import datetime, timedelta # Ensure timedelta is imported
from pathlib import Path # Added
from tkinter import *
from tkinter import ttk, messagebox
from logging.handlers import RotatingFileHandler

# Configure logging to record events in a log file
# Get the root logger
logger = logging.getLogger()
logger.setLevel(logging.INFO) # Set the root logger level

# Define the log file path (can keep it as 'bankapp.log')
log_file = 'bankapp.log'

# Create a RotatingFileHandler
# Rotate after 1MB, keep 3 backup logs
rotate_handler = RotatingFileHandler(log_file, maxBytes=1024*1024, backupCount=3, encoding='utf-8')

# Create a formatter and set it for the handler
formatter = logging.Formatter('%(asctime)s:%(levelname)s:%(message)s')
rotate_handler.setFormatter(formatter)

# Add the handler to the logger
logger.addHandler(rotate_handler)

# Optional: If you also want to see logs on the console during development (remove for production packaging)
# console_handler = logging.StreamHandler()
# console_handler.setFormatter(formatter)
# logger.addHandler(console_handler)


# DATA_FILE = 'appData.bin' # Removed as data is now handled by SQLite
# DB_PATH = 'bankapp.db' # Old DB_PATH definition

APP_NAME = "BankApp" # Can be a global constant
home_dir = Path.home()
app_data_dir = home_dir / f".{APP_NAME}" # e.g., ~/.BankApp or C:\Users\<user>\.BankApp
DB_PATH = app_data_dir / "bankapp.db"


def initialize_database(db_path: Path = DB_PATH) -> None:
    """
    Connects to or creates the SQLite database file in the user-specific directory.
    Creates 'users' and 'transactions' tables if they don't exist.
    Ensures the database directory exists.
    """
    try:
        # Ensure the parent directory for the database exists
        db_path.parent.mkdir(parents=True, exist_ok=True)
        
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            # Create users table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    full_name TEXT NOT NULL,
                    age INTEGER NOT NULL,
                    gender INTEGER NOT NULL,
                    balance INTEGER NOT NULL DEFAULT 0
                )
            """)
            # Create transactions table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS transactions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    type TEXT NOT NULL,
                    amount INTEGER NOT NULL,
                    timestamp TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                )
            """)
            # Create login_attempts table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS login_attempts (
                    username TEXT PRIMARY KEY,
                    failure_count INTEGER NOT NULL DEFAULT 0,
                    lockout_until TEXT 
                )
            """)
            conn.commit()
            logging.info("Database tables (users, transactions, login_attempts) initialized successfully at %s", db_path)
    except sqlite3.Error as e:
        logging.error("Error initializing database at %s: %s", db_path, e)


def create_user_sqlite(db_path: str, username: str, password_hash: str, full_name: str, age: int, gender: int, initial_balance: int) -> bool:
    """
    Inserts a new user into the users table.
    Returns True on success, False on failure (e.g., username exists).
    """
    try:
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO users (username, password_hash, full_name, age, gender, balance)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (username, password_hash, full_name, age, gender, initial_balance))
            conn.commit()
            logging.info("User '%s' created successfully in SQLite.", username)
            return True
    except sqlite3.IntegrityError:
        logging.warning("Failed to create user '%s' in SQLite: Username already exists.", username)
        return False
    except sqlite3.Error as e:
        logging.error("Error creating user '%s' in SQLite: %s", username, e)
        return False


def get_user_data_sqlite(db_path: str, username: str) -> dict | None:
    """
    Fetches user data from the users table by username.
    Returns a dictionary of user data or None if not found.
    """
    try:
        with sqlite3.connect(db_path) as conn:
            conn.row_factory = sqlite3.Row  # Access columns by name
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            row = cursor.fetchone()
            if row:
                logging.info("User data for '%s' retrieved successfully from SQLite.", username)
                return dict(row)
            else:
                logging.info("No user data found for '%s' in SQLite.", username)
                return None
    except sqlite3.Error as e:
        logging.error("Error fetching user data for '%s' from SQLite: %s", username, e)
        return None


def update_user_balance_sqlite(db_path: str, username: str, new_balance: int) -> bool:
    """
    Updates the balance for the specified username in the users table.
    Returns True on success, False on failure.
    """
    try:
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET balance = ? WHERE username = ?", (new_balance, username))
            conn.commit()
            if cursor.rowcount > 0:
                logging.info("Balance updated for user '%s' to %d in SQLite.", username, new_balance)
                return True
            else:
                logging.warning("Failed to update balance for user '%s' in SQLite: User not found.", username)
                return False
    except sqlite3.Error as e:
        logging.error("Error updating balance for user '%s' in SQLite: %s", username, e)
        return False


def update_user_password_hash_sqlite(db_path: str, username: str, new_full_hash_string: str) -> bool:
    """
    Updates the password_hash for the specified username in the users table.
    Returns True on success, False on failure.
    """
    try:
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET password_hash = ? WHERE username = ?", (new_full_hash_string, username))
            conn.commit()
            if cursor.rowcount > 0:
                logging.info("Password hash updated successfully for user '%s' in SQLite.", username)
                return True
            else:
                # This could mean the user was not found, or the new hash is the same as the old one (less likely here)
                logging.warning("Failed to update password hash for user '%s' in SQLite: User not found or no change made.", username)
                return False
    except sqlite3.Error as e:
        logging.error("SQLite error updating password hash for user '%s': %s", username, e)
        return False


def record_transaction_sqlite(db_path: str, username: str, transaction_type: str, amount: int, timestamp: str) -> bool:
    """
    Records a new transaction for the user.
    Returns True on success, False on failure.
    """
    user_data = get_user_data_sqlite(db_path, username)
    if not user_data:
        logging.warning("Failed to record transaction for '%s': User not found.", username)
        return False
    
    user_id = user_data['id']
    try:
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO transactions (user_id, type, amount, timestamp)
                VALUES (?, ?, ?, ?)
            """, (user_id, transaction_type, amount, timestamp))
            conn.commit()
            logging.info("Transaction recorded for user '%s' (ID: %d): %s, Amount: %d", username, user_id, transaction_type, amount)
            return True
    except sqlite3.Error as e:
        logging.error("Error recording transaction for user '%s' (ID: %d): %s", username, user_id, e)
        return False


def get_user_transactions_sqlite(db_path: str, username: str) -> list:
    """
    Fetches all transactions for a user, ordered by timestamp descending.
    Returns a list of transaction dictionaries or an empty list.
    """
    user_data = get_user_data_sqlite(db_path, username)
    if not user_data:
        logging.info("No transactions found for '%s': User not found.", username)
        return []

    user_id = user_data['id']
    try:
        with sqlite3.connect(db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("""
                SELECT type, amount, timestamp FROM transactions
                WHERE user_id = ? ORDER BY timestamp DESC
            """, (user_id,))
            transactions = [dict(row) for row in cursor.fetchall()]
            logging.info("Retrieved %d transactions for user '%s' (ID: %d) from SQLite.", len(transactions), username, user_id)
            return transactions
    except sqlite3.Error as e:
        logging.error("Error fetching transactions for user '%s' (ID: %d) from SQLite: %s", username, user_id, e)
        return []


def is_number(s: str) -> bool:
    """
    Check if the string can be interpreted as a number.
    
    Args:
        s (str): The string to check.
    
    Returns:
        bool: True if s is numeric, False otherwise.
    """
    try:
        float(s)
        return True
    except ValueError:
        return False


def check_password_strength(password: str) -> dict:
    score = 0
    feedback = {'level': '', 'text': '', 'color': 'black'} # Default color

    if not password:
        # Return empty feedback for empty password, color will be default label color
        return {'level': 'None', 'text': '', 'color': ''} 

    # Criteria checks
    if len(password) >= 8:
        score += 1
    if re.search(r"[a-z]", password):
        score += 1
    if re.search(r"[A-Z]", password):
        score += 1
    if re.search(r"[0-9]", password):
        score += 1
    # Define a set of common special characters
    # Note: Adjust the regex character set for special characters as needed.
    # Escaping is important for some characters within a regex set, e.g., ] \ - ^
    if re.search(r"[!@#$%^&*()_+\-=\[\]{};':"\|,.<>\/?~`]", password):
        score += 1
    
    # Bonus for longer length
    if len(password) >= 12:
        score += 1 # Max score can be 6

    # Map score to feedback
    if score <= 1:
        feedback['level'] = 'Too Weak'
        feedback['text'] = 'Strength: Too Weak'
        feedback['color'] = 'red'
    elif score == 2:
        feedback['level'] = 'Weak'
        feedback['text'] = 'Strength: Weak'
        feedback['color'] = 'orange red'
    elif score >= 3 and score <= 4:
        feedback['level'] = 'Medium'
        feedback['text'] = 'Strength: Medium'
        # Using a more common/safer yellow, Tkinter might not have DarkGoldenrod1 by default on all systems
        # Or fallback to black text if yellow is hard to see.
        feedback['color'] = 'gold' 
    elif score >= 5: # Covers 5 and 6
        feedback['level'] = 'Strong'
        feedback['text'] = 'Strength: Strong'
        feedback['color'] = 'forest green'
    
    # Safety net if somehow score is out of expected range, though unlikely with current logic
    if not feedback['level']: # If somehow no level was set
        if score > 4: feedback['level'] = 'Strong'
        elif score > 2: feedback['level'] = 'Medium'
        elif score > 1: feedback['level'] = 'Weak'
        else: feedback['level'] = 'Too Weak'
        feedback['text'] = f"Strength: {feedback['level']}"
        feedback['color'] = 'black' # Fallback color

    return feedback

# --- Password Hashing (New Implementation) ---
ITERATIONS = 260000 # Recommended by OWASP for PBKDF2-SHA256 as of a few years ago.

# --- Login Attempt Constants ---
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 2 # For easier testing, as requested

# --- Session Timeout Constants ---
SESSION_TIMEOUT_MINUTES = 1 # Use 1 minute for easier testing for now
SESSION_CHECK_INTERVAL_SECONDS = 30 # Check every 30 seconds


def hash_password_old_sha256(password: str) -> str:
    """
    Return the direct SHA-256 hash of the given password (old method, kept for migration/verification).
    
    Args:
        password (str): The password to hash.
    
    Returns:
        str: The hexadecimal digest of the password.
    """
    return hashlib.sha256(password.encode('utf-8')).hexdigest()


def hash_password(password: str) -> str:
    """
    Hashes a password using PBKDF2-SHA256.
    Stores algorithm, iterations, salt, and key in a single string.
    Format: "pbkdf2_sha256$<iterations>$<salt_hex>$<key_hex>"
    """
    salt = os.urandom(16)  # 16 bytes salt is a common size
    key = hashlib.pbkdf2_hmac(
        'sha256',                # Hash algorithm
        password.encode('utf-8'),# Password to hash
        salt,                    # Salt
        ITERATIONS,              # Iteration count
        dklen=32                 # Derived key length (32 bytes = 256 bits)
    )
    # Store all necessary info to verify the password later
    return f"pbkdf2_sha256${ITERATIONS}${salt.hex()}${key.hex()}"


def verify_password(password_attempt: str, full_hashed_password_string: str) -> bool:
    """
    Verifies a password attempt against a stored hashed password string.
    Handles both the new PBKDF2-SHA256 format and the old direct SHA-256 format.
    """
    if not full_hashed_password_string:
        logging.warning("Verification attempt against an empty hash string.")
        return False

    if '$' not in full_hashed_password_string:
        # Potentially an old SHA-256 hash (64 hex characters)
        if len(full_hashed_password_string) == 64:
            try:
                # Validate it's a hex string; actual value doesn't matter here
                int(full_hashed_password_string, 16) 
                expected_hash_old = hash_password_old_sha256(password_attempt)
                logging.info("Attempting password verification using old SHA-256 method.")
                return hashlib.compare_digest(expected_hash_old, full_hashed_password_string)
            except ValueError:
                logging.warning("Hash string (no '$') is not a valid hex string. Old format verification failed.")
                return False # Not a valid hex string
        else:
            logging.warning(f"Malformed hash string: No '$' delimiter and not 64 chars. Got {len(full_hashed_password_string)} chars.")
            return False # Not old format, not new format
    
    # Assuming new PBKDF2 format: "pbkdf2_sha256$<iterations>$<salt_hex>$<key_hex>"
    parts = full_hashed_password_string.split('$')
    if len(parts) != 4:
        logging.warning(f"Malformed PBKDF2 hash string: Expected 4 parts, got {len(parts)}. Hash starts with: {full_hashed_password_string[:30]}...")
        return False

    algorithm, iterations_str, salt_hex, stored_key_hex = parts

    if algorithm != 'pbkdf2_sha256':
        logging.warning(f"Unsupported hash algorithm: '{algorithm}'. Expected 'pbkdf2_sha256'.")
        return False

    try:
        iterations = int(iterations_str)
        if iterations <= 0: # Iterations must be positive
            logging.warning(f"Invalid iteration count in hash: {iterations}. Must be positive.")
            return False
        salt_bytes = bytes.fromhex(salt_hex)
        stored_key_bytes = bytes.fromhex(stored_key_hex)
    except ValueError as e:
        logging.error(f"Error converting parts of PBKDF2 hash (iterations, salt, or key): {e}. Hash starts with: {full_hashed_password_string[:30]}...")
        return False
    
    # Validate expected lengths after conversion
    if len(salt_bytes) != 16: # Salt was generated as 16 bytes
        logging.warning(f"Decoded salt length is {len(salt_bytes)}, expected 16.")
        return False
    if len(stored_key_bytes) != 32: # Key was derived as 32 bytes (dklen=32)
        logging.warning(f"Decoded key length is {len(stored_key_bytes)}, expected 32.")
        return False

    # Calculate the key from the password attempt using the stored parameters
    new_key_bytes = hashlib.pbkdf2_hmac(
        'sha256',
        password_attempt.encode('utf-8'),
        salt_bytes,
        iterations,
        dklen=32
    )

    # Compare the derived keys using a time-constant comparison
    is_correct = hashlib.compare_digest(new_key_bytes, stored_key_bytes)
    if is_correct:
        logging.info("Password verification successful (PBKDF2-SHA256).")
    else:
        logging.info("Password verification failed (PBKDF2-SHA256).")
    return is_correct
# --- End Password Hashing ---


def load_user_data_pickle(pickle_path: str = "appData.bin") -> list:
    """
    Load user data from a binary pickle file.
    Ensures each user has a 'transactions' key.
    Returns an empty list if the file does not exist or if an error occurs.
    """
    if not os.path.exists(pickle_path):
        logging.info("Pickle data file (%s) does not exist. Returning empty list.", pickle_path)
        return []
    try:
        with open(pickle_path, 'rb') as f:
            data = pickle.load(f)
            # Ensure each user has a 'transactions' key for compatibility
            for user in data:
                if 'transactions' not in user:
                    user['transactions'] = []
            logging.info("User data loaded successfully from pickle file: %s", pickle_path)
            return data
    except FileNotFoundError: # Should be caught by os.path.exists, but as a safeguard
        logging.error("Pickle file %s not found during load attempt.", pickle_path)
        return []
    except pickle.UnpicklingError as e:
        logging.error("Error unpickling data from %s: %s", pickle_path, e)
        return []
    except Exception as e: # Catch any other unexpected errors during loading
        logging.error("Unexpected error loading user data from pickle file %s: %s", pickle_path, e)
        return []


# def load_user_data() -> list: # Removed - Using SQLite
#     """
#     Load user data from a binary file. Returns an empty list if the file does not exist or if an error occurs.
    
#     Returns:
#         list: A list of user dictionaries.
#     """
#     if not os.path.exists(DATA_FILE):
#         logging.info("Data file does not exist. Returning empty list.")
#         return []
#     try:
#         with open(DATA_FILE, 'rb') as f:
#             data = pickle.load(f)
#             # Ensure each user has a 'transactions' key
#             for user in data:
#                 if 'transactions' not in user:
#                     user['transactions'] = []
#             logging.info("User data loaded successfully.")
#             return data
#     except Exception as e:
#         logging.error("Error loading user data: %s", e)
#         return []


# def save_user_data(data: list) -> None: # Removed - Using SQLite
#     """
#     Save user data list to a binary file.
    
#     Args:
#         data (list): The user data list to save.
#     """
#     try:
#         with open(DATA_FILE, 'wb') as f:
#             pickle.dump(data, f)
#             logging.info("User data saved successfully.")
#     except Exception as e:
#         logging.error("Error saving user data: %s", e)


def migrate_pickle_to_sqlite(db_path: str = DB_PATH, pickle_path: str = "appData.bin") -> tuple[int, int]:
    """
    Migrates user data from a pickle file to an SQLite database.
    Returns a tuple of (migrated_users_count, migrated_transactions_count).
    """
    logging.info("Starting migration from pickle file '%s' to SQLite DB '%s'", pickle_path, db_path)
    
    users_data = load_user_data_pickle(pickle_path)
    if not users_data:
        logging.info("No data found in pickle file '%s'. Migration terminated.", pickle_path)
        return 0, 0

    migrated_users_count = 0
    migrated_transactions_count = 0

    for user in users_data:
        try:
            uname = user.get("uname")
            pass_hash = user.get("pass") # Already hashed in pickle file
            name = user.get("name")
            age = user.get("age")
            gender = user.get("gender")
            balance = user.get("balance", 0) # Default balance to 0 if not present
            transactions = user.get("transactions", [])

            if not all([uname, pass_hash, name, age is not None, gender is not None]):
                logging.warning("Skipping user due to missing core data: %s", uname or "Unknown user")
                continue
            
            if create_user_sqlite(db_path, uname, pass_hash, name, int(age), int(gender), int(balance)):
                migrated_users_count += 1
                logging.info("User '%s' migrated successfully to SQLite.", uname)
                
                for tx in transactions:
                    tx_type = tx.get('type')
                    tx_amount = tx.get('amount')
                    tx_timestamp = tx.get('timestamp')
                    if not all([tx_type, tx_amount is not None, tx_timestamp]):
                        logging.warning("Skipping transaction for user '%s' due to missing transaction data: %s", uname, tx)
                        continue
                    
                    if record_transaction_sqlite(db_path, uname, tx_type, int(tx_amount), tx_timestamp):
                        migrated_transactions_count += 1
                    else:
                        logging.warning("Failed to migrate a transaction for user '%s'. Details: %s", uname, tx)
            else:
                logging.warning("User '%s' already exists in SQLite or could not be created. Skipping migration for this user.", uname)
        except Exception as e:
            logging.error("An unexpected error occurred during migration for user '%s': %s", user.get("uname", "Unknown"), e)
            # Decide if you want to continue with the next user or stop. For now, continuing.

    logging.info("Migration completed. Migrated %d users and %d transactions.", migrated_users_count, migrated_transactions_count)
    return migrated_users_count, migrated_transactions_count


class BankApp:
    """
    A Tkinter-based bank application that allows user registration, login, deposit,
    withdrawal, and viewing of personal information.
    """

    def __init__(self, master: Tk) -> None:
        """
        Initialize the BankApp with a master Tk window.
        
        Args:
            master (Tk): The main Tkinter window.
        """
        self.master = master
        self.master.title("Login Page")
        self.master.geometry("500x450")
        self.master.configure(bg="white")
        self.master.resizable(False, False)

        # Current user info will be stored here after login.
        self.current_user = None

        # Variables for login screen.
        self.username_var = StringVar()
        self.password_var = StringVar()

        # Session management attributes
        self.last_activity_time = None
        self.session_check_timer_id = None
        self.open_windows = {} # To store references like {'dashboard': dashboard_window}
        
        # Apply a ttk theme
        style = ttk.Style()
        try:
            # Attempt to use 'clam', a common modern theme
            style.theme_use('clam') 
        except Exception as e:
            logging.warning(f"Failed to apply 'clam' theme, using default: {e}")
            # Fallback to default if 'clam' is not available or fails
            # Ensure a theme is actually available before trying to use its name
            available_themes = style.theme_names()
            if available_themes:
                style.theme_use(available_themes[0])
            else:
                logging.error("No ttk themes available.")
        
        # Define custom styles for buttons for better contrast and visual hierarchy
        # Accent button for primary actions (e.g., Login, Register, Deposit, Withdraw)
        style.configure("Accent.TButton", foreground="white", background="#007bff", font=("Arial", 10, "bold"))
        style.map("Accent.TButton",
            background=[('active', '#0056b3'), ('pressed', '#004085')],
            foreground=[('active', 'white')])

        # Link button for secondary actions (e.g., Sign Up, Sign In links)
        style.configure("Link.TButton", foreground="#007bff", relief="flat", borderwidth=0)
        style.map("Link.TButton",
            foreground=[('active', '#0056b3'), ('pressed', '#004085')],
            underline=[('active', True)])
        
        # Standard buttons will use the default 'clam' TButton style which generally has good contrast.
        # If specific adjustments were needed for the eye toggle button, it could be:
        # style.configure("Eye.TButton", font=("Arial", 12), padding=2) 
        # For now, default TButton for the eye toggle.

        self.create_login_screen()

    def create_login_screen(self) -> None:
        """Create and display the login screen."""
        # Clear any existing widgets.
        for widget in self.master.winfo_children():
            widget.destroy()

        Label(self.master, text="LOGIN", font=("Arial", 40), bg="white").pack(pady=30)

        frame = Frame(self.master, bg="white")
        frame.pack()

        Label(frame, text="Username", font=("Arial", 20), bg="white").grid(
            row=0, column=0, pady=10, padx=10, sticky=E
        )
        entry_username = ttk.Entry(frame, font=("Arial", 18), textvariable=self.username_var, justify="center")
        entry_username.grid(row=0, column=1, pady=10, padx=10)

        Label(frame, text="Password", font=("Arial", 20), bg="white").grid(
            row=1, column=0, pady=10, padx=10, sticky=E
        )
        self.entry_password = ttk.Entry(
            frame, font=("Arial", 18), textvariable=self.password_var, show="⭕", justify="center"
        )
        self.entry_password.grid(row=1, column=1, pady=10, padx=10)

        # Toggle password visibility button.
        # Note: ttk.Button may not support bg/fg and border styling as directly as tk.Button.
        # Theme will handle styling. Font can be set via ttk.Style if needed globally.
        btn_toggle = ttk.Button(
            frame, text="👁",
            command=self.toggle_password_visibility
            # Using default TButton style from 'clam', which should be clear.
            # If specific styling like "Eye.TButton" was defined above, it would be used here.
        )
        btn_toggle.grid(row=1, column=2, padx=5)

        ttk.Button(self.master, text="Login", command=self.do_login, style="Accent.TButton").pack(pady=20)

        Label(self.master, text="Don't have an account?", font=("Arial", 15), bg="white").pack()
        ttk.Button(
            self.master, text="Sign Up",
            command=self.create_register_screen, style="Link.TButton"
        ).pack(pady=10)

    def toggle_password_visibility(self) -> None:
        """Toggle between hidden and visible password on the login screen."""
        if self.entry_password.cget("show") == "⭕":
            self.entry_password.config(show="")
        else:
            self.entry_password.config(show="⭕")

    def do_login(self) -> None:
        """Process login using provided credentials."""
        username = self.username_var.get().strip()
        password = self.password_var.get().strip()

        # 1. Check for existing lockout
        attempt_info = get_login_attempt_info(DB_PATH, username)
        if attempt_info:
            lockout_until_str = attempt_info.get('lockout_until')
            if lockout_until_str:
                try:
                    lockout_datetime = datetime.strptime(lockout_until_str, '%Y-%m-%d %H:%M:%S')
                    if datetime.now() < lockout_datetime:
                        remaining_time = lockout_datetime - datetime.now()
                        # Calculate remaining minutes and seconds for a more user-friendly message
                        remaining_minutes = int(remaining_time.total_seconds() // 60)
                        remaining_seconds = int(remaining_time.total_seconds() % 60)
                        
                        time_left_str = ""
                        if remaining_minutes > 0:
                            time_left_str += f"{remaining_minutes} minute(s)"
                        if remaining_seconds > 0:
                            if time_left_str: time_left_str += " and "
                            time_left_str += f"{remaining_seconds} second(s)"
                        if not time_left_str: # Should not happen if datetime.now() < lockout_datetime
                            time_left_str = "a short while"

                        messagebox.showerror(
                            "Login Failed",
                            f"Account for '{username}' is temporarily locked. Please try again in {time_left_str}."
                        )
                        logging.warning(f"Login attempt for locked account '{username}'. Lockout active until {lockout_datetime.strftime('%Y-%m-%d %H:%M:%S')}.")
                        return
                except ValueError:
                    logging.error(f"Could not parse lockout_until string '{lockout_until_str}' for user '{username}'. Allowing login attempt.")


        # Proceed with login attempt
        user_data = get_user_data_sqlite(DB_PATH, username)
        
        if user_data and verify_password(password, user_data["password_hash"]):
            # 3. Successful login: Reset login attempts
            reset_login_attempts(DB_PATH, username)

            stored_hash = user_data["password_hash"]
            # Check for old hash format and upgrade if necessary
            if '$' not in stored_hash and len(stored_hash) == 64: # Heuristic for old SHA256 hash
                logging.info(f"User '{username}' logged in with an old format password hash. Attempting to upgrade.")
                try:
                    new_secure_hash = hash_password(password) # Generate new PBKDF2 hash
                    if update_user_password_hash_sqlite(DB_PATH, username, new_secure_hash):
                        user_data["password_hash"] = new_secure_hash # Update hash in current session's data
                        logging.info(f"Password hash for user '{username}' successfully updated to new format in DB.")
                    else:
                        # If DB update fails, log warning but proceed with login for this session
                        logging.warning(f"Failed to update password hash in DB for user '{username}'. Login will proceed with old hash for this session.")
                except Exception as e:
                    logging.error(f"An unexpected error occurred during password hash upgrade for user '{username}': {e}")
                    # Log error but proceed with login as verification was successful.

            # Convert column names to match existing app's expectations if necessary
            # For example, 'username' -> 'uname', 'full_name' -> 'name', 'password_hash' -> 'pass'
            self.current_user = {
                'id': user_data['id'],
                'uname': user_data['username'],
                'pass': user_data['password_hash'],
                'name': user_data['full_name'],
                'age': user_data['age'],
                'gender': user_data['gender'],
                'balance': user_data['balance'],
                'transactions': get_user_transactions_sqlite(DB_PATH, username) # Fetch transactions on login
            }
            messagebox.showinfo("Success", "Login Successful")
            logging.info("User '%s' logged in successfully.", username)
            self.start_session_timer() # Start session timer on successful login
            self.show_dashboard()
        else:
            # 2. Failed login attempt: Record it
            # We record the failure regardless of whether the user exists or not,
            # as per instructions, tied to the entered username.
            record_failed_login_attempt(DB_PATH, username)
            
            # Check if this attempt caused a lockout to provide a more specific message
            # This is an optional refinement.
            updated_attempt_info = get_login_attempt_info(DB_PATH, username)
            if updated_attempt_info and updated_attempt_info.get('lockout_until'):
                 lockout_datetime_str = updated_attempt_info.get('lockout_until')
                 try:
                    lockout_dt = datetime.strptime(lockout_datetime_str, '%Y-%m-%d %H:%M:%S')
                    if datetime.now() < lockout_dt : # Check if lockout is now active
                        remaining_time = lockout_dt - datetime.now()
                        remaining_minutes = int(remaining_time.total_seconds() // 60)
                        remaining_seconds = int(remaining_time.total_seconds() % 60)
                        time_left_str = ""
                        if remaining_minutes > 0: time_left_str += f"{remaining_minutes} minute(s)"
                        if remaining_seconds > 0: 
                            if time_left_str: time_left_str += " and "
                            time_left_str += f"{remaining_seconds} second(s)"
                        if not time_left_str: time_left_str = "a short while"
                        
                        messagebox.showerror(
                            "Login Failed",
                            f"Incorrect username or password. Account for '{username}' is now locked due to too many failed attempts. Please try again in {time_left_str}."
                        )
                        logging.warning(f"Failed login attempt for username: '{username}'. Account now locked.")
                        return # Return after showing lockout message
                 except ValueError:
                    pass # If parsing fails, fall through to generic message

            messagebox.showerror("Login Failed", "Incorrect Username or Password")
            logging.warning("Failed login attempt for username: %s", username)


    def create_register_screen(self) -> None:
        """Display the registration window."""
        self.master.withdraw()
        register_window = Toplevel(self.master)
        self.open_windows['register'] = register_window # Add to tracking
        register_window.title("Sign Up")
        register_window.geometry("500x550")
        register_window.configure(bg="white")
        register_window.resizable(False, False)

        reg_vars = {
            "username": StringVar(),
            "full_name": StringVar(),
            "age": StringVar(),
            "gender": IntVar(),  # 1 for Male, 0 for Female.
            "balance": StringVar(),
            "password": StringVar()
        }

        def back_to_login() -> None:
            self.open_windows.pop('register', None) # Remove from tracking
            register_window.destroy()
            self.master.deiconify()

        def save_user() -> None:
            uname = reg_vars["username"].get().strip()
            full_name = reg_vars["full_name"].get().strip()
            age_str = reg_vars["age"].get().strip()
            gender = reg_vars["gender"].get()
            balance_str = reg_vars["balance"].get().strip()
            passwd = reg_vars["password"].get().strip()

            if not uname or not full_name or not age_str or not balance_str or not passwd:
                messagebox.showerror("Missing Data", "All fields are required.")
                return

            if not all(part.isalpha() for part in full_name.split()):
                messagebox.showerror("Invalid Name", "Please enter only alphabets in Full Name.")
                return
            if not is_number(balance_str):
                messagebox.showerror("Invalid Balance", "Balance must be numeric.")
                return
            if not is_number(age_str):
                messagebox.showerror("Invalid Age", "Age must be numeric.")
                return

            age = int(age_str)
            if age <= 0 or age >= 150:
                messagebox.showerror("Invalid Age", "Please provide a valid age.")
                return

            balance = int(float(balance_str))
            
            hashed_password = hash_password(passwd)

            # Confirmation Dialog for Registration
            if messagebox.askyesno("Confirm Registration", "Are you sure you want to register with these details?"):
                if create_user_sqlite(DB_PATH, uname, hashed_password, full_name, age, gender, balance):
                    messagebox.showinfo("Success", "User Registered Successfully")
                    logging.info("New user registered: %s", uname)
                    # Optionally pre-fetch transactions or handle as part of login
                    # For now, new users have no transactions, so an empty list is fine.
                    # self.current_user['transactions'] = [] 
                    back_to_login()
                else:
                    # Error message for username exists is handled by create_user_sqlite logging,
                    # but a user-facing message is also good.
                    messagebox.showerror("Registration Failed", "Username may already exist or another error occurred.")
            # If user clicks "No", they remain on the registration screen with data intact.

        Label(register_window, text="Sign Up", font=("Arial", 40), bg="white").pack(pady=20)
        form_frame = Frame(register_window, bg="white")
        form_frame.pack(pady=10)

        Label(form_frame, text="Username", font=("Arial", 20), bg="white").grid(row=0, column=0, pady=5, padx=10, sticky=E)
        ttk.Entry(form_frame, font=("Arial", 18), textvariable=reg_vars["username"], justify="center").grid(row=0, column=1, pady=5, padx=10)

        Label(form_frame, text="Full Name", font=("Arial", 20), bg="white").grid(row=1, column=0, pady=5, padx=10, sticky=E)
        ttk.Entry(form_frame, font=("Arial", 18), textvariable=reg_vars["full_name"], justify="center").grid(row=1, column=1, pady=5, padx=10)

        Label(form_frame, text="Age", font=("Arial", 20), bg="white").grid(row=2, column=0, pady=5, padx=10, sticky=E)
        ttk.Entry(form_frame, font=("Arial", 18), textvariable=reg_vars["age"], justify="center").grid(row=2, column=1, pady=5, padx=10)

        Label(form_frame, text="Gender", font=("Arial", 20), bg="white").grid(row=3, column=0, pady=5, padx=10, sticky=E)
        gender_frame = Frame(form_frame, bg="white") # Frame bg might be overridden by theme on children
        gender_frame.grid(row=3, column=1, pady=5, padx=10)
        # Font for ttk.Radiobutton can be set via style if needed
        ttk.Radiobutton(gender_frame, text="Male", variable=reg_vars["gender"], value=1).pack(side=LEFT, padx=5)
        ttk.Radiobutton(gender_frame, text="Female", variable=reg_vars["gender"], value=0).pack(side=LEFT, padx=5)

        Label(form_frame, text="Balance", font=("Arial", 20), bg="white").grid(row=4, column=0, pady=5, padx=10, sticky=E)
        ttk.Entry(form_frame, font=("Arial", 18), textvariable=reg_vars["balance"], justify="center").grid(row=4, column=1, pady=5, padx=10)

        Label(form_frame, text="Password", font=("Arial", 20), bg="white").grid(row=5, column=0, pady=5, padx=10, sticky=E)
        password_entry_field = ttk.Entry(form_frame, font=("Arial", 18), textvariable=reg_vars["password"], justify="center", show="*")
        password_entry_field.grid(row=5, column=1, pady=5, padx=10)

        # Password strength feedback label
        # This label will be updated by a trace on reg_vars["password"] in the next step.
        # Storing it on self.password_strength_feedback_label to make it accessible if the callback is a method,
        # or it can be accessed via closure if the callback is a nested function.
        # For now, let's assume it will be accessed via closure or passed to the callback setup.
        password_strength_feedback_label = ttk.Label(form_frame, text="", font=("Arial", 10), foreground="grey")
        password_strength_feedback_label.grid(row=6, column=1, sticky="w", padx=10, pady=(0,5)) # pady=(0,5) adds a little space below it

        # Callback function for password strength
        def update_password_strength_feedback(*args):
            current_password = reg_vars["password"].get()
            feedback = check_password_strength(current_password)
            # The label is defined in the outer scope of create_register_screen,
            # so it's accessible here via closure.
            password_strength_feedback_label.config(
                text=feedback['text'], 
                foreground=feedback['color'] if feedback['color'] else 'grey' # Default to grey
            )

        # Add trace after both the StringVar and the Label are defined
        reg_vars["password"].trace_add('write', update_password_strength_feedback)

        ttk.Button(register_window, text="Register", command=save_user, style="Accent.TButton").pack(pady=20)
        Label(register_window, text="Already have an account?", font=("Arial", 15), bg="white").pack()
        ttk.Button(register_window, text="Sign In", command=back_to_login, style="Link.TButton").pack(pady=10)

    def show_dashboard(self) -> None:
        """Display the dashboard with options for deposit, withdrawal, and personal information."""
        dashboard = Toplevel(self.master)
        # Close any lingering dashboard if one somehow exists (defensive)
        if 'dashboard' in self.open_windows and self.open_windows['dashboard'].winfo_exists():
            self.open_windows['dashboard'].destroy()
        self.open_windows['dashboard'] = dashboard
        self.update_last_activity_time() # Activity: dashboard shown
        # self.start_session_timer() was already called in do_login

        dashboard.title("Dashboard")
        dashboard.geometry("500x350")
        dashboard.configure(bg="white")
        dashboard.resizable(False, False)

        Label(dashboard, text=f"Welcome {self.current_user['uname']}", font=("Arial", 30), bg="white").pack(pady=20)
        balance_label = Label(dashboard, text=f"Balance: {self.current_user['balance']}", font=("Arial", 15), bg="white")
        balance_label.pack()

        def logout() -> None:
            if messagebox.askyesno("Confirm Logout", "Are you sure you want to logout?"):
                self.cancel_session_timer()
                self.open_windows.pop('dashboard', None) # Explicitly remove before destroy
                self.current_user = None
                dashboard.destroy()
                self.create_login_screen()
                self.master.deiconify()
        
        ttk.Button(dashboard, text="Deposit",
                   command=lambda: self.show_deposit(dashboard, balance_label)).pack(pady=5)
        ttk.Button(dashboard, text="Withdraw",
                   command=lambda: self.show_withdraw(dashboard, balance_label)).pack(pady=5)
        ttk.Button(dashboard, text="Personal Info",
                   command=lambda: self.show_personal_info(dashboard)).pack(pady=5)
        ttk.Button(dashboard, text="Transaction History",
                   command=lambda: self.show_transaction_history(dashboard, balance_label)).pack(pady=5)
        ttk.Button(dashboard, text="Logout", command=logout).pack(pady=20) # Already updated to call the wrapped logout

    def update_user_balance(self, new_balance: int) -> None:
        """
        Update the current user's balance and persist the change.
        
        Args:
            new_balance (int): The new balance value.
        """
        if update_user_balance_sqlite(DB_PATH, self.current_user["uname"], new_balance):
            self.current_user["balance"] = new_balance # Update current_user in memory
            logging.info("User '%s' balance updated to %d in app and SQLite.", self.current_user["uname"], new_balance)
        else:
            # This case should ideally not happen if username is validated, but good for robustness
            logging.error("Failed to update balance for user '%s' in SQLite from update_user_balance.", self.current_user["uname"])
            messagebox.showerror("Error", "Failed to update balance in the database.")


    def show_deposit(self, parent: Toplevel, balance_label: Label) -> None:
        """Display the deposit window."""
        self.start_session_timer() # User performed an action, reset timeout timer
        deposit_win = Toplevel(parent)
        deposit_win.title("Deposit")
        deposit_win.geometry("500x350")
        deposit_win.configure(bg="white")
        deposit_win.resizable(False, False)

        amount_var = StringVar()

        Label(deposit_win, text=f"User: {self.current_user['uname']}", font=("Arial", 12), bg="white").pack(anchor="w", padx=20, pady=10)
        bal_lbl = Label(deposit_win, text=f"Balance: {self.current_user['balance']}", font=("Arial", 12), bg="white")
        bal_lbl.pack(anchor="e", padx=20, pady=10)

        Label(deposit_win, text="Amount:", font=("Arial", 15), bg="white").pack(pady=10)
        ttk.Entry(deposit_win, font=("Arial", 15), textvariable=amount_var, justify="center").pack(pady=10)

        def deposit_process() -> None:
            amount = amount_var.get().strip()
            if not is_number(amount):
                messagebox.showerror("Invalid Amount", "Please provide only numeric data")
                return
            if int(amount) <= 0:
                messagebox.showerror("Invalid Amount", "Amount must be greater than zero")
                return
            
            transaction = {
                'type': 'deposit',
                'amount': int(amount),
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            # Record transaction in SQLite first
            if record_transaction_sqlite(DB_PATH, self.current_user["uname"], transaction['type'], transaction['amount'], transaction['timestamp']):
                # Update balance in SQLite and in-memory current_user object
                new_balance = int(self.current_user['balance']) + int(amount)
                self.update_user_balance(new_balance) # This now updates SQLite and self.current_user

                # Update UI
                messagebox.showinfo("Success", "Deposit Successful")
                bal_lbl.config(text=f"Balance: {new_balance}")
                balance_label.config(text=f"Balance: {new_balance}")
                
                # Update in-memory transaction list for the current session
                self.current_user['transactions'].append(transaction)
                logging.info("Deposit transaction processed and recorded for %s.", self.current_user["uname"])
                self.start_session_timer() # User performed an action, reset timeout timer
            else:
                messagebox.showerror("Deposit Failed", "Could not record the transaction in the database.")
                logging.error("Failed to record deposit transaction for %s in SQLite.", self.current_user["uname"])


        ttk.Button(deposit_win, text="Deposit", command=deposit_process, style="Accent.TButton").pack(pady=10)
        ttk.Button(deposit_win, text="Back", command=deposit_win.destroy).pack(side="right", padx=20, pady=20)
        
        def confirm_logout_from_deposit():
            if messagebox.askyesno("Confirm Logout", "Are you sure you want to logout?"):
                deposit_win.destroy()
                parent.destroy() # This is the dashboard window
                self.create_login_screen()
                self.master.deiconify()
        
        ttk.Button(deposit_win, text="Logout", command=confirm_logout_from_deposit).pack(side="left", padx=20, pady=20)

    def show_withdraw(self, parent: Toplevel, balance_label: Label) -> None:
        """Display the withdrawal window."""
        self.start_session_timer() # User performed an action, reset timeout timer
        withdraw_win = Toplevel(parent)
        withdraw_win.title("Withdraw")
        withdraw_win.geometry("500x350")
        withdraw_win.configure(bg="white")
        withdraw_win.resizable(False, False)

        amount_var = StringVar()

        Label(withdraw_win, text=f"User: {self.current_user['uname']}", font=("Arial", 12), bg="white").pack(anchor="w", padx=20, pady=10)
        bal_lbl = Label(withdraw_win, text=f"Balance: {self.current_user['balance']}", font=("Arial", 12), bg="white")
        bal_lbl.pack(anchor="e", padx=20, pady=10)

        Label(withdraw_win, text="Amount:", font=("Arial", 15), bg="white").pack(pady=10)
        ttk.Entry(withdraw_win, font=("Arial", 15), textvariable=amount_var, justify="center").pack(pady=10)

        def withdraw_process() -> None:
            amount = amount_var.get().strip()
            if not is_number(amount):
                messagebox.showerror("Invalid Amount", "Please provide only numeric data")
                return
            if int(amount) <= 0:
                messagebox.showerror("Invalid Amount", "Amount must be greater than zero")
                return
            if int(self.current_user['balance']) - int(amount) < 0:
                messagebox.showerror("Invalid Amount", "Insufficient funds")
                return

            transaction = {
                'type': 'withdrawal',
                'amount': int(amount),
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            
            # Record transaction in SQLite first
            if record_transaction_sqlite(DB_PATH, self.current_user["uname"], transaction['type'], transaction['amount'], transaction['timestamp']):
                # Update balance in SQLite and in-memory current_user object
                new_balance = int(self.current_user['balance']) - int(amount)
                self.update_user_balance(new_balance) # This now updates SQLite and self.current_user

                # Update UI
                messagebox.showinfo("Success", f"Withdraw successful of ${amount}")
                bal_lbl.config(text=f"Balance: {new_balance}")
                balance_label.config(text=f"Balance: {new_balance}")

                # Update in-memory transaction list for the current session
                self.current_user['transactions'].append(transaction)
                logging.info("Withdrawal transaction processed and recorded for %s.", self.current_user["uname"])
                self.start_session_timer() # User performed an action, reset timeout timer
            else:
                messagebox.showerror("Withdrawal Failed", "Could not record the transaction in the database.")
                logging.error("Failed to record withdrawal transaction for %s in SQLite.", self.current_user["uname"])

        ttk.Button(withdraw_win, text="Withdraw", command=withdraw_process, style="Accent.TButton").pack(pady=10)
        ttk.Button(withdraw_win, text="Back", command=withdraw_win.destroy).pack(side="right", padx=20, pady=20)

        def confirm_logout_from_withdraw():
            if messagebox.askyesno("Confirm Logout", "Are you sure you want to logout?"):
                withdraw_win.destroy()
                parent.destroy() # This is the dashboard window
                self.create_login_screen()
                self.master.deiconify()

        ttk.Button(withdraw_win, text="Logout", command=confirm_logout_from_withdraw).pack(side="left", padx=20, pady=20)

    def show_personal_info(self, parent: Toplevel) -> None:
        """Display a window showing the personal information of the current user."""
        self.start_session_timer() # User performed an action, reset timeout timer
        info_win = Toplevel(parent)
        info_win.title("Personal Information")
        info_win.geometry("500x350")
        info_win.configure(bg="white")
        info_win.resizable(False, False)

        Label(info_win, text=f"Personal Data of {self.current_user['uname']}", font=("Arial", 30), bg="white").pack(pady=10)
        Label(info_win, text=f"Name: {self.current_user['name']}", font=("Arial", 18), bg="white").pack(pady=5)
        Label(info_win, text=f"Age: {self.current_user['age']}", font=("Arial", 18), bg="white").pack(pady=5)
        gender_str = "Male" if self.current_user['gender'] else "Female"
        Label(info_win, text=f"Gender: {gender_str}", font=("Arial", 18), bg="white").pack(pady=5)
        Label(info_win, text=f"Balance: {self.current_user['balance']}", font=("Arial", 18), bg="white").pack(pady=5)

        def back_to_dashboard() -> None:
            info_win.destroy()
            parent.deiconify()

        def confirm_logout_from_personal_info():
            if messagebox.askyesno("Confirm Logout", "Are you sure you want to logout?"):
                info_win.destroy()
                parent.destroy() # This is the dashboard window
                self.create_login_screen()
                self.master.deiconify()
        
        ttk.Button(info_win, text="Back", command=back_to_dashboard).pack(side="right", padx=20, pady=20)
        ttk.Button(info_win, text="Logout", command=confirm_logout_from_personal_info).pack(side="left", padx=20, pady=20)

    def show_transaction_history(self, parent: Toplevel, balance_label: Label) -> None:
        """Display the transaction history window."""
        self.start_session_timer() # User performed an action, reset timeout timer
        history_win = Toplevel(parent)
        history_win.title("Transaction History")
        history_win.geometry("600x400")
        history_win.configure(bg="white")
        history_win.resizable(False, False)

        Label(history_win, text=f"Transaction History for {self.current_user['uname']}", font=("Arial", 20), bg="white").pack(pady=10)

        cols = ("Timestamp", "Type", "Amount")
        tree = ttk.Treeview(history_win, columns=cols, show="headings")
        for col in cols:
            tree.heading(col, text=col)
            tree.column(col, width=180, anchor=CENTER)
        
        # Add a scrollbar
        scrollbar = ttk.Scrollbar(history_win, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        tree.pack(expand=True, fill="both", padx=10, pady=10)

        # Fetch fresh transactions from SQLite when displaying history
        transactions = get_user_transactions_sqlite(DB_PATH, self.current_user["uname"])
        # Update current_user's transactions list in memory as well, if desired, or always fetch fresh.
        # For simplicity here, we'll rely on fetching fresh each time history is shown.
        # self.current_user['transactions'] = transactions 

        if not transactions:
            Label(history_win, text="No transactions yet.", font=("Arial", 15), bg="white").pack(pady=20)
        else:
            # Clear existing tree items before adding new ones, if any (e.g. if page is refreshed)
            for i in tree.get_children():
                tree.delete(i)
            for tx in transactions:
                # Ensure tx is a dict if get_user_transactions_sqlite returns Row objects or similar
                tree.insert("", "end", values=(tx['timestamp'], str(tx['type']).title(), tx['amount']))


        def confirm_logout_from_history():
            if messagebox.askyesno("Confirm Logout", "Are you sure you want to logout?"):
                history_win.destroy()
                parent.destroy() # This is the dashboard window
                self.create_login_screen()
                self.master.deiconify()

        ttk.Button(history_win, text="Back", command=history_win.destroy).pack(side="right", padx=20, pady=20)
        ttk.Button(history_win, text="Logout", command=confirm_logout_from_history).pack(side="left", padx=20, pady=20)

    # --- Session Management Methods ---
    def update_last_activity_time(self):
        self.last_activity_time = datetime.now()
        logging.info("User activity recorded at %s", self.last_activity_time.strftime('%Y-%m-%d %H:%M:%S'))

    def _close_all_app_windows(self):
        logging.info("Closing all open application windows due to session timeout or logout.")
        # Iterate over a copy of items because destroying widgets might modify the dict
        for window_key, window_instance in list(self.open_windows.items()):
            try:
                if window_instance and window_instance.winfo_exists(): # Check if window still exists
                    window_instance.destroy()
                self.open_windows.pop(window_key, None) # Remove from tracking
            except Exception as e:
                logging.error(f"Error destroying window {window_key}: {e}")
        # Ensure master window (login screen) is visible if all else closed
        # This might be handled by create_login_screen itself if it deiconifies.
        # For now, this method focuses on child windows.
        
    def check_session_timeout(self):
        if not self.current_user: # No user logged in, or already logged out
            self.cancel_session_timer() # Ensure timer is cancelled
            return

        if self.last_activity_time:
            elapsed_seconds = (datetime.now() - self.last_activity_time).total_seconds()
            timeout_seconds = SESSION_TIMEOUT_MINUTES * 60

            if elapsed_seconds > timeout_seconds:
                logging.info(f"User '{self.current_user['uname']}' session timed out due to inactivity.")
                # Store uname before clearing current_user for the message
                timed_out_username = self.current_user['uname'] 
                
                self._close_all_app_windows() # Close dashboard, deposit, etc.
                self.current_user = None # Clear current user session

                # Show login screen (master window should be withdrawn by other screens)
                # self.master.deiconify() # Ensure main window is visible for login screen
                self.create_login_screen() # Re-create login screen
                
                messagebox.showinfo(
                    "Session Timeout",
                    f"User '{timed_out_username}' has been logged out due to inactivity."
                )
                self.cancel_session_timer() # Stop further checks
                return # Important to return after timeout actions

        # If not timed out, reschedule the check
        # Ensure timer_id is managed to avoid multiple conflicting timers if start_session_timer is called again.
        if self.session_check_timer_id: # If a timer was already set, clear it before setting a new one
             self.master.after_cancel(self.session_check_timer_id)

        self.session_check_timer_id = self.master.after(
            SESSION_CHECK_INTERVAL_SECONDS * 1000, 
            self.check_session_timeout
        )

    def start_session_timer(self):
        self.update_last_activity_time() # Record current time as last activity
        if self.session_check_timer_id:
            self.master.after_cancel(self.session_check_timer_id)
        
        logging.info("Session timer started. Timeout in %d min. Check interval: %d sec.", 
                     SESSION_TIMEOUT_MINUTES, SESSION_CHECK_INTERVAL_SECONDS)
        self.session_check_timer_id = self.master.after(
            SESSION_CHECK_INTERVAL_SECONDS * 1000, 
            self.check_session_timeout
        )

    def cancel_session_timer(self):
        if self.session_check_timer_id:
            self.master.after_cancel(self.session_check_timer_id)
            self.session_check_timer_id = None
            logging.info("Session timer cancelled.")
    # --- End Session Management Methods ---


if __name__ == "__main__":
    root = Tk()
    # It's better to apply the theme once the root window exists,
    # so moving the style initialization here from BankApp.__init__ if it's better suited.
    # However, having it in BankApp.__init__ is also fine as root is passed to it.
    # For now, the change in BankApp.__init__ is kept.
    # If issues arise, this is an alternative spot:
    # style = ttk.Style(root)
    # style.theme_use('clam') # or another theme

    db_initialized_during_migration = False
    if os.path.exists("appData.bin") and (not os.path.exists(DB_PATH) or os.path.getsize(DB_PATH) == 0):
        user_choice = messagebox.askyesno(
            "Confirm Data Migration",
            "Old data file (appData.bin) found. Would you like to migrate this data to the new database format?\n"
            "If 'No', the old data will not be accessible by this version of the application."
        )
        if user_choice:
            initialize_database(DB_PATH) # Ensure DB and tables are ready for migration
            db_initialized_during_migration = True
            logging.info("User chose to migrate data.")
            migrated_users, migrated_transactions = migrate_pickle_to_sqlite(DB_PATH, "appData.bin")
            messagebox.showinfo(
                "Migration Complete",
                f"{migrated_users} users and {migrated_transactions} transactions were migrated."
            )
            
            rename_choice = messagebox.askyesno(
                "Rename Old Data File?",
                "Migration successful. Would you like to rename 'appData.bin' to 'appData.bin.migrated' "
                "to prevent this prompt in the future?"
            )
            if rename_choice:
                try:
                    os.rename("appData.bin", "appData.bin.migrated")
                    logging.info("'appData.bin' renamed to 'appData.bin.migrated'.")
                except OSError as e:
                    logging.error("Failed to rename 'appData.bin': %s", e)
                    messagebox.showwarning("Rename Failed", f"Could not rename 'appData.bin': {e}")
        else:
            logging.info("User chose not to migrate data from 'appData.bin'.")

    if not db_initialized_during_migration:
        initialize_database(DB_PATH) # Initialize the database if not done during migration
    
    app = BankApp(root)
    root.mainloop()
