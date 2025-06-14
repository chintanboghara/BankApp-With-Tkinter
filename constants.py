# -*- coding: utf-8 -*-
"""
Centralized constants for the Bank Application.

This file contains constants used throughout the application, including:
- Application-level settings (name, file names)
- Database configurations (table names, column names)
- Authentication parameters (hashing, lockout policy)
- Session management defaults
- UI elements (window titles, geometry, fonts, colors, styles, widget texts)
- Standardized messages for dialogs and user feedback
- Logging message formats
- Password strength indicators
- Default values for application logic
- Transaction type identifiers
"""

# --- Application Level Constants ---
APP_NAME_DEFAULT = "BankApp"
DEFAULT_PICKLE_FILE = "appData.bin"  # Original data file for migration
MIGRATED_PICKLE_FILE_SUFFIX = ".migrated" # Suffix for renamed pickle file after migration
LOG_FILE_NAME = "bankapp.log" # Name of the log file

# --- Database Constants ---
DB_FILE_NAME = "bankapp.db"  # Name of the SQLite database file

# Table Names
TABLE_USERS = "users"
TABLE_TRANSACTIONS = "transactions"
TABLE_LOGIN_ATTEMPTS = "login_attempts"

# Common Column Names
COLUMN_ID = "id"
COLUMN_USERNAME = "username"
COLUMN_PASSWORD_HASH = "password_hash"
COLUMN_FULL_NAME = "full_name"
COLUMN_BALANCE = "balance"
# Note: Other column names like 'age', 'gender', 'user_id', 'type', 'amount',
# 'timestamp', 'failure_count', 'lockout_until' are used directly in SQL queries
# as they are standard and less prone to typos than generic strings.

# --- Authentication Constants ---
# Hashing Parameters (for PBKDF2-SHA256)
PBKDF2_ALGORITHM = "pbkdf2_sha256"  # Hashing algorithm identifier
PBKDF2_ITERATIONS = 260000  # OWASP recommended iterations for PBKDF2-SHA256
SALT_BYTES = 16  # Size of the salt in bytes
DKLEN_BYTES = 32  # Derived key length in bytes (for SHA256, this is 32 bytes = 256 bits)

# Login Attempts Policy
MAX_FAILED_LOGIN_ATTEMPTS = 5  # Max number of failed login attempts before lockout
LOCKOUT_DURATION_MINUTES = 2  # Duration of account lockout in minutes

# --- Session Management Defaults ---
SESSION_TIMEOUT_MINUTES_DEFAULT = 1  # Default session timeout duration in minutes
SESSION_CHECK_INTERVAL_SECONDS_DEFAULT = 30  # Interval to check for session activity

# --- UI Constants ---
# Window Configuration
LOGIN_WINDOW_TITLE = "Login Page"
REGISTER_WINDOW_TITLE = "Sign Up"
DASHBOARD_WINDOW_TITLE = "Dashboard"
DEPOSIT_WINDOW_TITLE = "Deposit"
WITHDRAW_WINDOW_TITLE = "Withdraw"
PERSONAL_INFO_WINDOW_TITLE = "Personal Information"
TRANSACTION_HISTORY_WINDOW_TITLE = "Transaction History"
CRITICAL_ERROR_TITLE = "Critical Application Error"


DEFAULT_WINDOW_GEOMETRY = "500x450" # Default window size
REGISTER_WINDOW_GEOMETRY = "500x550" # Slightly taller for registration form
DASHBOARD_GEOMETRY = "500x350"       # Standard size for most internal windows
TRANSACTION_HISTORY_GEOMETRY = "600x400" # Wider for transaction table

# Fonts (Tuple format: (Family, Size, Style))
FONT_FAMILY_DEFAULT = "Arial"
FONT_TITLE = (FONT_FAMILY_DEFAULT, 40)
FONT_HEADER = (FONT_FAMILY_DEFAULT, 30)
FONT_SUBHEADER = (FONT_FAMILY_DEFAULT, 20)
FONT_BODY = (FONT_FAMILY_DEFAULT, 18)
FONT_LABEL = (FONT_FAMILY_DEFAULT, 15)
FONT_BUTTON = (FONT_FAMILY_DEFAULT, 10, "bold")
FONT_SMALL = (FONT_FAMILY_DEFAULT, 12)
FONT_FEEDBACK = (FONT_FAMILY_DEFAULT, 10) # For password strength, etc.

# Colors
COLOR_WHITE = "white"
COLOR_BLACK = "black" # For text, etc.
COLOR_RED = "red"
COLOR_ORANGE_RED = "orange red" # Darker orange
COLOR_GOLD = "gold"
COLOR_FOREST_GREEN = "forest green"
COLOR_GREY = "grey" # For less prominent text or disabled elements

# ttk Button Styles
COLOR_ACCENT_FG = "white"
COLOR_ACCENT_BG = "#007bff" # Primary button blue
COLOR_ACCENT_ACTIVE_BG = "#0056b3" # Darker blue when active/hovered
COLOR_ACCENT_PRESSED_BG = "#004085" # Even darker blue when pressed
COLOR_LINK_FG = "#007bff" # Blue for link-like buttons
COLOR_LINK_ACTIVE_FG = "#0056b3"
COLOR_LINK_PRESSED_FG = "#004085"

STYLE_ACCENT_BUTTON = "Accent.TButton" # Style name for primary action buttons
STYLE_LINK_BUTTON = "Link.TButton"     # Style name for text-like buttons

# Widget Texts / Labels
TEXT_LOGIN_TITLE = "LOGIN"
TEXT_REGISTER_TITLE = "Sign Up"
LABEL_USERNAME = "Username"
LABEL_PASSWORD = "Password"
LABEL_FULL_NAME = "Full Name"
LABEL_AGE = "Age"
LABEL_GENDER = "Gender"
LABEL_BALANCE = "Balance"
LABEL_AMOUNT = "Amount:"
BUTTON_LOGIN = "Login"
BUTTON_REGISTER = "Register"
BUTTON_SIGN_UP = "Sign Up"
BUTTON_SIGN_IN = "Sign In"
BUTTON_DEPOSIT = "Deposit"
BUTTON_WITHDRAW = "Withdraw"
BUTTON_PERSONAL_INFO = "Personal Info"
BUTTON_TRANSACTION_HISTORY = "Transaction History"
BUTTON_LOGOUT = "Logout"
BUTTON_BACK = "Back"
BUTTON_TOGGLE_VISIBILITY = "👁" # Eye icon for password visibility
TEXT_NO_ACCOUNT = "Don't have an account?"
TEXT_HAVE_ACCOUNT = "Already have an account?"
TEXT_MALE = "Male"
TEXT_FEMALE = "Female"
TEXT_NO_TRANSACTIONS = "No transactions yet."

# Messagebox Titles - Standardized titles for dialog boxes
TITLE_SUCCESS = "Success"
TITLE_ERROR = "Error"
TITLE_LOGIN_FAILED = "Login Failed"
TITLE_REGISTRATION_FAILED = "Registration Failed"
TITLE_MISSING_DATA = "Missing Data"
TITLE_INVALID_NAME = "Invalid Name"
TITLE_INVALID_BALANCE = "Invalid Balance"
TITLE_INVALID_AGE = "Invalid Age"
TITLE_INVALID_AMOUNT = "Invalid Amount"
TITLE_INSUFFICIENT_FUNDS = "Insufficient Funds"
TITLE_CONFIRM_REGISTRATION = "Confirm Registration"
TITLE_CONFIRM_LOGOUT = "Confirm Logout"
TITLE_SESSION_TIMEOUT = "Session Timeout"
TITLE_MIGRATION_CONFIRM = "Confirm Data Migration"
TITLE_MIGRATION_COMPLETE = "Migration Complete"
TITLE_MIGRATION_RENAME_CONFIRM = "Rename Old Data File?"
TITLE_MIGRATION_RENAME_FAILED = "Rename Failed"

# Messagebox Messages - Standardized messages for user feedback. Can use .format() for dynamic parts.
MSG_ACCOUNT_LOCKED = "Account for '{username}' is temporarily locked. Please try again in {time_left_str}."
MSG_LOGIN_FAILED_GENERAL = "Incorrect Username or Password."
MSG_LOGIN_SUCCESSFUL = "Login Successful." # Added for consistency
MSG_LOGIN_LOCKED_NOW = "Incorrect username or password. Account for '{username}' is now locked due to too many failed attempts. Please try again in {time_left_str}."
MSG_USER_REGISTERED_SUCCESS = "User Registered Successfully."
MSG_REGISTRATION_FAILED = "Username may already exist or another error occurred. Please try again."
MSG_ALL_FIELDS_REQUIRED = "All fields are required."
MSG_NAME_ONLY_ALPHABETS_SPACES = "Full Name should contain only alphabets and spaces."
MSG_BALANCE_NUMERIC = "Balance must be numeric."
MSG_BALANCE_NON_NEGATIVE = "Balance must be a non-negative number."
MSG_AGE_VALID_RANGE = "Please provide a valid age (numeric, 1-149)."
MSG_AMOUNT_POSITIVE = "Amount must be a positive number." # Changed from "greater than zero"
MSG_DEPOSIT_SUCCESS = "Deposit Successful."
MSG_INSUFFICIENT_FUNDS = "Not enough balance for this withdrawal." # Added
MSG_WITHDRAW_SUCCESS = "Withdrawal of ${amount} successful."
MSG_DEPOSIT_FAILED_DB = "Could not record the deposit transaction in the database."
MSG_WITHDRAW_FAILED_DB = "Could not record the withdrawal transaction in the database."
MSG_BALANCE_UPDATE_FAILED_DB = "Failed to update balance in the database."
MSG_CONFIRM_REGISTRATION_DETAILS = "Are you sure you want to register with these details?"
MSG_CONFIRM_LOGOUT = "Are you sure you want to logout?"
MSG_SESSION_TIMEOUT = "User '{username}' has been logged out due to inactivity."
MSG_MIGRATE_CONFIRM = ("Old data file (appData.bin) found. Would you like to migrate this data to the new database format?\n"
                       "If 'No', the old data will not be accessible by this version of the application.")
MSG_MIGRATE_COMPLETE = "{migrated_users} users and {migrated_transactions} transactions were migrated."
MSG_MIGRATE_RENAME_CONFIRM = ("Migration successful. Would you like to rename '{old_file}' to '{new_file}' "
                              "to prevent this prompt in the future?")
MSG_MIGRATE_RENAME_FAILED = "Could not rename '{filename}': {error}"
MSG_CRITICAL_ERROR = "A critical error occurred. The application might need to close. Please check logs."


# Logging Messages - Standard formats for log entries
LOG_MSG_DB_INIT_SUCCESS = "Database tables (users, transactions, login_attempts) initialized successfully at %s"
LOG_MSG_DB_INIT_ERROR = "Error initializing database at %s: %s"
# Example: LOG_LOGIN_SUCCESS = "User '%s' logged in successfully." (Can add more as needed)

# Password Strength Feedback
PASS_STRENGTH_TOO_WEAK = "Strength: Too Weak"
PASS_STRENGTH_WEAK = "Strength: Weak"
PASS_STRENGTH_MEDIUM = "Strength: Medium"
PASS_STRENGTH_STRONG = "Strength: Strong"
PASS_LEVEL_NONE = "None" # For when password field is empty
PASS_LEVEL_TOO_WEAK = "Too Weak"
PASS_LEVEL_WEAK = "Weak"
PASS_LEVEL_MEDIUM = "Medium"
PASS_LEVEL_STRONG = "Strong"

# Default Values
DEFAULT_BALANCE = 0  # Default balance for new users

# Transaction Types - Standardized strings for transaction types
TX_TYPE_DEPOSIT = "deposit"
TX_TYPE_WITHDRAWAL = "withdrawal"
