# -*- coding: utf-8 -*-
"""
Main application class for the BankApp GUI.

This module initializes the Tkinter application, sets up logging, database,
and core services (Authentication, Account, UI Management). It orchestrates
the overall application flow, user interactions, and session management.
"""
import os
import logging
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from tkinter import Tk, messagebox, StringVar, IntVar, Toplevel # Explicit Tkinter imports

from logging.handlers import RotatingFileHandler

# Application-specific modules
from auth_service import AuthService
from account_service import AccountService
from ui_manager import UIManager, is_number # is_number is a utility for input validation
import constants as const

# --- Global Configuration ---
# Setup logging to file and console
logger = logging.getLogger()
logger.setLevel(logging.INFO) # Set root logger level
log_file = const.LOG_FILE_NAME
# Rotating file handler: 1MB per file, keep 3 backups
rotate_handler = RotatingFileHandler(log_file, maxBytes=1024*1024, backupCount=3, encoding='utf-8')
formatter = logging.Formatter('%(asctime)s:%(levelname)s:%(module)s:%(funcName)s:%(message)s')
rotate_handler.setFormatter(formatter)
logger.addHandler(rotate_handler)

# Console handler for development (optional)
# console_handler = logging.StreamHandler()
# console_handler.setFormatter(formatter)
# logger.addHandler(console_handler)

# Database path configuration
home_dir = Path.home()
app_data_dir = home_dir / f".{const.APP_NAME_DEFAULT}"
DB_PATH = app_data_dir / const.DB_FILE_NAME # Full path to the database file

# Session management configuration
SESSION_TIMEOUT_MINUTES = const.SESSION_TIMEOUT_MINUTES_DEFAULT
SESSION_CHECK_INTERVAL_SECONDS = const.SESSION_CHECK_INTERVAL_SECONDS_DEFAULT

def initialize_database(db_path: Path = DB_PATH) -> None:
    """
    Initializes the SQLite database and creates necessary tables if they don't exist.

    Ensures the application's data directory exists and creates the database
    file with 'users', 'transactions', and 'login_attempts' tables.

    Args:
        db_path (Path, optional): The path to the database file.
                                  Defaults to the globally defined DB_PATH.
    """
    try:
        db_path.parent.mkdir(parents=True, exist_ok=True) # Ensure directory exists
        with sqlite3.connect(db_path) as conn: # `with` statement ensures connection is closed
            cursor = conn.cursor()
            # Users table: Stores user credentials and personal information
            cursor.execute(f"""
                CREATE TABLE IF NOT EXISTS {const.TABLE_USERS} (
                    {const.COLUMN_ID} INTEGER PRIMARY KEY AUTOINCREMENT,
                    {const.COLUMN_USERNAME} TEXT UNIQUE NOT NULL,
                    {const.COLUMN_PASSWORD_HASH} TEXT NOT NULL,
                    {const.COLUMN_FULL_NAME} TEXT NOT NULL,
                    age INTEGER NOT NULL,
                    gender INTEGER NOT NULL,
                    {const.COLUMN_BALANCE} INTEGER NOT NULL DEFAULT {const.DEFAULT_BALANCE}
                )
            """)
            # Transactions table: Stores all financial transactions for users
            cursor.execute(f"""
                CREATE TABLE IF NOT EXISTS {const.TABLE_TRANSACTIONS} (
                    {const.COLUMN_ID} INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    type TEXT NOT NULL,
                    amount INTEGER NOT NULL,
                    timestamp TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES {const.TABLE_USERS}({const.COLUMN_ID})
                )
            """)
            # Login attempts table: Tracks failed login attempts for security
            cursor.execute(f"""
                CREATE TABLE IF NOT EXISTS {const.TABLE_LOGIN_ATTEMPTS} (
                    {const.COLUMN_USERNAME} TEXT PRIMARY KEY,
                    failure_count INTEGER NOT NULL DEFAULT 0,
                    lockout_until TEXT 
                )
            """)
            conn.commit() # Commit changes to the database
            logging.info(const.LOG_MSG_DB_INIT_SUCCESS, db_path)
    except sqlite3.Error as e:
        # Log database-specific errors with stack trace
        logging.exception(const.LOG_MSG_DB_INIT_ERROR, db_path, e)
    except Exception as e:
        # Log any other unexpected errors during database initialization
        logging.exception("Unexpected error initializing database at %s: %s", db_path, e)


class BankApp:
    """
    Main application class for the BankApp.

    This class acts as the orchestrator, integrating the AuthService, AccountService,
    and UIManager to provide the bank application's functionality. It handles
    user session state, UI event callbacks, and coordinates actions between the
    different service layers.

    Attributes:
        master (Tk): The root Tkinter window.
        current_user (dict | None): Stores the data of the currently logged-in user.
                                    None if no user is logged in.
        last_activity_time (datetime | None): Timestamp of the last recorded user activity,
                                             used for session timeout.
        session_check_timer_id (str | None): ID of the `after` event for session checking,
                                             used to cancel the timer.
        auth_service (AuthService): Instance of the authentication service.
        account_service (AccountService): Instance of the account data service.
        ui_manager (UIManager): Instance of the UI management service.
    """
    def __init__(self, master: Tk) -> None:
        """
        Initializes the BankApp.

        Sets up the main window, instantiates services, defines UI callbacks,
        and displays the initial login screen.

        Args:
            master (Tk): The root Tkinter window.
        """
        self.master = master
        master.configure(bg=const.COLOR_WHITE)
        master.resizable(False, False) # Prevent window resizing

        self.current_user = None
        self.last_activity_time = None
        self.session_check_timer_id = None

        try:
            # Initialize core services; critical for app function
            self.auth_service = AuthService(DB_PATH)
            self.account_service = AccountService(DB_PATH)
        except Exception as e:
            logging.critical("Failed to initialize core services: %s", e, exc_info=True)
            # Use direct messagebox call as UIManager might not be initialized if services fail
            messagebox.showerror(const.TITLE_CRITICAL_ERROR,
                                 f"{const.MSG_CRITICAL_ERROR}\nServices failed to start.")
            master.destroy()
            return

        # Define callbacks that UIManager will use to trigger BankApp methods
        ui_callbacks = {
            "do_login": self.handle_login_attempt,
            "create_register_screen": self.ui_show_register_screen,
            "save_user": self.handle_registration,
            "show_login_screen_from_other": self.ui_show_login_screen,
            "logout": self.handle_logout,
            "deposit_action": self.ui_show_deposit_screen,
            "withdraw_action": self.ui_show_withdraw_screen,
            "personal_info_action": self.ui_show_personal_info_screen,
            "transaction_history_action": self.ui_show_transaction_history_screen,
            "process_deposit": self.handle_deposit_process,
            "process_withdraw": self.handle_withdraw_process,
            "fetch_transactions_for_history": self.fetch_user_transactions_for_ui,
            "logout_from_sub_window": self.handle_logout_from_sub_window
        }
        self.ui_manager = UIManager(master, ui_callbacks)
        self.ui_manager.create_login_screen() # Display the initial login screen

    # --- UI Navigation Handlers ---
    def ui_show_login_screen(self):
        """Instructs UIManager to display the login screen."""
        self.master.deiconify() # Ensure master window is visible for login screen
        self.ui_manager.create_login_screen()

    def ui_show_register_screen(self):
        """Instructs UIManager to display the registration screen."""
        # Master window is typically withdrawn by UIManager when showing Toplevels
        self.ui_manager.create_register_screen()
        
    def handle_logout_from_sub_window(self):
        """
        Handles logout initiated from a sub-window (e.g., deposit, withdraw).
        Ensures proper cleanup and returns to the login screen.
        """
        self.handle_logout_logic() # Core session cleanup
        self.ui_show_login_screen() # Display login screen

    # --- Core Application Logic Handlers ---
    def handle_login_attempt(self) -> None:
        """
        Handles a user's login attempt.

        Retrieves credentials from UIManager, checks for account lockout,
        verifies credentials using AuthService and AccountService.
        On success, updates session, upgrades password hash if needed, and shows dashboard.
        On failure, records attempt and shows appropriate error messages.
        """
        username = self.ui_manager.username_var.get().strip()
        password = self.ui_manager.password_var.get().strip()

        try:
            # Check for existing lockout
            attempt_info = self.auth_service.get_login_attempt_info(username)
            if attempt_info and attempt_info.get('lockout_until'):
                lockout_datetime = datetime.strptime(attempt_info['lockout_until'], '%Y-%m-%d %H:%M:%S')
                if datetime.now() < lockout_datetime:
                    # Calculate and display remaining lockout time
                    remaining_time = lockout_datetime - datetime.now()
                    remaining_minutes = int(remaining_time.total_seconds() // 60)
                    remaining_seconds = int(remaining_time.total_seconds() % 60)
                    time_left_str = f"{remaining_minutes} min(s)" if remaining_minutes > 0 else ""
                    if remaining_seconds > 0:
                        if time_left_str: time_left_str += " and "
                        time_left_str += f"{remaining_seconds} sec(s)"
                    if not time_left_str: time_left_str = "a short while" # Fallback text
                    self.ui_manager.show_message_box(const.TITLE_LOGIN_FAILED,
                                                     const.MSG_ACCOUNT_LOCKED.format(username=username, time_left_str=time_left_str),
                                                     msg_type="error")
                    logging.warning(f"Login attempt for locked account '{username}'.")
                    return

            # Proceed with login if not locked out
            user_data_from_db = self.account_service.get_user_data_sqlite(username)

            if user_data_from_db and self.auth_service.verify_password(password, user_data_from_db[const.COLUMN_PASSWORD_HASH]):
                # Successful login: reset attempts, update session, show dashboard
                self.auth_service.reset_login_attempts(username)

                # Password hash upgrade if using old format
                stored_hash = user_data_from_db[const.COLUMN_PASSWORD_HASH]
                if '$' not in stored_hash and len(stored_hash) == 64: # Heuristic for old SHA256
                    logging.info(f"User '{username}' logged in with old hash format. Upgrading.")
                    new_secure_hash = self.auth_service.hash_password(password)
                    if self.account_service.update_user_password_hash_sqlite(username, new_secure_hash):
                        user_data_from_db[const.COLUMN_PASSWORD_HASH] = new_secure_hash # Update in-memory data
                        logging.info(f"Password hash for user '{username}' successfully updated to new format.")
                    else:
                        logging.warning(f"Failed to update password hash in DB for user '{username}'.")

                # Populate current_user session data
                self.current_user = {
                    const.COLUMN_ID: user_data_from_db[const.COLUMN_ID],
                    'uname': user_data_from_db[const.COLUMN_USERNAME], # Keep 'uname' for UI consistency
                    'pass': user_data_from_db[const.COLUMN_PASSWORD_HASH],
                    'name': user_data_from_db[const.COLUMN_FULL_NAME],
                    'age': user_data_from_db['age'],
                    'gender': user_data_from_db['gender'],
                    const.COLUMN_BALANCE: user_data_from_db[const.COLUMN_BALANCE],
                    'transactions': self.account_service.get_user_transactions_sqlite(username)
                }
                self.ui_manager.show_message_box(const.TITLE_SUCCESS, const.MSG_LOGIN_SUCCESSFUL, msg_type="info")
                logging.info("User '%s' logged in successfully.", username)
                self.start_session_timer() # Start session activity timer
                self.ui_show_dashboard_screen()
            else:
                # Failed login: record attempt and show error
                self.auth_service.record_failed_login_attempt(username)
                updated_attempt_info = self.auth_service.get_login_attempt_info(username) # Check if now locked
                if updated_attempt_info and updated_attempt_info.get('lockout_until'):
                    # Account became locked due to this attempt
                    lockout_datetime_str = updated_attempt_info.get('lockout_until')
                    lockout_dt = datetime.strptime(lockout_datetime_str, '%Y-%m-%d %H:%M:%S')
                    if datetime.now() < lockout_dt :
                        remaining_time = lockout_dt - datetime.now()
                        # ... (calculate remaining time string as above) ...
                        time_left_str = "... calculation ..." # Placeholder for brevity
                        self.ui_manager.show_message_box(const.TITLE_LOGIN_FAILED,
                                                         const.MSG_LOGIN_LOCKED_NOW.format(username=username, time_left_str=time_left_str),
                                                         msg_type="error")
                        logging.warning(f"Failed login attempt for username: '{username}'. Account now locked.")
                        return
                # General incorrect credentials message
                self.ui_manager.show_message_box(const.TITLE_LOGIN_FAILED, const.MSG_LOGIN_FAILED_GENERAL, msg_type="error")
                logging.warning("Failed login attempt for username: %s (incorrect credentials).", username)
        except ValueError: # Specific error for strptime if date format is wrong
             logging.exception(f"Date parsing error for lockout_until for user '{username}'.")
             self.ui_manager.show_message_box(const.TITLE_LOGIN_FAILED, "An internal error occurred with login attempt timing. Please contact support.", msg_type="error")
        except sqlite3.Error: # Catch database-specific errors
            logging.exception("Database error during login attempt for user %s.", username)
            self.ui_manager.show_message_box(const.TITLE_LOGIN_FAILED, "A database error occurred. Please try again later.", msg_type="error")
        except Exception: # Catch any other unexpected errors
            logging.exception("An unexpected error occurred during login attempt for user %s.", username)
            self.ui_manager.show_message_box(const.TITLE_LOGIN_FAILED, "An unexpected error occurred. Please try again.", msg_type="error")

    def handle_registration(self, reg_vars: dict, register_window: Toplevel, back_to_login_action: callable) -> None:
        """
        Handles user registration.

        Validates input fields, hashes the password, creates the user via AccountService,
        and provides feedback through UIManager.

        Args:
            reg_vars (dict): Dictionary of Tkinter StringVars/IntVars from the registration form.
            register_window (Toplevel): The registration window instance (for parented message boxes).
            back_to_login_action (callable): Function to call to close registration and return to login.
        """
        # Retrieve and strip form data
        uname = reg_vars["username"].get().strip()
        full_name = reg_vars["full_name"].get().strip()
        age_str = reg_vars["age"].get().strip()
        gender = reg_vars["gender"].get()
        balance_str = reg_vars["balance"].get().strip()
        passwd = reg_vars["password"].get().strip()

        # Input validation
        if not all([uname, full_name, age_str, balance_str, passwd]):
            self.ui_manager.show_message_box(const.TITLE_MISSING_DATA, const.MSG_ALL_FIELDS_REQUIRED, msg_type="error", parent=register_window)
            return
        if not all(part.isalpha() or part.isspace() for part in full_name.split()): # Allow spaces, check parts
            self.ui_manager.show_message_box(const.TITLE_INVALID_NAME, const.MSG_NAME_ONLY_ALPHABETS_SPACES, msg_type="error", parent=register_window)
            return
        if not is_number(age_str) or not (0 < int(age_str) < 150): # Age validation
            self.ui_manager.show_message_box(const.TITLE_INVALID_AGE, const.MSG_AGE_VALID_RANGE, msg_type="error", parent=register_window)
            return
        if not is_number(balance_str) or int(float(balance_str)) < 0: # Balance validation
            self.ui_manager.show_message_box(const.TITLE_INVALID_BALANCE, const.MSG_BALANCE_NON_NEGATIVE, msg_type="error", parent=register_window)
            return
        
        age = int(age_str)
        balance = int(float(balance_str))

        try:
            hashed_password = self.auth_service.hash_password(passwd) # Hash password via AuthService
            # Confirmation dialog before creating user
            if self.ui_manager.show_message_box(const.TITLE_CONFIRM_REGISTRATION, const.MSG_CONFIRM_REGISTRATION_DETAILS,
                                                msg_type="askyesno", parent=register_window):
                if self.account_service.create_user_sqlite(uname, hashed_password, full_name, age, gender, balance):
                    self.ui_manager.show_message_box(const.TITLE_SUCCESS, const.MSG_USER_REGISTERED_SUCCESS,
                                                     msg_type="info", parent=register_window)
                    logging.info("New user '%s' registered successfully.", uname)
                    back_to_login_action() # Close registration and show login
                else:
                    # Typically, this means username already exists (due to UNIQUE constraint)
                    self.ui_manager.show_message_box(const.TITLE_REGISTRATION_FAILED, const.MSG_REGISTRATION_FAILED,
                                                     msg_type="error", parent=register_window)
        except sqlite3.Error:
            logging.exception("Database error during user registration for '%s'.", uname)
            self.ui_manager.show_message_box(const.TITLE_REGISTRATION_FAILED,
                                             "A database error occurred during registration. Please try again.",
                                             msg_type="error", parent=register_window)
        except Exception: # Catch any other unexpected errors
            logging.exception("Unexpected error during user registration for '%s'.", uname)
            self.ui_manager.show_message_box(const.TITLE_REGISTRATION_FAILED,
                                             "An unexpected error occurred during registration. Please try again.",
                                             msg_type="error", parent=register_window)

    def ui_show_dashboard_screen(self):
        """Instructs UIManager to display the main application dashboard."""
        if not self.current_user: # Should not happen if called after successful login
            logging.warning("Attempted to show dashboard without a logged-in user. Redirecting to login.")
            self.ui_show_login_screen()
            return
        self.update_last_activity_time() # User is active
        self.ui_manager.show_dashboard(
            current_user=self.current_user, logout_callback=self.handle_logout,
            deposit_callback=self.ui_show_deposit_screen, withdraw_callback=self.ui_show_withdraw_screen,
            personal_info_callback=self.ui_show_personal_info_screen,
            transaction_history_callback=self.ui_show_transaction_history_screen
        )
        self.master.withdraw() # Hide login window while dashboard is open

    def handle_logout(self):
        """Handles user logout: clears session, timers, and shows login screen."""
        self.handle_logout_logic() # Perform core logout operations
        self.ui_manager.close_all_secondary_windows() # Close any open Toplevels
        self.ui_show_login_screen() # Show the login screen again
        # self.master.deiconify() is handled by ui_show_login_screen if master was withdrawn

    def handle_logout_logic(self):
        """Core logout operations: clear user session and cancel timers."""
        if self.current_user:
            logging.info(f"User '{self.current_user['uname']}' logging out.")
        self.cancel_session_timer()
        self.current_user = None # Clear session data

    def update_user_balance_in_app(self, new_balance: int) -> bool:
        """
        Updates the user's balance both in the current session and in the database.

        Args:
            new_balance (int): The new balance to set.

        Returns:
            bool: True if update was successful in DB, False otherwise.
        """
        if not self.current_user:
            logging.error("Attempted to update balance with no current user.")
            self.ui_manager.show_message_box(const.TITLE_ERROR, "No user session found to update balance.", msg_type="error")
            return False
        try:
            if self.account_service.update_user_balance_sqlite(self.current_user["uname"], new_balance):
                self.current_user["balance"] = new_balance # Update in-memory session
                logging.info("User '%s' balance updated to %d in app and SQLite.", self.current_user["uname"], new_balance)
                return True
            else:
                logging.error("Failed to update balance for user '%s' in SQLite (user not found or no change).", self.current_user["uname"])
                self.ui_manager.show_message_box(const.TITLE_ERROR, const.MSG_BALANCE_UPDATE_FAILED_DB, msg_type="error")
                return False
        except Exception:
            logging.exception("Error updating user balance for %s.", self.current_user["uname"])
            self.ui_manager.show_message_box(const.TITLE_ERROR, "An unexpected error occurred while updating balance.", msg_type="error")
            return False

    def ui_show_deposit_screen(self, dashboard_toplevel: Toplevel, balance_label_on_dash: Label):
        """Instructs UIManager to display the deposit screen."""
        self.update_last_activity_time()
        self.ui_manager.show_deposit(
            parent=dashboard_toplevel, current_user=self.current_user,
            balance_label_on_dash=balance_label_on_dash,
            deposit_process_callback=self.handle_deposit_process,
            logout_from_sub_window_callback=self.handle_logout_from_sub_window
        )

    def handle_deposit_process(self, amount_var: StringVar, bal_lbl_deposit_win: Label,
                               balance_label_on_dash: Label, deposit_win: Toplevel):
        """
        Handles the deposit process: validates amount, records transaction, updates balance.
        Provides UI feedback via UIManager.

        Args:
            amount_var (StringVar): Tkinter variable for the deposit amount.
            bal_lbl_deposit_win (Label): Balance label on the deposit window.
            balance_label_on_dash (Label): Balance label on the dashboard.
            deposit_win (Toplevel): The deposit window (for parented message boxes).
        """
        amount_str = amount_var.get().strip()
        if not is_number(amount_str) or int(amount_str) <= 0:
            self.ui_manager.show_message_box(const.TITLE_INVALID_AMOUNT, const.MSG_AMOUNT_POSITIVE,
                                             msg_type="error", parent=deposit_win)
            return
        try:
            amount = int(amount_str)
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            if self.account_service.record_transaction_sqlite(self.current_user["uname"], const.TX_TYPE_DEPOSIT, amount, timestamp):
                new_balance = self.current_user['balance'] + amount
                if self.update_user_balance_in_app(new_balance): # update_user_balance_in_app handles its own errors/messaging
                    self.ui_manager.show_message_box(const.TITLE_SUCCESS, const.MSG_DEPOSIT_SUCCESS,
                                                     msg_type="info", parent=deposit_win)
                    # Update UI labels if balance update was successful
                    if bal_lbl_deposit_win and bal_lbl_deposit_win.winfo_exists():
                         bal_lbl_deposit_win.config(text=f"Balance: {new_balance}")
                    if balance_label_on_dash and balance_label_on_dash.winfo_exists():
                         balance_label_on_dash.config(text=f"Balance: {new_balance}")
                    # Update in-memory transaction list for current session
                    self.current_user['transactions'].append({'type': const.TX_TYPE_DEPOSIT, 'amount': amount, 'timestamp': timestamp})
                    logging.info("Deposit of %d processed for %s.", amount, self.current_user["uname"])
                    self.update_last_activity_time()
            else:
                self.ui_manager.show_message_box(const.TITLE_ERROR, const.MSG_DEPOSIT_FAILED_DB,
                                                 msg_type="error", parent=deposit_win)
                logging.error("Failed to record deposit for %s (AccountService indicated failure).", self.current_user["uname"])
        except sqlite3.Error:
            logging.exception("Database error during deposit process for %s.", self.current_user["uname"])
            self.ui_manager.show_message_box(const.TITLE_ERROR, "A database error occurred while processing the deposit.",
                                             msg_type="error", parent=deposit_win)
        except Exception:
            logging.exception("Unexpected error during deposit process for %s.", self.current_user["uname"])
            self.ui_manager.show_message_box(const.TITLE_ERROR, "An unexpected error occurred during deposit.",
                                             msg_type="error", parent=deposit_win)

    def ui_show_withdraw_screen(self, dashboard_toplevel: Toplevel, balance_label_on_dash: Label):
        """Instructs UIManager to display the withdrawal screen."""
        self.update_last_activity_time()
        self.ui_manager.show_withdraw(
            parent=dashboard_toplevel, current_user=self.current_user,
            balance_label_on_dash=balance_label_on_dash,
            withdraw_process_callback=self.handle_withdraw_process,
            logout_from_sub_window_callback=self.handle_logout_from_sub_window
        )

    def handle_withdraw_process(self, amount_var: StringVar, bal_lbl_withdraw_win: Label,
                                balance_label_on_dash: Label, withdraw_win: Toplevel):
        """
        Handles the withdrawal process: validates amount, checks funds, records transaction, updates balance.
        Provides UI feedback via UIManager.
        """
        amount_str = amount_var.get().strip()
        if not is_number(amount_str) or int(amount_str) <= 0:
            self.ui_manager.show_message_box(const.TITLE_INVALID_AMOUNT, const.MSG_AMOUNT_POSITIVE,
                                             msg_type="error", parent=withdraw_win)
            return
        try:
            amount = int(amount_str)
            if self.current_user['balance'] < amount:
                self.ui_manager.show_message_box(const.TITLE_INSUFFICIENT_FUNDS, const.MSG_INSUFFICIENT_FUNDS,
                                                 msg_type="error", parent=withdraw_win)
                return
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            if self.account_service.record_transaction_sqlite(self.current_user["uname"], const.TX_TYPE_WITHDRAWAL, amount, timestamp):
                new_balance = self.current_user['balance'] - amount
                if self.update_user_balance_in_app(new_balance): # Handles its own errors/messaging
                    self.ui_manager.show_message_box(const.TITLE_SUCCESS, const.MSG_WITHDRAW_SUCCESS.format(amount=amount),
                                                     msg_type="info", parent=withdraw_win)
                    if bal_lbl_withdraw_win and bal_lbl_withdraw_win.winfo_exists():
                        bal_lbl_withdraw_win.config(text=f"Balance: {new_balance}")
                    if balance_label_on_dash and balance_label_on_dash.winfo_exists():
                        balance_label_on_dash.config(text=f"Balance: {new_balance}")
                    self.current_user['transactions'].append({'type': const.TX_TYPE_WITHDRAWAL, 'amount': amount, 'timestamp': timestamp})
                    logging.info("Withdrawal of %d processed for %s.", amount, self.current_user["uname"])
                    self.update_last_activity_time()
            else:
                self.ui_manager.show_message_box(const.TITLE_ERROR, const.MSG_WITHDRAW_FAILED_DB,
                                                 msg_type="error", parent=withdraw_win)
                logging.error("Failed to record withdrawal for %s (AccountService indicated failure).", self.current_user["uname"])
        except sqlite3.Error:
            logging.exception("Database error during withdrawal process for %s.", self.current_user["uname"])
            self.ui_manager.show_message_box(const.TITLE_ERROR, "A database error occurred while processing the withdrawal.",
                                             msg_type="error", parent=withdraw_win)
        except Exception:
            logging.exception("Unexpected error during withdrawal process for %s.", self.current_user["uname"])
            self.ui_manager.show_message_box(const.TITLE_ERROR, "An unexpected error occurred during withdrawal.",
                                             msg_type="error", parent=withdraw_win)
            
    def ui_show_personal_info_screen(self, dashboard_toplevel: Toplevel):
        """Instructs UIManager to display the personal information screen."""
        self.update_last_activity_time()
        self.ui_manager.show_personal_info(
            parent=dashboard_toplevel, current_user=self.current_user,
            logout_from_sub_window_callback=self.handle_logout_from_sub_window
        )

    def ui_show_transaction_history_screen(self, dashboard_toplevel: Toplevel, balance_label_on_dash: Label):
        """Instructs UIManager to display the transaction history screen."""
        self.update_last_activity_time()
        self.ui_manager.show_transaction_history(
            parent=dashboard_toplevel, current_user_uname=self.current_user['uname'],
            transactions_fetch_callback=self.fetch_user_transactions_for_ui,
            logout_from_sub_window_callback=self.handle_logout_from_sub_window
        )
        
    def fetch_user_transactions_for_ui(self) -> list:
        """
        Fetches transactions for the current user via AccountService.
        Used as a callback by UIManager for the transaction history screen.
        """
        try:
            if self.current_user:
                return self.account_service.get_user_transactions_sqlite(self.current_user['uname'])
        except Exception:
            logging.exception("Error fetching user transactions for UI for user %s.", self.current_user.get('uname', 'Unknown'))
            self.ui_manager.show_message_box(const.TITLE_ERROR, "Could not load transaction history due to an error.", msg_type="error")
        return [] # Return empty list on error or if no user

    # --- Session Management Methods ---
    def update_last_activity_time(self):
        """Updates the timestamp of the last recorded user activity."""
        self.last_activity_time = datetime.now()
        logging.debug("User activity recorded at %s", self.last_activity_time.strftime('%Y-%m-%d %H:%M:%S')) # Debug level might be more appropriate

    def _close_all_app_windows_on_timeout(self):
        """Closes all secondary UI windows and resets user session on timeout."""
        logging.info("Session timeout: closing UI windows via UIManager.")
        self.ui_manager.close_all_secondary_windows()
        self.current_user = None # Clear current user session
        self.ui_show_login_screen() # Show login screen
        # self.master.deiconify() is handled by ui_show_login_screen

    def check_session_timeout(self):
        """
        Checks if the user session has timed out due to inactivity.
        If timed out, logs out the user and shows the login screen.
        Otherwise, reschedules itself to check again later.
        """
        if not self.current_user:
            self.cancel_session_timer()
            return
        if self.last_activity_time:
            elapsed_seconds = (datetime.now() - self.last_activity_time).total_seconds()
            timeout_seconds = SESSION_TIMEOUT_MINUTES * 60
            if elapsed_seconds > timeout_seconds:
                timed_out_username = self.current_user['uname'] # Get username before clearing session
                logging.info(f"User '{timed_out_username}' session timed out due to inactivity.")
                self._close_all_app_windows_on_timeout()
                # UIManager's show_message_box will use master as parent if others are closed
                self.ui_manager.show_message_box(
                    const.TITLE_SESSION_TIMEOUT,
                    const.MSG_SESSION_TIMEOUT.format(username=timed_out_username)
                )
                self.cancel_session_timer()
                return
        # Reschedule the check if not timed out
        if self.session_check_timer_id:
             self.master.after_cancel(self.session_check_timer_id)
        self.session_check_timer_id = self.master.after(SESSION_CHECK_INTERVAL_SECONDS * 1000, self.check_session_timeout)

    def start_session_timer(self):
        """Starts or restarts the session activity timer."""
        self.update_last_activity_time()
        if self.session_check_timer_id: # Cancel any existing timer
            self.master.after_cancel(self.session_check_timer_id)
        logging.info("Session timer started. Timeout in %d min. Check interval: %d sec.", 
                     SESSION_TIMEOUT_MINUTES, SESSION_CHECK_INTERVAL_SECONDS)
        self.session_check_timer_id = self.master.after(
            SESSION_CHECK_INTERVAL_SECONDS * 1000, 
            self.check_session_timeout
        )

    def cancel_session_timer(self):
        """Cancels the currently active session check timer."""
        if self.session_check_timer_id:
            self.master.after_cancel(self.session_check_timer_id)
            self.session_check_timer_id = None
            logging.info("Session timer cancelled.")

# --- Main Application Execution ---
if __name__ == "__main__":
    try:
        root = Tk() # Create the main Tkinter window

        # Perform database initialization and potential data migration before starting app
        db_initialized_during_migration = False
        # Check for old pickle data file and if DB is empty or non-existent
        if os.path.exists(const.DEFAULT_PICKLE_FILE) and \
           (not os.path.exists(DB_PATH) or os.path.getsize(DB_PATH) == 0):
            
            # Use direct tkinter.messagebox as UIManager is not yet initialized
            user_choice = messagebox.askyesno(
                const.TITLE_MIGRATION_CONFIRM,
                const.MSG_MIGRATE_CONFIRM
            )
            if user_choice:
                initialize_database(DB_PATH) # Ensure DB structure is ready
                db_initialized_during_migration = True
                logging.info("User chose to migrate data from pickle file.")
                temp_account_service = AccountService(DB_PATH) # Temporary instance for migration
                try:
                    migrated_users, migrated_transactions = temp_account_service.migrate_pickle_to_sqlite(const.DEFAULT_PICKLE_FILE)
                    messagebox.showinfo(
                        const.TITLE_MIGRATION_COMPLETE,
                        const.MSG_MIGRATE_COMPLETE.format(migrated_users=migrated_users, migrated_transactions=migrated_transactions)
                    )
                    # Offer to rename the old pickle file to prevent re-prompting
                    new_pickle_filename = f"{const.DEFAULT_PICKLE_FILE}{const.MIGRATED_PICKLE_FILE_SUFFIX}"
                    rename_choice = messagebox.askyesno(
                        const.TITLE_MIGRATION_RENAME_CONFIRM,
                        const.MSG_MIGRATE_RENAME_CONFIRM.format(old_file=const.DEFAULT_PICKLE_FILE, new_file=new_pickle_filename)
                    )
                    if rename_choice:
                        try:
                            os.rename(const.DEFAULT_PICKLE_FILE, new_pickle_filename)
                            logging.info(f"'{const.DEFAULT_PICKLE_FILE}' renamed to '{new_pickle_filename}'.")
                        except OSError as e_rename:
                            logging.error(f"Failed to rename '{const.DEFAULT_PICKLE_FILE}': {e_rename}", exc_info=True)
                            messagebox.showwarning(const.TITLE_MIGRATION_RENAME_FAILED,
                                                   const.MSG_MIGRATE_RENAME_FAILED.format(filename=const.DEFAULT_PICKLE_FILE, error=e_rename))
                except Exception as e_migrate:
                    logging.exception("Error during data migration process.")
                    messagebox.showerror(const.TITLE_ERROR, f"An error occurred during data migration: {e_migrate}")
            else:
                logging.info(f"User chose not to migrate data from '{const.DEFAULT_PICKLE_FILE}'.")

        # Ensure database is initialized if migration didn't occur (e.g., no pickle file)
        if not db_initialized_during_migration:
            initialize_database(DB_PATH)

        app = BankApp(root) # Instantiate the main application
        root.mainloop() # Start the Tkinter event loop
    except Exception as e: # Global catch-all for critical errors during startup or runtime
        logging.critical("Critical error initializing or running the application: %s", e, exc_info=True)
        try:
            # Attempt to show a final error message if Tkinter is still somewhat functional
            messagebox.showerror(const.TITLE_CRITICAL_ERROR, f"{const.MSG_CRITICAL_ERROR}\nDetails: {e}")
        except:
            # If Tkinter itself is broken, nothing more can be done via UI.
            print(f"CRITICAL ERROR: {e}") # Fallback to console
            pass
