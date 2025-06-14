# -*- coding: utf-8 -*-
"""
Unit Tests for the Bank Application Logic and SQLite functions.

This module contains unittest.TestCase classes for testing various components
of the BankApp, including:
- Password hashing and verification (old and new methods).
- Utility functions like is_number and check_password_strength.
- Core SQLite database operations (user creation, data retrieval, updates, transactions).
- Simulated application logic for registration, login, deposit, and withdrawal.
- Data migration from pickle to SQLite.
- Login attempt and account lockout mechanisms.
- Session timeout management.
"""
import unittest
import os
import pickle
import hashlib
from unittest.mock import MagicMock, patch
import sqlite3
from datetime import datetime, timedelta
from tkinter import Tk, StringVar, IntVar # For mocking UI variables

# Import functions and classes from the main application module
from BankAppWithTkinter import (
    BankApp,
    initialize_database,
    # DB_PATH will be patched, so direct import not strictly needed here for that
)
# Import service classes
from auth_service import AuthService
from account_service import AccountService
# Import utility functions that are now part of ui_manager or other modules
from ui_manager import is_number, check_password_strength
import constants as const

# --- Test Configuration ---
TEST_DB_PATH_STR = ":memory:" # Use an in-memory SQLite database for tests
TEST_PICKLE_FILE = "test_migration_appData.bin" # Specific pickle file for migration tests

class TestAuthService(unittest.TestCase):
    """Test suite specifically for AuthService methods."""
    def setUp(self):
        """Set up an in-memory database and AuthService instance for each test."""
        self.db_path = TEST_DB_PATH_STR
        # Patch DB_PATH in the global scope of AuthService module if it uses a global DB_PATH
        # However, AuthService is instantiated with db_path, so direct instantiation is better.
        initialize_database(self.db_path) # Ensure tables are created
        self.auth_service = AuthService(self.db_path)

    def test_hash_password_old_sha256(self):
        """Test the legacy SHA-256 hashing function."""
        self.assertEqual(len(self.auth_service.hash_password_old_sha256("test")), 64)

    def test_hash_and_verify_password_pbkdf2(self):
        """Test PBKDF2 hashing and verification."""
        password = "strongPassword123!"
        hashed_password = self.auth_service.hash_password(password)
        self.assertTrue(hashed_password.startswith(f"{const.PBKDF2_ALGORITHM}$"))
        self.assertTrue(self.auth_service.verify_password(password, hashed_password))
        self.assertFalse(self.auth_service.verify_password("wrongPassword", hashed_password))

    def test_verify_password_with_old_hash(self):
        """Test verification of old SHA256 hashes for backward compatibility."""
        old_password = "oldPassword"
        old_hash = self.auth_service.hash_password_old_sha256(old_password)
        self.assertTrue(self.auth_service.verify_password(old_password, old_hash))

    def test_login_attempts_logic(self):
        """Test recording, retrieving, and resetting login attempts."""
        username = "test_login_attempts_user"
        self.assertIsNone(self.auth_service.get_login_attempt_info(username))

        # Record failures
        for i in range(const.MAX_FAILED_LOGIN_ATTEMPTS):
            self.auth_service.record_failed_login_attempt(username)
            info = self.auth_service.get_login_attempt_info(username)
            self.assertEqual(info['failure_count'], i + 1)
            if i < const.MAX_FAILED_LOGIN_ATTEMPTS - 1:
                self.assertIsNone(info['lockout_until'])
            else: # Lockout should occur on the last attempt
                self.assertIsNotNone(info['lockout_until'])
                # Check lockout time is roughly correct
                lockout_end_dt = datetime.strptime(info['lockout_until'], '%Y-%m-%d %H:%M:%S')
                expected_end_dt = datetime.now() + timedelta(minutes=const.LOCKOUT_DURATION_MINUTES)
                self.assertAlmostEqual(lockout_end_dt, expected_end_dt, delta=timedelta(seconds=10))

        # Reset attempts
        self.auth_service.reset_login_attempts(username)
        info_after_reset = self.auth_service.get_login_attempt_info(username)
        # Depending on implementation, reset might remove the row or set count to 0 and lockout_until to NULL
        # AuthService's reset_login_attempts updates the row. If no update, it means row might not exist.
        # A more robust check might be to ensure failure_count is 0 if row exists.
        # For now, assume if it's reset, attempting to get it might return None or a cleared record.
        # The current AuthService.reset_login_attempts updates, so a record should exist.
        self.assertIsNotNone(info_after_reset, "Record should exist after reset to clear values.")
        self.assertEqual(info_after_reset['failure_count'], 0)
        self.assertIsNone(info_after_reset['lockout_until'])


class TestAccountService(unittest.TestCase):
    """Test suite specifically for AccountService methods."""
    def setUp(self):
        """Set up an in-memory database and AccountService instance for each test."""
        self.db_path = TEST_DB_PATH_STR
        initialize_database(self.db_path)
        self.account_service = AccountService(self.db_path)
        # For migration test, ensure the test pickle file is clean
        if os.path.exists(TEST_PICKLE_FILE):
            os.remove(TEST_PICKLE_FILE)

    def tearDown(self):
        """Clean up test pickle file if created."""
        if os.path.exists(TEST_PICKLE_FILE):
            os.remove(TEST_PICKLE_FILE)

    def test_user_creation_and_retrieval(self):
        """Test creating a new user and retrieving their data."""
        self.assertTrue(self.account_service.create_user_sqlite("user_acc_1", "hash", "Acc User One", 30, 1, 100))
        user_data = self.account_service.get_user_data_sqlite("user_acc_1")
        self.assertIsNotNone(user_data)
        self.assertEqual(user_data[const.COLUMN_USERNAME], "user_acc_1")
        self.assertEqual(user_data[const.COLUMN_FULL_NAME], "Acc User One")
        self.assertIsNone(self.account_service.get_user_data_sqlite("non_existent_user"))

    def test_duplicate_user_creation(self):
        """Test that creating a user with a duplicate username fails."""
        self.account_service.create_user_sqlite("user_dup", "hash", "User Dup", 30, 1, 100)
        self.assertFalse(self.account_service.create_user_sqlite("user_dup", "hash2", "User Dup2", 31, 0, 200))

    def test_balance_update(self):
        """Test updating a user's account balance."""
        self.account_service.create_user_sqlite("user_bal", "hash", "Bal User", 30, 1, 100)
        self.assertTrue(self.account_service.update_user_balance_sqlite("user_bal", 150))
        user_data = self.account_service.get_user_data_sqlite("user_bal")
        self.assertEqual(user_data[const.COLUMN_BALANCE], 150)
        self.assertFalse(self.account_service.update_user_balance_sqlite("non_existent", 200))

    def test_password_hash_update(self):
        """Test updating a user's password hash."""
        self.account_service.create_user_sqlite("user_pass_upd", "old_hash", "Pass Upd User", 30, 1, 100)
        new_hash = "new_secure_hash_value" # In real scenario, this would be a PBKDF2 hash
        self.assertTrue(self.account_service.update_user_password_hash_sqlite("user_pass_upd", new_hash))
        user_data = self.account_service.get_user_data_sqlite("user_pass_upd")
        self.assertEqual(user_data[const.COLUMN_PASSWORD_HASH], new_hash)

    def test_transaction_recording_and_retrieval(self):
        """Test recording transactions and retrieving them for a user."""
        self.account_service.create_user_sqlite("user_trans", "hash", "Trans User", 30, 1, 500)
        ts1 = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.assertTrue(self.account_service.record_transaction_sqlite("user_trans", const.TX_TYPE_DEPOSIT, 200, ts1))
        # Brief pause to ensure next timestamp is different if tests run very fast
        # Alternatively, mock datetime for more predictable timestamps in tests
        # For now, assuming execution takes enough time for distinct timestamps.
        # import time; time.sleep(0.001)
        ts2 = (datetime.now() + timedelta(seconds=1)).strftime('%Y-%m-%d %H:%M:%S')
        self.assertTrue(self.account_service.record_transaction_sqlite("user_trans", const.TX_TYPE_WITHDRAWAL, 50, ts2))

        transactions = self.account_service.get_user_transactions_sqlite("user_trans")
        self.assertEqual(len(transactions), 2)
        self.assertEqual(transactions[0]['type'], const.TX_TYPE_WITHDRAWAL) # Ordered DESC by timestamp
        self.assertEqual(transactions[0]['amount'], 50)
        self.assertEqual(transactions[1]['type'], const.TX_TYPE_DEPOSIT)
        self.assertEqual(transactions[1]['amount'], 200)

    def test_migrate_pickle_to_sqlite(self):
        """Test data migration from a pickle file to the SQLite database."""
        auth_for_hash = AuthService(self.db_path) # For creating old hashes
        pickle_data = [
            {"uname": "p_user1", "pass": auth_for_hash.hash_password_old_sha256("mig_pass1"),
             "name": "Pickle User One", "age": 42, "gender": 1, "balance": 1200,
             "transactions": [{'type': 'deposit', 'amount': 1200, 'timestamp': '2022-12-01 10:00:00'}]},
            {"uname": "p_user2", "pass": auth_for_hash.hash_password_old_sha256("mig_pass2"),
             "name": "Pickle User Two", "age": 38, "gender": 0, "balance": 600}
        ]
        with open(TEST_PICKLE_FILE, 'wb') as f: pickle.dump(pickle_data, f)

        mig_users, mig_txs = self.account_service.migrate_pickle_to_sqlite(pickle_path=TEST_PICKLE_FILE)
        self.assertEqual(mig_users, 2)
        self.assertEqual(mig_txs, 1)
        u1_data = self.account_service.get_user_data_sqlite("p_user1")
        self.assertTrue(auth_for_hash.verify_password("mig_pass1", u1_data[const.COLUMN_PASSWORD_HASH]))


class TestBankAppMainLogic(unittest.TestCase): # Renamed from TestBankAppLogic
    """
    Test suite for the BankApp class, focusing on its role as an orchestrator.
    Mocks service classes and UIManager to test BankApp's handling of UI events,
    session management, and coordination between services.
    """
    def setUp(self):
        """Set up a mock BankApp instance with mocked services."""
        self.mock_master = MagicMock(spec=Tk)
        
        # Patch the actual service instantiations within BankApp's __init__
        self.auth_service_patcher = patch('BankAppWithTkinter.AuthService')
        self.account_service_patcher = patch('BankAppWithTkinter.AccountService')
        self.ui_manager_patcher = patch('BankAppWithTkinter.UIManager')

        self.MockAuthService = self.auth_service_patcher.start()
        self.MockAccountService = self.account_service_patcher.start()
        self.MockUIManager = self.ui_manager_patcher.start()

        # Create instances of the mocked services that BankApp will receive
        self.mock_auth_service_instance = self.MockAuthService.return_value
        self.mock_account_service_instance = self.MockAccountService.return_value
        self.mock_ui_manager_instance = self.MockUIManager.return_value
        
        # Patch DB_PATH used by BankApp if it's used directly outside of services
        # (It shouldn't be, but as a safeguard for tests)
        self.db_path_patcher = patch('BankAppWithTkinter.DB_PATH', TEST_DB_PATH_STR)
        self.db_path_patcher.start()

        # Initialize BankApp with mocked services
        self.app = BankApp(self.mock_master)
        # Ensure BankApp uses the mocked instances
        self.app.auth_service = self.mock_auth_service_instance
        self.app.account_service = self.mock_account_service_instance
        self.app.ui_manager = self.mock_ui_manager_instance


    def tearDown(self):
        """Stop all patchers."""
        self.auth_service_patcher.stop()
        self.account_service_patcher.stop()
        self.ui_manager_patcher.stop()
        self.db_path_patcher.stop()
        if os.path.exists(TEST_PICKLE_FILE): # Clean up test pickle file
            os.remove(TEST_PICKLE_FILE)


    def test_app_initialization(self):
        """Test that BankApp initializes services and UIManager correctly."""
        self.MockAuthService.assert_called_once_with(TEST_DB_PATH_STR) # DB_PATH is patched
        self.MockAccountService.assert_called_once_with(TEST_DB_PATH_STR)
        self.MockUIManager.assert_called_once_with(self.mock_master, unittest.mock.ANY) # Callbacks dict
        self.app.ui_manager.create_login_screen.assert_called_once()

    def test_handle_login_attempt_success_new_hash(self):
        """Test successful login flow with a new PBKDF2 hash."""
        self.app.ui_manager.username_var.get.return_value = "testuser"
        self.app.ui_manager.password_var.get.return_value = "testpass"
        
        mock_user_data = {
            const.COLUMN_ID: 1, const.COLUMN_USERNAME: "testuser",
            const.COLUMN_PASSWORD_HASH: "pbkdf2_hash_value", # Assume this is a valid new hash
            const.COLUMN_FULL_NAME: "Test User", 'age': 30, 'gender': 1,
            const.COLUMN_BALANCE: 100
        }
        self.mock_auth_service_instance.get_login_attempt_info.return_value = None # No prior attempts/lockout
        self.mock_account_service_instance.get_user_data_sqlite.return_value = mock_user_data
        self.mock_auth_service_instance.verify_password.return_value = True
        self.mock_account_service_instance.get_user_transactions_sqlite.return_value = []

        with patch.object(self.app, 'start_session_timer') as mock_start_timer, \
             patch.object(self.app, 'ui_show_dashboard_screen') as mock_show_dashboard:
            self.app.handle_login_attempt()

        self.mock_auth_service_instance.reset_login_attempts.assert_called_once_with("testuser")
        self.assertIsNotNone(self.app.current_user)
        self.assertEqual(self.app.current_user['uname'], "testuser")
        self.app.ui_manager.show_message_box.assert_called_with(const.TITLE_SUCCESS, const.MSG_LOGIN_SUCCESSFUL, msg_type="info")
        mock_start_timer.assert_called_once()
        mock_show_dashboard.assert_called_once()

    # Further tests for BankApp logic (handle_registration, handle_deposit_process, etc.)
    # would follow a similar pattern:
    # 1. Set up mocks for service methods that will be called.
    # 2. Set up mock return values for those service methods.
    # 3. Mock UIManager interactions (like input variable gets, show_message_box calls).
    # 4. Call the BankApp handler method.
    # 5. Assert that service methods were called with expected arguments.
    # 6. Assert that UIManager methods were called as expected for feedback.
    # 7. Assert changes in BankApp state (e.g., self.current_user).

    def test_session_timeout_flow_in_bank_app(self):
        """Test session timeout logic within BankApp, mocking time and UI calls."""
        self.app.master.after = MagicMock(return_value="timer_id_test_session")
        self.app.master.after_cancel = MagicMock()

        self.app.current_user = {"uname": "session_user_app", "balance": 0}
        
        mock_now = datetime(2023, 1, 1, 12, 0, 0)
        # Patch datetime directly in BankAppWithTkinter module where it's imported
        with patch('BankAppWithTkinter.datetime') as mock_datetime_module:
            mock_datetime_module.now.return_value = mock_now
            mock_datetime_module.strptime = datetime.strptime
            mock_datetime_module.timedelta = timedelta
            
            self.app.last_activity_time = mock_now - timedelta(minutes=const.SESSION_TIMEOUT_MINUTES_DEFAULT + 1)
            self.app.session_check_timer_id = "active_timer_id_for_app_timeout"
            
            self.app.check_session_timeout()

            self.app.ui_manager.close_all_secondary_windows.assert_called_once()
            self.assertIsNone(self.app.current_user)
            self.app.ui_manager.show_message_box.assert_called_with(
                const.TITLE_SESSION_TIMEOUT,
                const.MSG_SESSION_TIMEOUT.format(username="session_user_app")
            )
            self.app.ui_manager.create_login_screen.assert_called_once() # Called via ui_show_login_screen
            self.app.master.after_cancel.assert_any_call("active_timer_id_for_app_timeout")


# --- Utility Function Tests (if not covered by service tests) ---
class TestUtilFunctions(unittest.TestCase):
    """Test standalone utility functions if they exist outside classes."""
    def test_is_number_direct(self):
        """Directly test is_number if it's a global utility."""
        self.assertTrue(is_number("123.45"))
        self.assertFalse(is_number("test"))

    def test_check_password_strength_direct(self):
        """Directly test check_password_strength if it's a global utility."""
        self.assertEqual(check_password_strength("Password123!")['level'], const.PASS_LEVEL_STRONG)
        self.assertEqual(check_password_strength("weak")['level'], const.PASS_LEVEL_TOO_WEAK)


if __name__ == '__main__':
    unittest.main(argv=['first-arg-is-ignored'], exit=False)
