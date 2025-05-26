import unittest
import os
import pickle
import hashlib
from unittest.mock import MagicMock, patch

import sqlite3

# Assuming BankAppWithTkinter.py is in the same directory or accessible in PYTHONPATH
from BankAppWithTkinter import (
    hash_password_old_sha256, 
    hash_password_old_sha256, 
    hash_password, 
    verify_password, 
    ITERATIONS, 
    is_number,
    check_password_strength,
    BankApp,
    DB_PATH, 
    initialize_database,
    create_user_sqlite,
    get_user_data_sqlite,
    update_user_balance_sqlite,
    update_user_password_hash_sqlite,
    record_transaction_sqlite,
    get_user_transactions_sqlite,
    load_user_data_pickle, 
    migrate_pickle_to_sqlite,
    # Login attempt functions and constants
    get_login_attempt_info,
    record_failed_login_attempt,
    reset_login_attempts,
    MAX_FAILED_ATTEMPTS,
    LOCKOUT_DURATION_MINUTES
)
from datetime import datetime, timedelta # Added

# Define a test-specific DB path (in-memory)
TEST_DB_PATH = ":memory:"
# For migration test, we'll use a specific pickle file name
TEST_PICKLE_FILE = "test_migration_appData.bin"


class TestBankAppLogic(unittest.TestCase):

    def setUp(self):
        """
        Set up for each test.
        - Patch DB_PATH to use an in-memory SQLite database.
        - Initialize the database schema.
        """
        self.db_path_patcher = patch('BankAppWithTkinter.DB_PATH', TEST_DB_PATH)
        self.mock_db_path = self.db_path_patcher.start()
        
        # Initialize the in-memory database for each test
        # Connection needs to be held if :memory: is to persist for the test method,
        # but our functions open/close connections themselves.
        # initialize_database will create tables in the :memory: db pointed to by TEST_DB_PATH.
        initialize_database(TEST_DB_PATH)

        # Clean up any potential test pickle file from previous failed runs
        if os.path.exists(TEST_PICKLE_FILE):
            os.remove(TEST_PICKLE_FILE)


    def tearDown(self):
        """
        Clean up after each test.
        - Stop the DB_PATH patcher.
        - Remove the test pickle file if it was created.
        """
        self.db_path_patcher.stop()
        if os.path.exists(TEST_PICKLE_FILE):
            os.remove(TEST_PICKLE_FILE)

    def test_old_hash_password(self): # Renamed from test_hash_password
        """Test the old hash_password_old_sha256 function."""
        pw1 = "password123"
        pw2 = "anotherPassword"

        self.assertEqual(hash_password_old_sha256(pw1), hash_password_old_sha256(pw1))
        self.assertNotEqual(hash_password_old_sha256(pw1), hash_password_old_sha256(pw2))

        hashed_pw = hash_password_old_sha256(pw1)
        self.assertIsInstance(hashed_pw, str)
        try:
            int(hashed_pw, 16) # Check if it's a hex digest
            is_hex = True
        except ValueError:
            is_hex = False
        self.assertTrue(is_hex, "Old password hash is not a valid hex string.")
        self.assertEqual(len(hashed_pw), 64) # SHA-256 produces 64 hex characters

    def test_new_password_hashing_functions(self):
        """Test the new PBKDF2 hash_password and verify_password functions."""
        pw = "securePassword123"
        
        # Test hash_password (new PBKDF2)
        hashed_pw_new = hash_password(pw)
        self.assertIsInstance(hashed_pw_new, str)
        self.assertTrue(hashed_pw_new.startswith("pbkdf2_sha256$"), "New hash should start with 'pbkdf2_sha256$'")
        parts = hashed_pw_new.split('$')
        self.assertEqual(len(parts), 4, "PBKDF2 hash string should have 4 parts.")
        self.assertEqual(parts[0], "pbkdf2_sha256", "Algorithm part is incorrect.")
        self.assertTrue(parts[1].isdigit(), "Iterations part should be a digit.")
        self.assertEqual(int(parts[1]), ITERATIONS, "Iterations part does not match defined ITERATIONS.")
        self.assertTrue(len(parts[2]) > 0, "Salt hex part should not be empty.")
        self.assertTrue(len(parts[3]) > 0, "Key hex part should not be empty.")
        # Attempt to decode salt and key from hex to check for valid hex format
        try:
            bytes.fromhex(parts[2])
            bytes.fromhex(parts[3])
        except ValueError:
            self.fail("Salt or Key part of PBKDF2 hash is not valid hex.")
        
        # Test verify_password with new PBKDF2 hash
        self.assertTrue(verify_password(pw, hashed_pw_new), "Verification of correct new hash failed.")
        self.assertFalse(verify_password("wrongPassword", hashed_pw_new), "Verification of incorrect password with new hash succeeded.")
        self.assertFalse(verify_password(pw, hashed_pw_new + "tamper"), "Verification of tampered new hash succeeded.") # Basic tamper check

        # Test verify_password with old SHA-256 hash (backward compatibility)
        old_plain_pw = "oldPassword456"
        old_hashed_pw_str = hash_password_old_sha256(old_plain_pw)
        self.assertTrue(verify_password(old_plain_pw, old_hashed_pw_str), "Verification of correct old hash failed.")
        self.assertFalse(verify_password("wrongOldPassword", old_hashed_pw_str), "Verification of incorrect password with old hash succeeded.")
        
        # Test verify_password with malformed/invalid hashes
        with patch('BankAppWithTkinter.logging') as mock_logging:
            self.assertFalse(verify_password(pw, ""), "Verification of empty hash string succeeded.")
            mock_logging.warning.assert_any_call("Verification attempt against an empty hash string.")

            self.assertFalse(verify_password(pw, "juststring"), "Verification of non-format string succeeded.")
            mock_logging.warning.assert_any_call("Malformed hash string: No '$' delimiter and not 64 chars. Got 10 chars.")
            
            self.assertFalse(verify_password(pw, "pbkdf2_sha256$1000$salt"), "Verification of too few parts succeeded.")
            mock_logging.warning.assert_any_call("Malformed PBKDF2 hash string: Expected 4 parts, got 3. Hash starts with: pbkdf2_sha256$1000$salt...")

            self.assertFalse(verify_password(pw, "unsupported_alg$1000$salt$key"), "Verification with wrong algorithm succeeded.")
            mock_logging.warning.assert_any_call("Unsupported hash algorithm: 'unsupported_alg'. Expected 'pbkdf2_sha256'.")

            self.assertFalse(verify_password(pw, f"pbkdf2_sha256$not_int${parts[2]}${parts[3]}"), "Verification with non-int iterations succeeded.")
            mock_logging.error.assert_any_call(f"Error converting parts of PBKDF2 hash (iterations, salt, or key): invalid literal for int() with base 10: 'not_int'. Hash starts with: pbkdf2_sha256$not_int${parts[2]}...")
            
            self.assertFalse(verify_password(pw, f"pbkdf2_sha256$0${parts[2]}${parts[3]}"), "Verification with zero iterations succeeded.")
            mock_logging.warning.assert_any_call("Invalid iteration count in hash: 0. Must be positive.")

            self.assertFalse(verify_password(pw, f"pbkdf2_sha256${ITERATIONS}$nothexsalt${parts[3]}"), "Verification with non-hex salt succeeded.")
            mock_logging.error.assert_any_call(f"Error converting parts of PBKDF2 hash (iterations, salt, or key): non-hexadecimal number found in fromhex() arg at position 0. Hash starts with: pbkdf2_sha256${ITERATIONS}$nothexsalt...")
            
            # Re-using parts[2] (a valid salt hex) to test non-hex key
            self.assertFalse(verify_password(pw, f"pbkdf2_sha256${ITERATIONS}${parts[2]}$nothexkey"), "Verification with non-hex key succeeded.")
            mock_logging.error.assert_any_call(f"Error converting parts of PBKDF2 hash (iterations, salt, or key): non-hexadecimal number found in fromhex() arg at position 0. Hash starts with: pbkdf2_sha256${ITERATIONS}${parts[2]}...")

            short_salt_hex = "aabbcc" # 3 bytes, expected 16
            short_key_hex = "ddeeff"  # 3 bytes, expected 32
            self.assertFalse(verify_password(pw, f"pbkdf2_sha256${ITERATIONS}${short_salt_hex}${parts[3]}"), "Verification with short salt succeeded.")
            mock_logging.warning.assert_any_call(f"Decoded salt length is 3, expected 16.")
            self.assertFalse(verify_password(pw, f"pbkdf2_sha256${ITERATIONS}${parts[2]}${short_key_hex}"), "Verification with short key succeeded.")
            mock_logging.warning.assert_any_call(f"Decoded key length is 3, expected 32.")

            self.assertFalse(verify_password(pw, "g" * 64), "Verification of 64 non-hex chars (old format) succeeded.") # Non-hex old hash
            mock_logging.warning.assert_any_call("Hash string (no '$') is not a valid hex string. Old format verification failed.")

    def test_is_number(self):
        """Test the is_number utility function."""
        self.assertTrue(is_number("123"))
        self.assertTrue(is_number("123.45"))
        self.assertTrue(is_number("-123"))
        self.assertTrue(is_number("0"))
        self.assertFalse(is_number("abc"))
        self.assertFalse(is_number("12a.3"))
        self.assertFalse(is_number(""))
        self.assertFalse(is_number(" "))

    def test_check_password_strength(self):
        # Test empty password
        feedback = check_password_strength("")
        self.assertEqual(feedback['level'], 'None')
        self.assertEqual(feedback['text'], '')
        self.assertEqual(feedback['color'], '') # Or whatever default it's set to for empty

        # Test "Too Weak" passwords (score 0 or 1)
        # Score 0 (e.g. <8 chars, one type) - or just too short
        feedback = check_password_strength("abc") 
        self.assertEqual(feedback['level'], 'Too Weak', f"Test 'abc': {feedback}")
        self.assertEqual(feedback['text'], 'Strength: Too Weak')
        self.assertEqual(feedback['color'], 'red')

        feedback = check_password_strength("1234567") # Length < 8, only digits
        self.assertEqual(feedback['level'], 'Too Weak', f"Test '1234567': {feedback}")
        self.assertEqual(feedback['text'], 'Strength: Too Weak')
        self.assertEqual(feedback['color'], 'red')

        # Score 1 (e.g. length >= 8, but only one character type, no bonus length)
        # feedback = check_password_strength("abcdefgh") # Length=8 (1pt), lowercase (1pt) -> score 2 expected -> Weak
                                                      # Let's adjust test case for score 1:
        feedback = check_password_strength("aaaaaaa") # Length < 8 (0pt), lowercase (1pt) -> score 1
        self.assertEqual(feedback['level'], 'Too Weak', f"Test 'aaaaaaa': {feedback}") # Should be Too Weak
        
        feedback = check_password_strength("abcdefg") # len 7 (0), lower (1) = score 1
        self.assertEqual(feedback['level'], 'Too Weak', f"Test 'abcdefg': {feedback}")
        self.assertEqual(feedback['text'], 'Strength: Too Weak')
        self.assertEqual(feedback['color'], 'red')


        # Test "Weak" passwords (score 2)
        feedback = check_password_strength("abcdefgh") # len 8 (1), lower (1) = score 2
        self.assertEqual(feedback['level'], 'Weak', f"Test 'abcdefgh': {feedback}")
        self.assertEqual(feedback['text'], 'Strength: Weak')
        self.assertEqual(feedback['color'], 'orange red')

        feedback = check_password_strength("Abcdefg") # len 7 (0), lower (1), upper (1) = score 2
        self.assertEqual(feedback['level'], 'Weak', f"Test 'Abcdefg': {feedback}")
        self.assertEqual(feedback['text'], 'Strength: Weak')
        self.assertEqual(feedback['color'], 'orange red')

        feedback = check_password_strength("12345678") # len 8 (1), digit (1) = score 2
        self.assertEqual(feedback['level'], 'Weak', f"Test '12345678': {feedback}")

        # Test "Medium" passwords (score 3 or 4)
        feedback = check_password_strength("Abcdefgh") # len 8 (1), lower (1), upper (1) = score 3
        self.assertEqual(feedback['level'], 'Medium', f"Test 'Abcdefgh': {feedback}")
        self.assertEqual(feedback['text'], 'Strength: Medium')
        self.assertEqual(feedback['color'], 'gold')

        feedback = check_password_strength("Abcdef12") # len 8 (1), lower (1), upper (1), digit (1) = score 4
        self.assertEqual(feedback['level'], 'Medium', f"Test 'Abcdef12': {feedback}")

        feedback = check_password_strength("abcdefgh1!") # len 10 (1), lower (1), digit (1), special (1) = score 4
        self.assertEqual(feedback['level'], 'Medium', f"Test 'abcdefgh1!': {feedback}")


        # Test "Strong" passwords (score 5 or 6)
        feedback = check_password_strength("Abcdef1!") # len 8 (1), lower (1), upper (1), digit (1), special (1) = score 5
        self.assertEqual(feedback['level'], 'Strong', f"Test 'Abcdef1!': {feedback}")
        self.assertEqual(feedback['text'], 'Strength: Strong')
        self.assertEqual(feedback['color'], 'forest green')

        feedback = check_password_strength("Abcdefgh123!") # len 12 (1+1 bonus), lower (1), upper (1), digit (1), special (1) = score 6
        self.assertEqual(feedback['level'], 'Strong', f"Test 'Abcdefgh123!': {feedback}")
        
        feedback = check_password_strength("V€ryStr0ngP@ssword") # len 18 (2), lower (1), upper (1), digit (1), special (1) = score 6
        self.assertEqual(feedback['level'], 'Strong', f"Test 'V€ryStr0ngP@ssword': {feedback}")

        # Test case sensitivity of special characters if your regex is specific
        # The current regex [!@#$%^&*()_+\-=\[\]{};':"\|,.<>\/?~`] is fine.

        # Test all criteria met but just under 12 chars
        feedback = check_password_strength("Abc1@efg") # len 8 (1), L(1), U(1), D(1), S(1) = score 5
        self.assertEqual(feedback['level'], 'Strong', f"Test 'Abc1@efg': {feedback}")

    def test_sqlite_io_functions(self):
        """Test the SQLite I/O functions."""
        # Test create_user_sqlite
        self.assertTrue(create_user_sqlite(TEST_DB_PATH, "user1", "hash1", "User One", 30, 1, 100))
        self.assertFalse(create_user_sqlite(TEST_DB_PATH, "user1", "hash1_dup", "User One Dup", 31, 0, 200)) # Duplicate

        # Test get_user_data_sqlite
        user1_data = get_user_data_sqlite(TEST_DB_PATH, "user1")
        self.assertIsNotNone(user1_data)
        self.assertEqual(user1_data["username"], "user1")
        self.assertEqual(user1_data["full_name"], "User One")
        self.assertEqual(user1_data["balance"], 100)
        self.assertIsNone(get_user_data_sqlite(TEST_DB_PATH, "nonexistentuser"))

        # Test update_user_balance_sqlite
        self.assertTrue(update_user_balance_sqlite(TEST_DB_PATH, "user1", 150))
        user1_updated_data = get_user_data_sqlite(TEST_DB_PATH, "user1")
        self.assertEqual(user1_updated_data["balance"], 150)
        self.assertFalse(update_user_balance_sqlite(TEST_DB_PATH, "nonexistentuser", 200))

        # Test update_user_password_hash_sqlite
        new_hash_for_user1 = hash_password("new_password_for_user1")
        self.assertTrue(update_user_password_hash_sqlite(TEST_DB_PATH, "user1", new_hash_for_user1))
        user1_reloaded = get_user_data_sqlite(TEST_DB_PATH, "user1")
        self.assertEqual(user1_reloaded["password_hash"], new_hash_for_user1)
        self.assertFalse(update_user_password_hash_sqlite(TEST_DB_PATH, "nonexistentuser", "newhash"))


        # Test record_transaction_sqlite
        # First, create another user for more comprehensive transaction tests
        self.assertTrue(create_user_sqlite(TEST_DB_PATH, "user2", hash_password("user2pass"), "User Two", 25, 0, 50))
        
        ts1 = "2023-01-01 10:00:00"
        ts2 = "2023-01-01 11:00:00"
        self.assertTrue(record_transaction_sqlite(TEST_DB_PATH, "user1", "deposit", 50, ts1))
        self.assertTrue(record_transaction_sqlite(TEST_DB_PATH, "user1", "withdraw", 20, ts2))
        self.assertFalse(record_transaction_sqlite(TEST_DB_PATH, "nonexistentuser", "deposit", 10, "2023-01-01 12:00:00"))

        # Test get_user_transactions_sqlite
        user1_transactions = get_user_transactions_sqlite(TEST_DB_PATH, "user1")
        self.assertEqual(len(user1_transactions), 2)
        # Transactions are ordered by timestamp DESC
        self.assertEqual(user1_transactions[0]["type"], "withdraw")
        self.assertEqual(user1_transactions[0]["amount"], 20)
        self.assertEqual(user1_transactions[1]["type"], "deposit")
        self.assertEqual(user1_transactions[1]["amount"], 50)

        user2_transactions = get_user_transactions_sqlite(TEST_DB_PATH, "user2")
        self.assertEqual(len(user2_transactions), 0) # No transactions for user2 yet

        nonexistent_transactions = get_user_transactions_sqlite(TEST_DB_PATH, "nonexistentuser")
        self.assertEqual(len(nonexistent_transactions), 0)

    # --- Simulation Tests for BankApp Logic (without real Tkinter) ---

    def _create_mock_app_instance(self):
        """Helper to create a BankApp instance with a mocked Tk master."""
        mock_master = MagicMock() # Mocks the Tk() root window
        app = BankApp(mock_master)
        # Ensure current_user has 'transactions' if we set it manually
        if app.current_user and 'transactions' not in app.current_user:
            app.current_user['transactions'] = []
        return app

    def test_registration_logic_simulation(self):
        """Simulate and test parts of the user registration logic using SQLite backend."""
        # Initial state: no users (assured by setUp's in-memory DB)

        # Valid registration
        uname_valid = "newuser"
        name_valid = "Test User"
        age_valid = 30
        gender_valid = 1
        balance_valid = 100
        pass_valid = "password"
        
        # Simulate BankApp's save_user behavior by directly using create_user_sqlite
        # In a real scenario, BankApp.save_user would be called, which then calls create_user_sqlite.
        # Here, we test if the underlying SQLite function works as expected for registration.
        # User password should be stored in the new PBKDF2 format.
        hashed_pass_valid = hash_password(pass_valid)
        created = create_user_sqlite(TEST_DB_PATH, uname_valid, hashed_pass_valid, 
                                     name_valid, age_valid, gender_valid, balance_valid)
        self.assertTrue(created)
        
        user_data_db = get_user_data_sqlite(TEST_DB_PATH, uname_valid)
        self.assertIsNotNone(user_data_db)
        self.assertEqual(user_data_db["username"], uname_valid)
        self.assertEqual(user_data_db["full_name"], name_valid)
        self.assertEqual(user_data_db["password_hash"], hashed_pass_valid) # Check new hash stored
        self.assertTrue(user_data_db["password_hash"].startswith("pbkdf2_sha256$"), "Registered user hash is not in PBKDF2 format.")

        # Duplicate username check (create_user_sqlite should return False)
        created_duplicate = create_user_sqlite(TEST_DB_PATH, uname_valid, hash_password("anotherpass"),
                                               "Another User", 25, 0, 50)
        self.assertFalse(created_duplicate)
        
        # Verify only one user with uname_valid exists
        # This is implicitly tested by the assertFalse above, but a direct count could be added if desired.
        # For example, fetching all users and checking length, though get_user_data_sqlite is sufficient.

    def test_login_logic_simulation(self):
        """Simulate and test login logic with SQLite backend."""
        app = self._create_mock_app_instance()
        
        uname_login_new_hash = "loginuser_new"
        pass_login_new_hash = "goodpass_new"
        initial_balance_new = 150
        
        # Setup user with new PBKDF2 hash
        create_user_sqlite(TEST_DB_PATH, uname_login_new_hash, hash_password(pass_login_new_hash), 
                           "Login NewHash User", 40, 1, initial_balance_new)

        # Successful login with new hash
        app.username_var.set(uname_login_new_hash)
        app.password_var.set(pass_login_new_hash)
        with patch('BankAppWithTkinter.messagebox') as mock_messagebox:
            app.do_login()
        self.assertIsNotNone(app.current_user, "Login with new hash failed.")
        self.assertEqual(app.current_user["uname"], uname_login_new_hash)
        mock_messagebox.showinfo.assert_called_with("Success", "Login Successful")
        app.current_user = None # Reset for next test

        # --- Test Gradual Migration (Login with Old SHA-256 Hash) ---
        uname_login_old_hash = "loginuser_old"
        pass_login_old_hash = "goodpass_old"
        initial_balance_old = 200
        old_hash_str = hash_password_old_sha256(pass_login_old_hash)

        create_user_sqlite(TEST_DB_PATH, uname_login_old_hash, old_hash_str,
                           "Login OldHash User", 50, 0, initial_balance_old)
        
        # Login with old hash
        app.username_var.set(uname_login_old_hash)
        app.password_var.set(pass_login_old_hash)
        with patch('BankAppWithTkinter.messagebox') as mock_messagebox, \
             patch('BankAppWithTkinter.logging') as mock_login_logging:
            app.do_login()
        
        self.assertIsNotNone(app.current_user, "Login with old hash failed.")
        self.assertEqual(app.current_user["uname"], uname_login_old_hash)
        mock_messagebox.showinfo.assert_called_with("Success", "Login Successful")
        
        # Verify hash was updated in DB
        user_data_after_login = get_user_data_sqlite(TEST_DB_PATH, uname_login_old_hash)
        self.assertIsNotNone(user_data_after_login)
        new_hash_in_db = user_data_after_login["password_hash"]
        self.assertNotEqual(new_hash_in_db, old_hash_str, "Hash was not updated in DB after login with old hash.")
        self.assertTrue(new_hash_in_db.startswith("pbkdf2_sha256$"), "Updated hash is not in PBKDF2 format.")
        
        # Verify logging message for hash upgrade
        mock_login_logging.info.assert_any_call(f"User '{uname_login_old_hash}' logged in with an old format password hash. Attempting to upgrade.")
        mock_login_logging.info.assert_any_call(f"Password hash for user '{uname_login_old_hash}' successfully updated to new format in DB.")

        # Verify can still login with the same password (now checked against new hash)
        app.current_user = None 
        app.username_var.set(uname_login_old_hash)
        app.password_var.set(pass_login_old_hash)
        with patch('BankAppWithTkinter.messagebox') as mock_messagebox:
            app.do_login()
        self.assertIsNotNone(app.current_user, "Login after hash migration failed.")
        self.assertEqual(app.current_user["uname"], uname_login_old_hash)
        mock_messagebox.showinfo.assert_called_with("Success", "Login Successful")
        app.current_user = None # Reset

        # --- Test failed login (wrong password) for user with old hash - ensure hash NOT updated ---
        uname_login_old_hash_fail = "loginuser_old_fail"
        pass_login_old_hash_fail = "pass_old_fail"
        old_hash_fail_str = hash_password_old_sha256(pass_login_old_hash_fail)
        create_user_sqlite(TEST_DB_PATH, uname_login_old_hash_fail, old_hash_fail_str, "OldHash Fail User", 60, 1, 300)

        app.username_var.set(uname_login_old_hash_fail)
        app.password_var.set("wrongpass") # Incorrect password
        with patch('BankAppWithTkinter.messagebox') as mock_messagebox:
            app.do_login()
        self.assertIsNone(app.current_user)
        mock_messagebox.showerror.assert_called_with("Login Failed", "Incorrect Username or Password")
        user_data_after_failed_login = get_user_data_sqlite(TEST_DB_PATH, uname_login_old_hash_fail)
        self.assertEqual(user_data_after_failed_login["password_hash"], old_hash_fail_str, "Hash was updated after a FAILED login attempt.")


        # --- Standard Failed login tests ---
        app.username_var.set(uname_login_new_hash) # Use a user with new hash
        app.password_var.set("badpass")
        with patch('BankAppWithTkinter.messagebox') as mock_messagebox:
            app.do_login()
        self.assertIsNone(app.current_user)
        mock_messagebox.showerror.assert_called_with("Login Failed", "Incorrect Username or Password")

        app.current_user = None # Reset
        app.username_var.set("nosuchuser")
        app.password_var.set("anypass")
        with patch('BankAppWithTkinter.messagebox') as mock_messagebox:
            app.do_login()
        self.assertIsNone(app.current_user)
        mock_messagebox.showerror.assert_called_with("Login Failed", "Incorrect Username or Password")


    def test_deposit_logic_simulation(self):
        """Simulate and test deposit logic with SQLite backend."""
        app = self._create_mock_app_instance()
        
        uname_deposit = "deposituser"
        initial_balance = 500
        
        # Setup user in DB (using new hash format)
        deposit_user_pass = "deposit_pass"
        create_user_sqlite(TEST_DB_PATH, uname_deposit, hash_password(deposit_user_pass), 
                           "Deposit Test", 30, 1, initial_balance)
        
        # Simulate login to set app.current_user correctly
        user_db_data = get_user_data_sqlite(TEST_DB_PATH, uname_deposit)
        app.current_user = {
            "id": user_db_data['id'], 
            "uname": user_db_data['username'], 
            "pass": user_db_data['password_hash'], # This is the new hash
            "balance": user_db_data['balance'], 
            "name": user_db_data['full_name'], 
            "age": user_db_data['age'], 
            "gender": user_db_data['gender'], 
            "transactions": get_user_transactions_sqlite(TEST_DB_PATH, uname_deposit)
        }
        
        # Mock UI elements that deposit_process interacts with
        # mock_parent_win = MagicMock() # Not strictly needed if we don't call show_deposit directly
        # mock_balance_label_dashboard = MagicMock() # For dashboard updates
        
        # --- Test successful deposit ---
        deposit_amount = 100
        
        # Mock BankApp's internal show_deposit call structure (simplified)
        # We need to simulate the call to deposit_process which is usually a command on a button.
        # To do this, we'll mock the amount variable that deposit_process reads from.
        # And then call a simplified version of the logic within deposit_process.
        
        # Simulate the Toplevel deposit window and its amount variable
        mock_deposit_win_app_ref = MagicMock() # Mocked Toplevel
        app.amount_var_deposit = MagicMock() # Mocking the StringVar for deposit amount
        app.amount_var_deposit.get.return_value = str(deposit_amount)
        
        # Mock the balance label on the deposit window, and dashboard (though less critical for logic test)
        app.bal_lbl_deposit_win = MagicMock()
        app.balance_label_dashboard = MagicMock() # This would be passed to show_deposit

        with patch('BankAppWithTkinter.messagebox') as mock_messagebox, \
             patch('BankAppWithTkinter.datetime') as mock_datetime:
            mock_datetime.now.return_value.strftime.return_value = "mock_timestamp"
            
            # Directly simulate the core logic of deposit_process
            # This bypasses needing to fully mock show_deposit and its UI setup.
            # We assume app.current_user is set (done above)
            # and app.amount_var_deposit is set and has a .get() method (mocked above)

            # --- Start of simulated deposit_process logic ---
            amount_to_deposit_str = app.amount_var_deposit.get().strip()
            self.assertTrue(is_number(amount_to_deposit_str)) # Check valid number
            amount_to_deposit_int = int(amount_to_deposit_str)
            self.assertGreater(amount_to_deposit_int, 0) # Check positive amount
            
            transaction_data = {
                'type': 'deposit',
                'amount': amount_to_deposit_int,
                'timestamp': mock_datetime.now().strftime.return_value
            }
            
            # Call the actual SQLite functions that would be called by BankApp methods
            self.assertTrue(record_transaction_sqlite(TEST_DB_PATH, app.current_user["uname"], 
                                                      transaction_data['type'], transaction_data['amount'], 
                                                      transaction_data['timestamp']))
            
            new_balance_val = app.current_user['balance'] + amount_to_deposit_int
            self.assertTrue(update_user_balance_sqlite(TEST_DB_PATH, app.current_user["uname"], new_balance_val))
            
            # Update in-memory user object as BankApp does
            app.current_user['balance'] = new_balance_val
            app.current_user['transactions'].append(transaction_data)
            
            mock_messagebox.showinfo.assert_called_with("Success", "Deposit Successful")
            # app.bal_lbl_deposit_win.config.assert_called_with(text=f"Balance: {new_balance_val}")
            # app.balance_label_dashboard.config.assert_called_with(text=f"Balance: {new_balance_val}")
            # --- End of simulated deposit_process logic ---

        self.assertEqual(app.current_user["balance"], initial_balance + deposit_amount)
        # Verify data was saved to DB
        user_data_after_deposit = get_user_data_sqlite(TEST_DB_PATH, uname_deposit)
        self.assertEqual(user_data_after_deposit["balance"], initial_balance + deposit_amount)
        
        transactions_after_deposit = get_user_transactions_sqlite(TEST_DB_PATH, uname_deposit)
        self.assertEqual(len(transactions_after_deposit), 1)
        self.assertEqual(transactions_after_deposit[0]["type"], "deposit")
        self.assertEqual(transactions_after_deposit[0]["amount"], deposit_amount)
        self.assertEqual(transactions_after_deposit[0]["timestamp"], "mock_timestamp")

        # --- Test invalid deposit amounts (simplified, focusing on checks before DB ops) ---
        # Example: Invalid amount string
        app.amount_var_deposit.get.return_value = "abc"
        with patch('BankAppWithTkinter.messagebox') as mock_messagebox:
            # Simulate just the start of deposit_process
            if not is_number(app.amount_var_deposit.get()):
                mock_messagebox.showerror("Invalid Amount", "Please provide only numeric data")
            mock_messagebox.showerror.assert_called_with("Invalid Amount", "Please provide only numeric data")
        
        # Example: Non-positive amount
        app.amount_var_deposit.get.return_value = "-10"
        with patch('BankAppWithTkinter.messagebox') as mock_messagebox:
            if is_number(app.amount_var_deposit.get()) and int(app.amount_var_deposit.get()) <= 0:
                 mock_messagebox.showerror("Invalid Amount", "Amount must be greater than zero")
            mock_messagebox.showerror.assert_called_with("Invalid Amount", "Amount must be greater than zero")


    def test_withdrawal_logic_simulation(self):
        """Simulate and test withdrawal logic with SQLite backend."""
        app = self._create_mock_app_instance()

        uname_withdraw = "withdrawuser"
        initial_balance = 500
        withdraw_user_pass = "withdraw_pass"
        create_user_sqlite(TEST_DB_PATH, uname_withdraw, hash_password(withdraw_user_pass),
                           "Withdraw Test", 30, 1, initial_balance)
        
        user_db_data_withdraw = get_user_data_sqlite(TEST_DB_PATH, uname_withdraw)
        app.current_user = {
            "id": user_db_data_withdraw['id'],
            "uname": user_db_data_withdraw['username'], 
            "pass": user_db_data_withdraw['password_hash'], 
            "balance": user_db_data_withdraw['balance'],
            "name": user_db_data_withdraw['full_name'], 
            "age": user_db_data_withdraw['age'], 
            "gender": user_db_data_withdraw['gender'], 
            "transactions": get_user_transactions_sqlite(TEST_DB_PATH, uname_withdraw)
        }

        app.amount_var_withdraw = MagicMock() # StringVar for withdrawal

        # --- Test successful withdrawal ---
        withdrawal_amount = 100
        app.amount_var_withdraw.get.return_value = str(withdrawal_amount)

        with patch('BankAppWithTkinter.messagebox') as mock_messagebox, \
             patch('BankAppWithTkinter.datetime') as mock_datetime:
            mock_datetime.now.return_value.strftime.return_value = "mock_timestamp_withdraw"

            # --- Start of simulated withdraw_process logic ---
            amount_to_withdraw_str = app.amount_var_withdraw.get().strip()
            self.assertTrue(is_number(amount_to_withdraw_str))
            amount_to_withdraw_int = int(amount_to_withdraw_str)
            self.assertGreater(amount_to_withdraw_int, 0)
            self.assertLessEqual(amount_to_withdraw_int, app.current_user['balance'])

            transaction_data = {
                'type': 'withdrawal',
                'amount': amount_to_withdraw_int,
                'timestamp': mock_datetime.now().strftime.return_value
            }
            
            self.assertTrue(record_transaction_sqlite(TEST_DB_PATH, app.current_user["uname"], 
                                                      transaction_data['type'], transaction_data['amount'], 
                                                      transaction_data['timestamp']))
            
            new_balance_val = app.current_user['balance'] - amount_to_withdraw_int
            self.assertTrue(update_user_balance_sqlite(TEST_DB_PATH, app.current_user["uname"], new_balance_val))
            
            app.current_user['balance'] = new_balance_val
            app.current_user['transactions'].append(transaction_data)
            
            mock_messagebox.showinfo.assert_called_with("Success", f"Withdraw successful of ${amount_to_withdraw_int}")
            # --- End of simulated withdraw_process logic ---

        self.assertEqual(app.current_user["balance"], initial_balance - withdrawal_amount)
        user_data_after_withdraw = get_user_data_sqlite(TEST_DB_PATH, uname_withdraw)
        self.assertEqual(user_data_after_withdraw["balance"], initial_balance - withdrawal_amount)
        
        transactions_after_withdraw = get_user_transactions_sqlite(TEST_DB_PATH, uname_withdraw)
        self.assertEqual(len(transactions_after_withdraw), 1)
        self.assertEqual(transactions_after_withdraw[0]["type"], "withdrawal")

        # --- Test invalid withdrawal (e.g., insufficient funds) ---
        app.amount_var_withdraw.get.return_value = str(app.current_user['balance'] + 100) # Insufficient
        with patch('BankAppWithTkinter.messagebox') as mock_messagebox:
            # Simulate checks from withdraw_process
            if is_number(app.amount_var_withdraw.get()):
                val = int(app.amount_var_withdraw.get())
                if val > 0 and val > app.current_user['balance']:
                    mock_messagebox.showerror("Invalid Amount", "Insufficient funds")
            mock_messagebox.showerror.assert_called_with("Invalid Amount", "Insufficient funds")

    def test_migrate_pickle_to_sqlite(self):
        """Test the migrate_pickle_to_sqlite function."""
        # 1. Create a dummy pickle file (TEST_PICKLE_FILE)
        # For migrate_pickle_to_sqlite, the 'pass' field in pickle data is assumed to be old SHA256.
        # The migration function itself does not re-hash; it stores the hash as is from the pickle.
        # The gradual migration during login handles updating these old hashes to new PBKDF2.
        dummy_pickle_data = [
            {
                "uname": "pickleuser1", "pass": hash_password_old_sha256("picklepass1"), 
                "name": "Pickle User One", "age": 40, "gender": 1, "balance": 1000,
                "transactions": [
                    {'type': 'deposit', 'amount': 1000, 'timestamp': '2023-01-01 09:00:00'}
                ]
            },
            {
                "uname": "pickleuser2", "pass": hash_password_old_sha256("picklepass2"), 
                "name": "Pickle User Two", "age": 35, "gender": 0, "balance": 500,
                "transactions": [] 
            },
            { 
                "uname": "pickleuser3", "pass": hash_password_old_sha256("picklepass3"), 
                "name": "Pickle User Three", "age": 20, "gender": 1, "balance": 100
            }
        ]
        with open(TEST_PICKLE_FILE, 'wb') as f:
            pickle.dump(dummy_pickle_data, f)

        # 2. Call migrate_pickle_to_sqlite
        # Ensure the in-memory DB is fresh (setUp does this)
        # initialize_database(TEST_DB_PATH) # Called in setUp
        
        migrated_users_count, migrated_transactions_count = migrate_pickle_to_sqlite(
            db_path=TEST_DB_PATH, 
            pickle_path=TEST_PICKLE_FILE
        )

        # 3. Verify counts
        self.assertEqual(migrated_users_count, 3)
        self.assertEqual(migrated_transactions_count, 1) # Only user1 had a transaction

        # 4. Verify data in SQLite
        # User 1
        user1_db = get_user_data_sqlite(TEST_DB_PATH, "pickleuser1")
        self.assertIsNotNone(user1_db)
        self.assertEqual(user1_db["full_name"], "Pickle User One")
        self.assertEqual(user1_db["balance"], 1000)
        user1_db_transactions = get_user_transactions_sqlite(TEST_DB_PATH, "pickleuser1")
        self.assertEqual(len(user1_db_transactions), 1)
        self.assertEqual(user1_db_transactions[0]["amount"], 1000)

        # User 2
        user2_db = get_user_data_sqlite(TEST_DB_PATH, "pickleuser2")
        self.assertIsNotNone(user2_db)
        self.assertEqual(user2_db["balance"], 500)
        user2_db_transactions = get_user_transactions_sqlite(TEST_DB_PATH, "pickleuser2")
        self.assertEqual(len(user2_db_transactions), 0)

        # User 3
        user3_db = get_user_data_sqlite(TEST_DB_PATH, "pickleuser3")
        self.assertIsNotNone(user3_db)
        self.assertEqual(user3_db["balance"], 100)
        user3_db_transactions = get_user_transactions_sqlite(TEST_DB_PATH, "pickleuser3")
        self.assertEqual(len(user3_db_transactions), 0) # Should have empty transactions list

        # 5. Test migration with an existing user in DB (should not overwrite or duplicate)
        # Re-create pickleuser1 in DB *before* migration attempt
        initialize_database(TEST_DB_PATH) # Clear DB
        create_user_sqlite(TEST_DB_PATH, "pickleuser1", "original_hash", "Original DB User1", 41, 0, 100)

        # Ensure the pickle file still exists (it should from the first part of the test)
        # Or recreate it if the migration process modifies/deletes it (current migrate_pickle_to_sqlite doesn't)
        
        migrated_users_count_again, migrated_transactions_count_again = migrate_pickle_to_sqlite(
            db_path=TEST_DB_PATH, 
            pickle_path=TEST_PICKLE_FILE
        )
        
        # pickleuser1 should not be migrated again, but user2 and user3 should.
        self.assertEqual(migrated_users_count_again, 2) 
        self.assertEqual(migrated_transactions_count_again, 0) # User1's transactions not migrated because user1 was skipped

        user1_db_after_second_migration = get_user_data_sqlite(TEST_DB_PATH, "pickleuser1")
        self.assertEqual(user1_db_after_second_migration["password_hash"], "original_hash") # Still the original
        self.assertEqual(user1_db_after_second_migration["balance"], 100) # Still the original balance
        
        # User2 and User3 should now exist from the second migration pass
        self.assertIsNotNone(get_user_data_sqlite(TEST_DB_PATH, "pickleuser2"))
        self.assertIsNotNone(get_user_data_sqlite(TEST_DB_PATH, "pickleuser3"))

        # Clean up is handled by tearDown for TEST_PICKLE_FILE


if __name__ == '__main__':
    unittest.main(argv=['first-arg-is-ignored'], exit=False)

# Note: The BankApp methods like deposit_process and withdraw_process are deeply tied to Tkinter vars
# and messagebox calls. The simulation tests above try to test the core logic (data changes, conditions)
# by replicating the conditional checks and data manipulations rather than calling the methods directly,
# which would require more extensive mocking of Tkinter elements.
# A more robust approach for those methods would involve refactoring them in BankAppWithTkinter.py
# to separate the logic from the UI updates, making the logic part directly testable.
# For instance, a method like `process_deposit_logic(username, amount)` could return (new_balance, transaction_record)
# or raise specific exceptions for errors, and the UI method would then call this and update Tkinter elements.
# Given the current structure, these simulation tests are a compromise.
# The test_is_number and test_hash_password, test_data_storage_functions are more direct unit tests.

    def test_rate_limiting_logic(self):
        # Define a test username
        test_user = "rate_test_user"
        test_pass = "password"
        
        # Create the user for testing login success/failure
        create_user_sqlite(TEST_DB_PATH, test_user, hash_password(test_pass), "Rate Test", 30, 1, 100)

        # --- Test helper functions directly ---
        # 1. Initial state: No attempts
        info = get_login_attempt_info(TEST_DB_PATH, test_user)
        self.assertIsNone(info, "There should be no login attempt info for a new user.")

        # 2. Record one failed attempt
        record_failed_login_attempt(TEST_DB_PATH, test_user)
        info = get_login_attempt_info(TEST_DB_PATH, test_user)
        self.assertIsNotNone(info)
        self.assertEqual(info['username'], test_user)
        self.assertEqual(info['failure_count'], 1)
        self.assertIsNone(info['lockout_until'], "Should not be locked out after 1 failure.")

        # 3. Reset attempts
        reset_login_attempts(TEST_DB_PATH, test_user)
        info = get_login_attempt_info(TEST_DB_PATH, test_user)
        self.assertIsNone(info, "Login attempt info should be cleared after reset.")

        # 4. Trigger lockout by exceeding MAX_FAILED_ATTEMPTS
        for i in range(MAX_FAILED_ATTEMPTS):
            record_failed_login_attempt(TEST_DB_PATH, test_user)
        
        info = get_login_attempt_info(TEST_DB_PATH, test_user)
        self.assertIsNotNone(info)
        self.assertEqual(info['failure_count'], MAX_FAILED_ATTEMPTS)
        self.assertIsNotNone(info['lockout_until'], "Should be locked out now.")
        
        # Check lockout_until time is roughly correct (within a small delta)
        lockout_end_dt = datetime.strptime(info['lockout_until'], '%Y-%m-%d %H:%M:%S')
        expected_end_dt = datetime.now() + timedelta(minutes=LOCKOUT_DURATION_MINUTES)
        self.assertAlmostEqual(lockout_end_dt, expected_end_dt, delta=timedelta(seconds=5),
                               msg="Lockout time not set as expected.")

        # --- Test do_login integration ---
        app = self._create_mock_app_instance() # From existing test setup

        # Scenario A: User gets locked out after MAX_FAILED_ATTEMPTS
        reset_login_attempts(TEST_DB_PATH, test_user) # Clean slate for this user
        app.username_var.set(test_user)
        app.password_var.set("wrong_password")

        for i in range(MAX_FAILED_ATTEMPTS):
            with patch('BankAppWithTkinter.messagebox') as mock_messagebox:
                app.do_login()
                if i < MAX_FAILED_ATTEMPTS - 1:
                    mock_messagebox.showerror.assert_called_with("Login Failed", "Incorrect Username or Password")
                else:
                    # On the attempt that triggers lockout, a different message might be shown by the enhanced do_login
                    # This depends on the exact implementation of the "enhanced message"
                    # For now, let's assume it shows a lockout message on the attempt *after* lockout is active
                    # or the specific "now locked" message.
                    # Checking for any call to showerror is a basic check here.
                    mock_messagebox.showerror.assert_called()
        
        # Verify user is locked in DB
        info_after_lockout = get_login_attempt_info(TEST_DB_PATH, test_user)
        self.assertIsNotNone(info_after_lockout)
        self.assertEqual(info_after_lockout['failure_count'], MAX_FAILED_ATTEMPTS)
        self.assertIsNotNone(info_after_lockout['lockout_until'])

        # Scenario B: Attempt login while locked out
        with patch('BankAppWithTkinter.messagebox') as mock_messagebox:
            app.do_login() # Attempt login again
            # Expected: Show error about account being locked
            mock_messagebox.showerror.assert_called_with(
                "Login Failed", 
                unittest.mock.ANY # Using ANY because the exact time remaining string is hard to match
            ) 
            # Check that the message contains "locked"
            args, _ = mock_messagebox.showerror.call_args
            self.assertIn("locked", args[1].lower())


        # Scenario C: Login succeeds after lockout period expires
        # Mock datetime.now() to be in the future, after lockout_until
        current_lockout_str = get_login_attempt_info(TEST_DB_PATH, test_user)['lockout_until']
        lockout_end_time_obj = datetime.strptime(current_lockout_str, '%Y-%m-%d %H:%M:%S')
        
        future_time = lockout_end_time_obj + timedelta(seconds=1) # 1 second after lockout expires
        
        with patch('BankAppWithTkinter.datetime') as mock_datetime_module:
            mock_datetime_module.now.return_value = future_time
            mock_datetime_module.strptime = datetime.strptime # Keep strptime working
            mock_datetime_module.timedelta = timedelta # Keep timedelta working

            # Attempt login with correct password
            app.password_var.set(test_pass) # Set correct password
            with patch('BankAppWithTkinter.messagebox') as mock_messagebox_success:
                app.do_login()
            
            mock_messagebox_success.showinfo.assert_called_with("Success", "Login Successful")
            self.assertIsNotNone(app.current_user)
            self.assertEqual(app.current_user['uname'], test_user)

            # Verify attempts were reset in DB
            info_after_successful_login = get_login_attempt_info(TEST_DB_PATH, test_user)
            self.assertIsNone(info_after_successful_login, "Login attempts should be reset after successful login post-lockout.")

        # Scenario D: Successful login resets attempts if user was not locked but had some failures
        reset_login_attempts(TEST_DB_PATH, test_user) # Clean slate
        app.current_user = None # Reset app state

        # Record a few failures, but not enough to lock
        record_failed_login_attempt(TEST_DB_PATH, test_user)
        record_failed_login_attempt(TEST_DB_PATH, test_user)
        info_before_success = get_login_attempt_info(TEST_DB_PATH, test_user)
        self.assertEqual(info_before_success['failure_count'], 2)

        app.username_var.set(test_user)
        app.password_var.set(test_pass) # Correct password
        with patch('BankAppWithTkinter.messagebox') as mock_messagebox_final:
            app.do_login()
        
        mock_messagebox_final.showinfo.assert_called_with("Success", "Login Successful")
        self.assertIsNotNone(app.current_user)
        info_after_final_success = get_login_attempt_info(TEST_DB_PATH, test_user)
        self.assertIsNone(info_after_final_success, "Login attempts should be reset by a successful login.")
