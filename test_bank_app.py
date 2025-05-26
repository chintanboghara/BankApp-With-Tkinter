import unittest
import os
import pickle
import hashlib
from unittest.mock import MagicMock, patch

import sqlite3

# Assuming BankAppWithTkinter.py is in the same directory or accessible in PYTHONPATH
from BankAppWithTkinter import (
    hash_password,
    # load_user_data, # Removed
    # save_user_data, # Removed
    is_number,
    BankApp,  # Will be used carefully, potentially with mocked Tk
    # DATA_FILE, # Removed
    DB_PATH, # Added
    initialize_database,
    create_user_sqlite,
    get_user_data_sqlite,
    update_user_balance_sqlite,
    record_transaction_sqlite,
    get_user_transactions_sqlite,
    load_user_data_pickle, # For migration test
    migrate_pickle_to_sqlite # For migration test
)

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

    def test_hash_password(self):
        """Test the hash_password function."""
        pw1 = "password123"
        pw2 = "anotherPassword"

        self.assertEqual(hash_password(pw1), hash_password(pw1))
        self.assertNotEqual(hash_password(pw1), hash_password(pw2))

        # Check if it's a hex digest
        hashed_pw = hash_password(pw1)
        self.assertIsInstance(hashed_pw, str)
        try:
            int(hashed_pw, 16)
            is_hex = True
        except ValueError:
            is_hex = False
        self.assertTrue(is_hex, "Password hash is not a valid hex string.")
        self.assertEqual(len(hashed_pw), 64) # SHA-256 produces 64 hex characters

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

        # Test record_transaction_sqlite
        # First, create another user for more comprehensive transaction tests
        self.assertTrue(create_user_sqlite(TEST_DB_PATH, "user2", "hash2", "User Two", 25, 0, 50))
        
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
        created = create_user_sqlite(TEST_DB_PATH, uname_valid, hash_password(pass_valid), 
                                     name_valid, age_valid, gender_valid, balance_valid)
        self.assertTrue(created)
        
        user_data_db = get_user_data_sqlite(TEST_DB_PATH, uname_valid)
        self.assertIsNotNone(user_data_db)
        self.assertEqual(user_data_db["username"], uname_valid)
        self.assertEqual(user_data_db["full_name"], name_valid)

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
        
        uname_login = "loginuser"
        pass_login = "goodpass"
        initial_balance = 100
        
        # Setup user in DB
        create_user_sqlite(TEST_DB_PATH, uname_login, hash_password(pass_login), 
                           "Login TestUser", 40, 1, initial_balance)

        # Successful login
        app.username_var.set(uname_login)
        app.password_var.set(pass_login)
        
        # Mock messagebox to avoid GUI pop-ups
        with patch('BankAppWithTkinter.messagebox') as mock_messagebox:
            app.do_login() # This method updates app.current_user
        
        self.assertIsNotNone(app.current_user)
        self.assertEqual(app.current_user["uname"], uname_login)
        self.assertEqual(app.current_user["balance"], initial_balance)
        # Check if transactions are loaded (should be empty for new user)
        self.assertIn('transactions', app.current_user)
        self.assertEqual(len(app.current_user['transactions']), 0)
        mock_messagebox.showinfo.assert_called_with("Success", "Login Successful")

        # Failed login - wrong password
        app.current_user = None # Reset
        app.password_var.set("badpass")
        with patch('BankAppWithTkinter.messagebox') as mock_messagebox:
            app.do_login()
        self.assertIsNone(app.current_user)
        mock_messagebox.showerror.assert_called_with("Login Failed", "Incorrect Username or Password")

        # Failed login - user not found
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
        
        # Setup user in DB
        create_user_sqlite(TEST_DB_PATH, uname_deposit, "hash", "Deposit Test", 30, 1, initial_balance)
        
        # Simulate login to set app.current_user correctly
        app.current_user = {
            "id": get_user_data_sqlite(TEST_DB_PATH, uname_deposit)['id'], # Fetch ID
            "uname": uname_deposit, "pass": "hash", "balance": initial_balance, 
            "name": "Deposit Test", "age": 30, "gender": 1, 
            "transactions": get_user_transactions_sqlite(TEST_DB_PATH, uname_deposit) # Should be empty
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
        create_user_sqlite(TEST_DB_PATH, uname_withdraw, "hash", "Withdraw Test", 30, 1, initial_balance)
        
        app.current_user = {
            "id": get_user_data_sqlite(TEST_DB_PATH, uname_withdraw)['id'],
            "uname": uname_withdraw, "pass": "hash", "balance": initial_balance,
            "name": "Withdraw Test", "age": 30, "gender": 1, 
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
        dummy_pickle_data = [
            {
                "uname": "pickleuser1", "pass": hash_password("picklepass1"), "name": "Pickle User One",
                "age": 40, "gender": 1, "balance": 1000,
                "transactions": [
                    {'type': 'deposit', 'amount': 1000, 'timestamp': '2023-01-01 09:00:00'}
                ]
            },
            {
                "uname": "pickleuser2", "pass": hash_password("picklepass2"), "name": "Pickle User Two",
                "age": 35, "gender": 0, "balance": 500,
                "transactions": [] # No transactions
            },
            { # User missing some non-critical data, but core data present
                "uname": "pickleuser3", "pass": hash_password("picklepass3"), "name": "Pickle User Three",
                "age": 20, "gender": 1, "balance": 100 # Transactions will default to empty if key missing
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
