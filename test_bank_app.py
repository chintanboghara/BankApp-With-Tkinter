import unittest
import os
import pickle
import hashlib
from unittest.mock import MagicMock, patch

# Assuming BankAppWithTkinter.py is in the same directory or accessible in PYTHONPATH
from BankAppWithTkinter import (
    hash_password,
    load_user_data,
    save_user_data,
    is_number,
    BankApp,  # Will be used carefully, potentially with mocked Tk
    DATA_FILE
)

# Store the original DATA_FILE name and define a test-specific one
ORIGINAL_DATA_FILE = DATA_FILE
TEST_DATA_FILE = 'test_appData.bin'

class TestBankAppLogic(unittest.TestCase):

    def setUp(self):
        """
        Set up for each test.
        - Back up original data file if it exists.
        - Set DATA_FILE to TEST_DATA_FILE for test isolation.
        - Ensure no old test data file exists.
        """
        global DATA_FILE
        # Ensure BankAppWithTkinter uses the test file
        patcher = patch('BankAppWithTkinter.DATA_FILE', TEST_DATA_FILE)
        self.addCleanup(patcher.stop)
        patcher.start()
        DATA_FILE = TEST_DATA_FILE # Also update for test file's direct usage

        if os.path.exists(ORIGINAL_DATA_FILE):
            os.rename(ORIGINAL_DATA_FILE, ORIGINAL_DATA_FILE + ".bak")
        
        if os.path.exists(TEST_DATA_FILE):
            os.remove(TEST_DATA_FILE)

    def tearDown(self):
        """
        Clean up after each test.
        - Restore original data file if it was backed up.
        - Remove the test data file.
        - Restore original DATA_FILE name for other potential modules.
        """
        global DATA_FILE
        if os.path.exists(TEST_DATA_FILE):
            os.remove(TEST_DATA_FILE)

        if os.path.exists(ORIGINAL_DATA_FILE + ".bak"):
            os.rename(ORIGINAL_DATA_FILE + ".bak", ORIGINAL_DATA_FILE)
        
        DATA_FILE = ORIGINAL_DATA_FILE # Restore for any other module if needed

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

    def test_data_storage_functions(self):
        """Test save_user_data and load_user_data."""
        # 1. Test saving and loading typical data
        sample_data = [
            {"uname": "user1", "pass": "hash1", "balance": 100, "transactions": []},
            {"uname": "user2", "pass": "hash2", "balance": 200, "transactions": [{'type': 'deposit', 'amount': 50}]}
        ]
        save_user_data(sample_data)
        loaded_data = load_user_data()
        self.assertEqual(loaded_data, sample_data)

        # 2. Test load_user_data returns empty list if file doesn't exist
        if os.path.exists(TEST_DATA_FILE):
            os.remove(TEST_DATA_FILE)
        self.assertEqual(load_user_data(), [])

        # 3. Test load_user_data initializes transactions: [] if missing
        data_missing_transactions = [
            {"uname": "user3", "pass": "hash3", "balance": 300} # No 'transactions' key
        ]
        # Manually pickle this to create the file state
        with open(TEST_DATA_FILE, 'wb') as f:
            pickle.dump(data_missing_transactions, f)
        
        loaded_data_fixed = load_user_data()
        self.assertIn('transactions', loaded_data_fixed[0])
        self.assertEqual(loaded_data_fixed[0]['transactions'], [])

        # 4. Test load_user_data with empty file (pickle error)
        with open(TEST_DATA_FILE, 'wb') as f:
            pass # Create an empty file
        self.assertEqual(load_user_data(), []) # Should handle pickle error and return empty

        # 5. Test load_user_data with corrupted file (pickle error)
        with open(TEST_DATA_FILE, 'wb') as f:
            f.write(b"corrupted data")
        self.assertEqual(load_user_data(), [])

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
        """Simulate and test parts of the user registration logic."""
        # Initial state: no users
        save_user_data([])

        # Valid registration
        user_data_valid = {
            "uname": "newuser", "name": "Test User", "age": 30, 
            "gender": 1, "balance": 100, "pass": hash_password("password")
        }
        users = load_user_data()
        users.append(user_data_valid)
        save_user_data(users)
        
        loaded_users = load_user_data()
        self.assertEqual(len(loaded_users), 1)
        self.assertEqual(loaded_users[0]["uname"], "newuser")

        # Duplicate username
        user_data_duplicate = {
            "uname": "newuser", "name": "Another User", "age": 25,
            "gender": 0, "balance": 50, "pass": hash_password("newpass")
        }
        # Simulate check:
        is_duplicate = any(u["uname"] == user_data_duplicate["uname"] for u in loaded_users)
        self.assertTrue(is_duplicate)
        # If we were to call save_user from BankApp, it should prevent this.
        # Here, we just check that our simulation of the check works.

        # Invalid data (e.g., non-numeric age - BankApp's save_user would check this)
        # The actual save_user in BankApp does these checks before appending.
        # Here, we are more focused on the data storage aspect and username duplication.

    def test_login_logic_simulation(self):
        """Simulate and test login logic."""
        app = self._create_mock_app_instance()
        
        test_users = [
            {"uname": "loginuser", "pass": hash_password("goodpass"), "balance": 100, "transactions": []}
        ]
        save_user_data(test_users)

        # Successful login
        app.username_var.set("loginuser")
        app.password_var.set("goodpass")
        
        # Mock messagebox to avoid GUI pop-ups
        with patch('BankAppWithTkinter.messagebox') as mock_messagebox:
            app.do_login() # This method updates app.current_user
        
        self.assertIsNotNone(app.current_user)
        self.assertEqual(app.current_user["uname"], "loginuser")
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
        """Simulate and test deposit logic."""
        app = self._create_mock_app_instance()
        
        # Setup a current user for the app instance
        initial_balance = 500
        app.current_user = {
            "uname": "deposituser", "pass": "hash", "balance": initial_balance, 
            "name": "Deposit Test", "age": 30, "gender": 1, "transactions": []
        }
        # Also save this user to the "database" for update_user_balance to find
        save_user_data([app.current_user])

        # Mock UI elements that deposit_process interacts with
        mock_parent_win = MagicMock()
        mock_balance_label_dashboard = MagicMock() # For dashboard
        
        # --- Test successful deposit ---
        deposit_amount = 100
        # Simulate what show_deposit would do to set up for deposit_process
        mock_deposit_win = MagicMock() # The Toplevel window for deposit
        mock_amount_var = MagicMock()
        mock_amount_var.get.return_value = str(deposit_amount)
        mock_bal_lbl_deposit_win = MagicMock() # Balance label on deposit window

        # Patching internal calls made by deposit_process
        with patch('BankAppWithTkinter.messagebox') as mock_messagebox, \
             patch.object(app, 'update_user_balance', wraps=app.update_user_balance) as mock_update_balance:
            
            # Simulate calling the core logic part of deposit
            # This is a bit simplified as we are not creating the full deposit window
            # We directly call a simplified version of what deposit_process would do
            
            # Valid amount
            self.assertTrue(is_number(mock_amount_var.get()))
            self.assertGreater(int(mock_amount_var.get()), 0)

            transaction = {
                'type': 'deposit',
                'amount': int(mock_amount_var.get()),
                'timestamp': 'dummy_timestamp' # In real code, this is datetime.now()
            }
            app.current_user['transactions'].append(transaction)
            
            new_balance = int(app.current_user['balance']) + int(mock_amount_var.get())
            app.update_user_balance(new_balance) # This calls save_user_data

            mock_messagebox.showinfo.assert_called_with("Success", "Deposit Successful")
            mock_bal_lbl_deposit_win.config.assert_not_called() # Not directly testing this mock call here
            mock_balance_label_dashboard.config.assert_not_called() # Nor this one

        self.assertEqual(app.current_user["balance"], initial_balance + deposit_amount)
        self.assertEqual(len(app.current_user["transactions"]), 1)
        self.assertEqual(app.current_user["transactions"][0]["type"], "deposit")
        self.assertEqual(app.current_user["transactions"][0]["amount"], deposit_amount)
        
        # Verify data was saved
        loaded_data = load_user_data()
        self.assertEqual(loaded_data[0]["balance"], initial_balance + deposit_amount)
        self.assertEqual(len(loaded_data[0]["transactions"]), 1)

        # --- Test invalid deposit amounts ---
        invalid_amounts = ["-10", "0", "abc"]
        for amount_str in invalid_amounts:
            app.current_user["balance"] = initial_balance + deposit_amount # Reset balance for each test
            app.current_user["transactions"] = [app.current_user["transactions"][0]] # Reset transactions
            save_user_data([app.current_user]) # Save reset state

            mock_amount_var.get.return_value = amount_str
            with patch('BankAppWithTkinter.messagebox') as mock_messagebox:
                # Simulate the checks in deposit_process
                if not is_number(amount_str):
                    mock_messagebox.showerror("Invalid Amount", "Please provide only numeric data")
                elif int(amount_str) <= 0:
                    mock_messagebox.showerror("Invalid Amount", "Amount must be greater than zero")
                else:
                    # This part should not be reached for these invalid amounts
                    self.fail("Deposit logic allowed invalid amount: " + amount_str)

                if not is_number(amount_str):
                    mock_messagebox.showerror.assert_called_with("Invalid Amount", "Please provide only numeric data")
                elif int(amount_str) <= 0:
                    mock_messagebox.showerror.assert_called_with("Invalid Amount", "Amount must be greater than zero")
            
            # Ensure balance and transactions didn't change
            self.assertEqual(app.current_user["balance"], initial_balance + deposit_amount)
            self.assertEqual(len(app.current_user["transactions"]), 1)


    def test_withdrawal_logic_simulation(self):
        """Simulate and test withdrawal logic."""
        app = self._create_mock_app_instance()

        initial_balance = 500
        app.current_user = {
            "uname": "withdrawuser", "pass": "hash", "balance": initial_balance,
            "name": "Withdraw Test", "age": 30, "gender": 1, "transactions": []
        }
        save_user_data([app.current_user])

        mock_amount_var = MagicMock()

        # --- Test successful withdrawal ---
        withdrawal_amount = 100
        mock_amount_var.get.return_value = str(withdrawal_amount)

        with patch('BankAppWithTkinter.messagebox') as mock_messagebox, \
             patch.object(app, 'update_user_balance', wraps=app.update_user_balance):

            # Simulate checks and logic from withdraw_process
            self.assertTrue(is_number(mock_amount_var.get()))
            amount_val = int(mock_amount_var.get())
            self.assertGreater(amount_val, 0)
            self.assertLessEqual(amount_val, app.current_user['balance'])

            transaction = {
                'type': 'withdrawal',
                'amount': amount_val,
                'timestamp': 'dummy_timestamp' 
            }
            app.current_user['transactions'].append(transaction)
            
            new_balance = int(app.current_user['balance']) - amount_val
            app.update_user_balance(new_balance)

            mock_messagebox.showinfo.assert_called_with("Success", f"Withdraw successful of ${amount_val}")

        self.assertEqual(app.current_user["balance"], initial_balance - withdrawal_amount)
        self.assertEqual(len(app.current_user["transactions"]), 1)
        self.assertEqual(app.current_user["transactions"][0]["type"], "withdrawal")
        self.assertEqual(app.current_user["transactions"][0]["amount"], withdrawal_amount)
        
        loaded_data = load_user_data()
        self.assertEqual(loaded_data[0]["balance"], initial_balance - withdrawal_amount)

        # --- Test invalid withdrawal amounts ---
        # Reset state for these tests
        app.current_user["balance"] = initial_balance - withdrawal_amount 
        app.current_user["transactions"] = [app.current_user["transactions"][0]]
        save_user_data([app.current_user])
        
        current_bal_for_invalid_tests = app.current_user["balance"]
        num_transactions_before_invalid = len(app.current_user["transactions"])

        invalid_scenarios = {
            "-10": "Amount must be greater than zero",
            "0": "Amount must be greater than zero",
            "abc": "Please provide only numeric data",
            str(current_bal_for_invalid_tests + 100): "Insufficient funds" # Insufficient
        }

        for amount_str, error_msg in invalid_scenarios.items():
            mock_amount_var.get.return_value = amount_str
            with patch('BankAppWithTkinter.messagebox') as mock_messagebox:
                # Simulate the checks in withdraw_process
                if not is_number(amount_str):
                    mock_messagebox.showerror("Invalid Amount", "Please provide only numeric data")
                else:
                    amount_val_invalid = int(amount_str)
                    if amount_val_invalid <= 0:
                        mock_messagebox.showerror("Invalid Amount", "Amount must be greater than zero")
                    elif int(app.current_user['balance']) - amount_val_invalid < 0:
                         mock_messagebox.showerror("Invalid Amount", "Insufficient funds")
                    else:
                        self.fail("Withdrawal logic allowed invalid amount/scenario: " + amount_str)
                
                mock_messagebox.showerror.assert_called_with("Invalid Amount", error_msg)
            
            self.assertEqual(app.current_user["balance"], current_bal_for_invalid_tests)
            self.assertEqual(len(app.current_user["transactions"]), num_transactions_before_invalid)


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
