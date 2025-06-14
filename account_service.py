# -*- coding: utf-8 -*-
"""
Account Service for the Bank Application.

This module provides the AccountService class, responsible for all interactions
with the database concerning user account data, balances, and transaction records.
It handles creating users, fetching user data, updating balances and passwords,
recording transactions, and migrating data from older formats (pickle).
"""
import sqlite3
import logging
import os
import pickle
from pathlib import Path
import constants as const

class AccountService:
    """
    Manages user account data and financial transactions in the database.

    Attributes:
        db_path (str): The path to the SQLite database file.
    """
    def __init__(self, db_path: Path | str):
        """
        Initializes the AccountService with the path to the database.

        Args:
            db_path (Path | str): The path to the SQLite database.
                                  Can be a string or a Path object.
        """
        self.db_path = db_path
        if isinstance(self.db_path, Path):
            self.db_path = str(self.db_path)

    def create_user_sqlite(self, username: str, password_hash: str, full_name: str,
                           age: int, gender: int, initial_balance: int) -> bool:
        """
        Inserts a new user into the 'users' table in the SQLite database.

        Args:
            username (str): The username for the new user. Must be unique.
            password_hash (str): The hashed password for the new user.
            full_name (str): The full name of the new user.
            age (int): The age of the new user.
            gender (int): The gender of the new user (typically 0 for Female, 1 for Male).
            initial_balance (int): The initial account balance for the new user.

        Returns:
            bool: True if the user was created successfully, False otherwise (e.g., username exists, database error).
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                # SQL query to insert a new user, using f-strings for table/column names from constants
                # and parameterized queries for user-supplied values to prevent SQL injection.
                cursor.execute(f"""
                    INSERT INTO {const.TABLE_USERS}
                        ({const.COLUMN_USERNAME}, {const.COLUMN_PASSWORD_HASH}, {const.COLUMN_FULL_NAME},
                         age, gender, {const.COLUMN_BALANCE})
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (username, password_hash, full_name, age, gender, initial_balance))
                conn.commit()
                logging.info("User '%s' created successfully in SQLite via AccountService.", username)
                return True
        except sqlite3.IntegrityError: # Specific error for UNIQUE constraint violation (e.g., username exists)
            logging.warning("Failed to create user '%s' in SQLite via AccountService: Username already exists.", username)
            return False
        except sqlite3.Error as e: # Catch other SQLite related errors
            logging.exception("Error creating user '%s' in SQLite via AccountService: %s", username, e)
            return False

    def get_user_data_sqlite(self, username: str) -> dict | None:
        """
        Fetches user data from the 'users' table by username.

        Args:
            username (str): The username of the user to retrieve.

        Returns:
            dict | None: A dictionary containing all columns for the user if found,
                         otherwise None. Returns None also in case of a database error.
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row  # Allows accessing columns by name
                cursor = conn.cursor()
                cursor.execute(f"SELECT * FROM {const.TABLE_USERS} WHERE {const.COLUMN_USERNAME} = ?", (username,))
                row = cursor.fetchone()
                if row:
                    logging.info("User data for '%s' retrieved successfully from SQLite via AccountService.", username)
                    return dict(row)  # Convert sqlite3.Row to a standard dictionary
                else:
                    logging.info("No user data found for '%s' in SQLite via AccountService.", username)
                    return None
        except sqlite3.Error as e:
            logging.exception("Error fetching user data for '%s' from SQLite via AccountService: %s", username, e)
            return None

    def update_user_balance_sqlite(self, username: str, new_balance: int) -> bool:
        """
        Updates the balance for the specified username in the 'users' table.

        Args:
            username (str): The username whose balance needs to be updated.
            new_balance (int): The new balance amount.

        Returns:
            bool: True if the balance was updated successfully, False otherwise
                  (e.g., user not found, database error).
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(f"UPDATE {const.TABLE_USERS} SET {const.COLUMN_BALANCE} = ? WHERE {const.COLUMN_USERNAME} = ?",
                               (new_balance, username))
                conn.commit()
                if cursor.rowcount > 0: # rowcount indicates if any row was affected
                    logging.info("Balance updated for user '%s' to %d in SQLite via AccountService.", username, new_balance)
                    return True
                else:
                    # User not found or balance was already the same (though latter is less likely to be an "error")
                    logging.warning("Failed to update balance for user '%s' in SQLite via AccountService: User not found or no change needed.", username)
                    return False
        except sqlite3.Error as e:
            logging.exception("Error updating balance for user '%s' in SQLite via AccountService: %s", username, e)
            return False

    def update_user_password_hash_sqlite(self, username: str, new_password_hash: str) -> bool:
        """
        Updates the password_hash for the specified username in the 'users' table.

        Args:
            username (str): The username whose password hash needs to be updated.
            new_password_hash (str): The new password hash.

        Returns:
            bool: True if the password hash was updated successfully, False otherwise.
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(f"UPDATE {const.TABLE_USERS} SET {const.COLUMN_PASSWORD_HASH} = ? WHERE {const.COLUMN_USERNAME} = ?",
                               (new_password_hash, username))
                conn.commit()
                if cursor.rowcount > 0:
                    logging.info("Password hash updated successfully for user '%s' in SQLite via AccountService.", username)
                    return True
                else:
                    logging.warning("Failed to update password hash for user '%s' in SQLite via AccountService: User not found or no change made.", username)
                    return False
        except sqlite3.Error as e:
            logging.exception("SQLite error updating password hash for user '%s' via AccountService: %s", username, e)
            return False

    def record_transaction_sqlite(self, username: str, transaction_type: str, amount: int, timestamp: str) -> bool:
        """
        Records a new transaction for the user in the 'transactions' table.

        Args:
            username (str): The username of the user performing the transaction.
            transaction_type (str): The type of transaction (e.g., 'deposit', 'withdrawal').
            amount (int): The amount of the transaction.
            timestamp (str): The ISO format timestamp of the transaction.

        Returns:
            bool: True if the transaction was recorded successfully, False otherwise.
        """
        user_data = self.get_user_data_sqlite(username)
        if not user_data:
            logging.warning("Failed to record transaction for '%s' via AccountService: User not found.", username)
            return False

        user_id = user_data[const.COLUMN_ID]
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                # Insert new transaction record
                cursor.execute(f"""
                    INSERT INTO {const.TABLE_TRANSACTIONS} (user_id, type, amount, timestamp)
                    VALUES (?, ?, ?, ?)
                """, (user_id, transaction_type, amount, timestamp))
                conn.commit()
                logging.info("Transaction recorded for user '%s' (ID: %d) via AccountService: Type: %s, Amount: %d",
                             username, user_id, transaction_type, amount)
                return True
        except sqlite3.Error as e:
            logging.exception("Error recording transaction for user '%s' (ID: %d) via AccountService: %s", username, user_id, e)
            return False

    def get_user_transactions_sqlite(self, username: str) -> list:
        """
        Fetches all transactions for a specific user, ordered by timestamp descending.

        Args:
            username (str): The username of the user whose transactions are to be retrieved.

        Returns:
            list: A list of dictionaries, where each dictionary represents a transaction.
                  Returns an empty list if the user is not found or has no transactions,
                  or in case of a database error.
        """
        user_data = self.get_user_data_sqlite(username)
        if not user_data:
            logging.info("No transactions found for '%s' via AccountService: User not found.", username)
            return []

        user_id = user_data[const.COLUMN_ID]
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                # Fetch transactions, ordered by most recent first
                cursor.execute(f"""
                    SELECT type, amount, timestamp FROM {const.TABLE_TRANSACTIONS}
                    WHERE user_id = ? ORDER BY timestamp DESC
                """, (user_id,))
                transactions = [dict(row) for row in cursor.fetchall()]
                logging.info("Retrieved %d transactions for user '%s' (ID: %d) from SQLite via AccountService.",
                             len(transactions), username, user_id)
                return transactions
        except sqlite3.Error as e:
            logging.exception("Error fetching transactions for user '%s' (ID: %d) from SQLite via AccountService: %s",
                             username, user_id, e)
            return []

    def _load_user_data_pickle(self, pickle_path: str) -> list:
        """
        Loads user data from a binary pickle file. (Helper for migration)

        Ensures each user dictionary in the loaded data has a 'transactions' key,
        initializing it to an empty list if missing.

        Args:
            pickle_path (str): The path to the pickle file.

        Returns:
            list: A list of user data dictionaries. Returns an empty list if the
                  file does not exist or an error occurs during loading/unpickling.
        """
        if not os.path.exists(pickle_path):
            logging.info("Pickle data file (%s) does not exist. Returning empty list for migration.", pickle_path)
            return []
        try:
            with open(pickle_path, 'rb') as f:
                data = pickle.load(f)
                # Ensure data integrity for 'transactions' key
                for user_dict in data:
                    if 'transactions' not in user_dict:
                        user_dict['transactions'] = []
                logging.info("User data loaded successfully from pickle file: %s for migration.", pickle_path)
                return data
        except FileNotFoundError: # Should be caught by os.path.exists, but as a safeguard
            logging.exception("Pickle file %s not found during load attempt for migration.", pickle_path)
            return []
        except pickle.UnpicklingError:
            logging.exception("Error unpickling data from %s during migration.", pickle_path)
            return []
        except Exception:
            logging.exception("Unexpected error loading user data from pickle file %s for migration.", pickle_path)
            return []

    def migrate_pickle_to_sqlite(self, pickle_path: str = const.DEFAULT_PICKLE_FILE) -> tuple[int, int]:
        """
        Migrates user data from a legacy pickle file to the SQLite database.

        This process involves reading user and transaction data from the pickle file
        and inserting it into the corresponding SQLite tables. It's designed to be
        run once if old data exists.

        Args:
            pickle_path (str, optional): The path to the pickle file.
                                         Defaults to `const.DEFAULT_PICKLE_FILE`.

        Returns:
            tuple[int, int]: A tuple containing the number of users migrated and
                             the number of transactions migrated.
        """
        logging.info("Starting migration from pickle file '%s' to SQLite DB '%s' via AccountService.", pickle_path, self.db_path)

        users_data = self._load_user_data_pickle(pickle_path)
        if not users_data:
            logging.info("No data found in pickle file '%s'. Migration terminated.", pickle_path)
            return 0, 0

        migrated_users_count = 0
        migrated_transactions_count = 0

        for user_pickle_data in users_data: # Renamed to avoid conflict
            try:
                uname = user_pickle_data.get("uname")
                pass_hash = user_pickle_data.get("pass")
                name = user_pickle_data.get("name")
                age = user_pickle_data.get("age")
                gender = user_pickle_data.get("gender")
                balance = user_pickle_data.get("balance", const.DEFAULT_BALANCE)
                transactions_pickle = user_pickle_data.get("transactions", [])

                # Basic validation of core user data from pickle
                if not all([uname, pass_hash, name, age is not None, gender is not None]):
                    logging.warning("Skipping user due to missing core data in pickle: %s", uname or "Unknown user")
                    continue

                if self.create_user_sqlite(uname, pass_hash, name, int(age), int(gender), int(balance)):
                    migrated_users_count += 1
                    logging.info("User '%s' migrated successfully to SQLite by AccountService.", uname)

                    for tx_pickle_data in transactions_pickle:
                        tx_type = tx_pickle_data.get('type')
                        tx_amount = tx_pickle_data.get('amount')
                        tx_timestamp = tx_pickle_data.get('timestamp')
                        if not all([tx_type, tx_amount is not None, tx_timestamp]):
                            logging.warning("Skipping transaction for user '%s' due to missing transaction data in pickle: %s", uname, tx_pickle_data)
                            continue

                        if self.record_transaction_sqlite(uname, tx_type, int(tx_amount), tx_timestamp):
                            migrated_transactions_count += 1
                        else:
                            logging.warning("Failed to migrate a transaction for user '%s' by AccountService. Pickle Details: %s", uname, tx_pickle_data)
                # If create_user_sqlite returns False, it logs the reason (e.g., user exists)
            except Exception: # Catch any other unexpected error during a specific user's migration
                logging.exception("An unexpected error occurred during migration for user data: %s", user_pickle_data.get("uname", "Unknown user in pickle"))

        logging.info("Migration completed by AccountService. Migrated %d users and %d transactions.", migrated_users_count, migrated_transactions_count)
        return migrated_users_count, migrated_transactions_count
