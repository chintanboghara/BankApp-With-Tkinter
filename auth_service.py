# -*- coding: utf-8 -*-
"""
Authentication Service for the Bank Application.

This module provides the AuthService class, which handles all user authentication
logic, including password hashing and verification, and management of login
attempt tracking to prevent brute-force attacks.
"""
import hashlib
import os
import logging
from datetime import datetime, timedelta
import sqlite3
import constants as const


class AuthService:
    """
    Manages user authentication, including password security and login attempt tracking.

    Attributes:
        db_path (str): The path to the SQLite database file.
    """

    def __init__(self, db_path: str):
        """
        Initializes the AuthService with the path to the database.

        Args:
            db_path (str): The path to the SQLite database.
        """
        self.db_path = db_path

    def hash_password_old_sha256(self, password: str) -> str:
        """
        Generates a direct SHA-256 hash of a password.
        This is an older method kept for migrating or verifying old password hashes.

        Args:
            password (str): The password to hash.

        Returns:
            str: The hexadecimal SHA-256 hash of the password.
        """
        return hashlib.sha256(password.encode('utf-8')).hexdigest()

    def hash_password(self, password: str) -> str:
        """
        Hashes a password using PBKDF2-SHA256 with a random salt.

        The generated hash string includes the algorithm, iterations, salt (hex),
        and the key (hex), formatted for easy storage and later verification.
        Format: "pbkdf2_sha256$<iterations>$<salt_hex>$<key_hex>"

        Args:
            password (str): The password to hash.

        Returns:
            str: The formatted string containing all information needed for verification.
        """
        salt = os.urandom(const.SALT_BYTES)  # Generate a cryptographically secure random salt
        # Derive the key using PBKDF2
        key = hashlib.pbkdf2_hmac(
            const.PBKDF2_ALGORITHM.split('_')[-1],  # e.g., 'sha256'
            password.encode('utf-8'),  # Password must be encoded to bytes
            salt,
            const.PBKDF2_ITERATIONS,
            dklen=const.DKLEN_BYTES  # Desired key length
        )
        # Return the full string including algorithm, iterations, salt, and key
        return f"{const.PBKDF2_ALGORITHM}${const.PBKDF2_ITERATIONS}${salt.hex()}${key.hex()}"

    def verify_password(self, password_attempt: str, full_hashed_password_string: str) -> bool:
        """
        Verifies a password attempt against a stored hashed password string.

        This method supports both the new PBKDF2-SHA256 format and the legacy
        direct SHA-256 hash format for backward compatibility.

        Args:
            password_attempt (str): The password attempt to verify.
            full_hashed_password_string (str): The stored hash string.
                This can be an old SHA-256 hash or the new PBKDF2 formatted string.

        Returns:
            bool: True if the password attempt matches the stored hash, False otherwise.
        """
        if not full_hashed_password_string:
            logging.warning("Verification attempt against an empty hash string.")
            return False

        # Check if it's the old direct SHA-256 hash (64 hex characters, no '$')
        if '$' not in full_hashed_password_string:
            if len(full_hashed_password_string) == 64:  # Standard length of SHA-256 hex digest
                try:
                    int(full_hashed_password_string, 16)  # Validate if it's a hex string
                    expected_hash_old = self.hash_password_old_sha256(password_attempt)
                    logging.info("Attempting password verification using old SHA-256 method.")
                    return hashlib.compare_digest(expected_hash_old, full_hashed_password_string)
                except ValueError:
                    # Not a valid hex string, so it's not a valid old hash
                    logging.warning("Hash string (no '$') is not a valid hex string. Old format verification failed.")
                    return False
            else:
                # Not 64 chars, so definitely not a valid old SHA-256 hash
                logging.warning(f"Malformed hash string: No '$' delimiter and not 64 chars. Got {len(full_hashed_password_string)} chars.")
                return False

        # Assuming new PBKDF2 format: "algorithm$iterations$salt$key"
        parts = full_hashed_password_string.split('$')
        if len(parts) != 4:
            logging.warning(f"Malformed PBKDF2 hash string: Expected 4 parts, got {len(parts)}. Hash starts with: {full_hashed_password_string[:30]}...")
            return False

        algorithm, iterations_str, salt_hex, stored_key_hex = parts

        if algorithm != const.PBKDF2_ALGORITHM:
            logging.warning(f"Unsupported hash algorithm: '{algorithm}'. Expected '{const.PBKDF2_ALGORITHM}'.")
            return False

        try:
            iterations = int(iterations_str)
            if iterations <= 0: # Iterations must be positive for security
                logging.warning(f"Invalid iteration count in hash: {iterations}. Must be positive.")
                return False
            salt_bytes = bytes.fromhex(salt_hex)
            stored_key_bytes = bytes.fromhex(stored_key_hex)
        except ValueError:
            # Handles errors from int() or bytes.fromhex() if parts are not valid
            logging.exception(f"Error converting parts of PBKDF2 hash. Hash starts with: {full_hashed_password_string[:30]}...")
            return False

        # Validate expected lengths after conversion (important sanity check)
        if len(salt_bytes) != const.SALT_BYTES:
            logging.warning(f"Decoded salt length is {len(salt_bytes)}, expected {const.SALT_BYTES}.")
            return False
        if len(stored_key_bytes) != const.DKLEN_BYTES:
            logging.warning(f"Decoded key length is {len(stored_key_bytes)}, expected {const.DKLEN_BYTES}.")
            return False

        # Calculate the key from the password attempt using the stored parameters
        new_key_bytes = hashlib.pbkdf2_hmac(
            const.PBKDF2_ALGORITHM.split('_')[-1],  # e.g., 'sha256'
            password_attempt.encode('utf-8'),
            salt_bytes,
            iterations,  # Use iterations from the hash string itself for flexibility
            dklen=const.DKLEN_BYTES
        )

        # Compare the derived keys using a time-constant comparison to prevent timing attacks
        is_correct = hashlib.compare_digest(new_key_bytes, stored_key_bytes)
        if is_correct:
            logging.info(f"Password verification successful ({const.PBKDF2_ALGORITHM}).")
        else:
            logging.info(f"Password verification failed ({const.PBKDF2_ALGORITHM}).")
        return is_correct

    def get_login_attempt_info(self, username: str) -> dict | None:
        """
        Retrieves login attempt information (failure count, lockout time) for a user.

        Args:
            username (str): The username to query.

        Returns:
            dict | None: A dictionary containing 'username', 'failure_count',
                         and 'lockout_until' (if set), or None if no record exists
                         or an error occurs.
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row # Access columns by name
                cursor = conn.cursor()
                cursor.execute(
                    f"SELECT {const.COLUMN_USERNAME}, failure_count, lockout_until FROM {const.TABLE_LOGIN_ATTEMPTS} WHERE {const.COLUMN_USERNAME} = ?",
                    (username,)
                )
                row = cursor.fetchone()
                if row:
                    logging.info(f"Login attempt info retrieved for '{username}'.")
                    return dict(row)
                else:
                    logging.info(f"No login attempt info found for '{username}'.")
                    return None
        except sqlite3.Error as e:
            logging.exception(f"SQLite error retrieving login attempt info for '{username}': {e}")
            return None

    def record_failed_login_attempt(self, username: str) -> None:
        """
        Records a failed login attempt for the specified username.

        If the number of failed attempts reaches MAX_FAILED_LOGIN_ATTEMPTS,
        the account is locked for LOCKOUT_DURATION_MINUTES.

        Args:
            username (str): The username for which the failed attempt is recorded.
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                current_attempt_info = self.get_login_attempt_info(username)

                failure_count = 0
                if current_attempt_info:
                    failure_count = current_attempt_info.get('failure_count', 0)
                failure_count += 1

                if failure_count >= const.MAX_FAILED_LOGIN_ATTEMPTS:
                    lockout_until_dt = datetime.now() + timedelta(minutes=const.LOCKOUT_DURATION_MINUTES)
                    lockout_until_str = lockout_until_dt.strftime('%Y-%m-%d %H:%M:%S')
                    # Lock account: update failure count and set lockout_until timestamp
                    cursor.execute(
                        f"""INSERT OR REPLACE INTO {const.TABLE_LOGIN_ATTEMPTS}
                           ({const.COLUMN_USERNAME}, failure_count, lockout_until) VALUES (?, ?, ?)""",
                        (username, failure_count, lockout_until_str)
                    )
                    logging.warning(f"Recorded failed login for '{username}'. Attempt {failure_count}. Account locked until {lockout_until_str}.")
                else:
                    # Increment failure count, ensure lockout_until is NULL (or not set)
                    cursor.execute(
                        f"""INSERT OR REPLACE INTO {const.TABLE_LOGIN_ATTEMPTS}
                           ({const.COLUMN_USERNAME}, failure_count, lockout_until) VALUES (?, ?, NULL)""",
                        (username, failure_count)
                    )
                    logging.info(f"Recorded failed login for '{username}'. Attempt {failure_count}. Not locked yet.")
                conn.commit()
        except sqlite3.Error as e:
            logging.exception(f"SQLite error recording failed login attempt for '{username}': {e}")

    def reset_login_attempts(self, username: str) -> None:
        """
        Resets the login attempt counter and clears any lockout for the user.
        Typically called upon a successful login.

        Args:
            username (str): The username for which to reset attempts.
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                # Update attempts to 0 and clear lockout time.
                # If user is not in table, this will do nothing, which is fine.
                cursor.execute(
                    f"""UPDATE {const.TABLE_LOGIN_ATTEMPTS}
                       SET failure_count = 0, lockout_until = NULL
                       WHERE {const.COLUMN_USERNAME} = ?""",
                    (username,)
                )
                conn.commit()
                if cursor.rowcount > 0:
                    logging.info(f"Login attempts reset for user '{username}'.")
                else:
                    # This can happen if the user had no prior failed attempts recorded.
                    logging.info(f"No login attempts to reset for user '{username}' (user might not have had failed attempts or does not exist in table).")
        except sqlite3.Error as e:
            logging.exception(f"SQLite error resetting login attempts for '{username}': {e}")
