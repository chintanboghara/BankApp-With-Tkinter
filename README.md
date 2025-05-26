# BankApp with Tkinter

This is a simple bank application built using Python's Tkinter library for the graphical user interface. The application enables users to register, log in, and perform basic banking operations such as depositing and withdrawing money. This improved version features an object-oriented design for enhanced structure, maintainability, and robust error handling.

## Features

- **User Registration:**  
  Create a new account by entering a username, full name, age, gender, initial balance, and password. Input validation ensures names contain only alphabetic characters and numeric fields are correctly formatted. During registration, a password strength meter provides real-time feedback to help users choose a more secure password.

- **User Login:**  
  Log in with a username and password, validated against stored user data.

- **Home Dashboard:**  
  Post-login, users can view their current balance and access options like viewing personal details, depositing, or withdrawing funds.

- **Deposit and Withdraw:**  
  Perform deposits or withdrawals with validations to prevent negative amounts or overdrafts. Balances update in real-time and are saved to storage.

- **Personal Information:**  
  Display stored details such as full name, age, gender, and balance.

- **Password Visibility Toggle:**  
  An eye icon next to the password field allows toggling between hidden and visible text for improved usability.

- **Transaction History:**  
  Users can view a history of their deposits and withdrawals, including the type of transaction, amount, and timestamp. This is accessible from the dashboard.

- **Improved User Experience:**  
  The application now utilizes Tkinter's themed widgets (`ttk`) for a more modern visual appearance and improved consistency. Critical actions like registration and logout now feature confirmation dialogs to prevent accidental operations and enhance usability.

## Installation

1. **Python 3.x:**  
   Ensure Python 3.x is installed. Tkinter comes bundled with standard Python distributions on most platforms. Download Python from the [official website](https://www.python.org/downloads/) if needed.

2. **Run the Application:**  
   Clone the repository and execute the main script:
   ```sh
   git clone https://github.com/chintanboghara/BankApp-With-Tkinter.git
   cd BankApp-With-Tkinter
   python BankAppWithTkinter.py
   ```
   Alternatively, run directly:
   ```sh
   python BankAppWithTkinter.py
   ```
   or
   ```sh
   py BankAppWithTkinter.py
   ```

3. **Login Window:**  
   The login window will launch, offering options to register or log in.

## Usage

### Registration
1. On the login screen, click **Sign Up**.
2. Provide required details: username, full name, age, gender, initial balance, and password.
3. Click **Register** to create your account.

### Login
1. Input your username and password on the login screen.
2. Click **Login** to enter the home dashboard.

### Home Dashboard
- **Personal Info:** View your personal details.
- **Deposit:** Add funds to your account.
- **Withdraw:** Remove funds from your account.
- **Transaction History:** View a log of your past deposits and withdrawals.
- **Logout:** Exit to the login screen.

### Password Visibility
- Click the eye icon beside the password field to toggle visibility.

## Code Structure

- **Main Window (`master`):**  
  The initial login window for user authentication or registration navigation.

- **Registration Screen (`rScreen`):**  
  A dedicated window for account creation with input validation and error handling.

- **Dashboard (`hScreen`):**  
  The central interface after login, offering access to banking operations.

- **Deposit & Withdraw Pages (`dScreen` & `wScreen`):**  
  Separate windows managing deposit and withdrawal with real-time balance updates.

- **Personal Info Page (`pScreen`):**  
  A window showing the logged-in user's information.

- **Transaction History Display:**  
  A window accessible from the dashboard (via the `show_transaction_history` method in `BankApp`) that displays a table of the user's past transactions (deposits and withdrawals) with timestamps, types, and amounts.

- **Object-Oriented Design:**  
  Encapsulated within a `BankApp` class, organizing UI, event handling, and data management for maintainability.

- **Unit Tests (`test_bank_app.py`):**  
  A suite of unit tests using Python's `unittest` module to verify the core logic of the application, including data manipulation, user authentication, transaction processing, and utility functions. These tests help ensure code reliability and facilitate safer modifications.

## Data Storage and Logging

### Database
User data is stored in an SQLite database file named `bankapp.db`. 
The `bankapp.db` file is located in a user-specific application data directory: `~/.BankApp/bankapp.db` (the `~/.BankApp` directory is created automatically if it doesn't exist). This ensures user data is stored in a standard, user-private location.

Previously, data was stored in `appData.bin` using Python's `pickle` module; the application includes a one-time migration utility for users with existing `appData.bin` files (this old file is looked for in the directory where the application is run).

Each user's data in the database includes:
- `username`: The user's chosen login name.
- `password_hash`: Securely hashed password. The application uses PBKDF2-SHA256 with a unique salt per user and a high iteration count (currently 260,000). The stored format is `pbkdf2_sha256$<iterations>$<salt_hex>$<key_hex>`. For users with accounts created with the older hashing method (plain SHA-256, typically found in migrated `appData.bin` files), their password hash will be automatically and seamlessly upgraded to the new PBKDF2-SHA256 format upon their next successful login. This significantly improves the security of stored passwords.
- `full_name`: The user's full name.
- `age`: The user's age.
- `gender`: The user's gender (stored as an integer).
- `balance`: The user's current account balance.
- `transactions`: Stored in a separate `transactions` table linked to the user, where each transaction record contains `type` ('deposit' or 'withdrawal'), `amount`, and `timestamp`.

### Log File
The application log (`bankapp.log`) is created in the same directory from which the application is run. 
- When running from source, this is typically the project's root directory.
- When using the packaged executable, this is the directory containing the executable file. 
The log file implements rotation: it rotates when it reaches approximately 1MB, and up to 3 backup log files are kept.

## Error Handling

- **Input Validation:**  
  Ensures numeric inputs (balance, age) are valid and full names are alphabetic only.

- **User Feedback:**  
  Message boxes provide alerts for errors like invalid inputs, insufficient funds, or duplicate usernames.

- **Robust File I/O:**  
  Helper functions manage file operations, gracefully handling missing or corrupted data.

## Running Tests

Unit tests are provided to verify the application's core logic. These tests ensure that data handling, user operations (registration, login, deposit, withdrawal), and utility functions work as expected.

To run the tests, navigate to the project's root directory in your terminal and execute:

```sh
python test_bank_app.py
```

The tests will run, and you'll see output indicating the status of each test (e.g., OK, FAILED, ERROR). This helps in identifying any regressions or issues after making changes to the codebase.

## Building from Source

To create a standalone executable from the source code, you can use PyInstaller.

1.  **Virtual Environment (Recommended):**  
    It is recommended to create and activate a virtual environment before installing dependencies and building:
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    ```

2.  **Install PyInstaller:**  
    Install PyInstaller using pip:
    ```bash
    pip install pyinstaller
    ```

3.  **Build the Application:**  
    To build the application, run one of the following commands from the project's root directory:

    *   Using direct command-line options:
        ```bash
        pyinstaller --name BankApp --onefile --windowed BankAppWithTkinter.py
        ```
    *   Using a spec file (if `BankApp.spec` is present and configured):
        ```bash
        pyinstaller BankApp.spec
        ```
    The distributable application (e.g., `BankApp.exe` on Windows or `BankApp` on macOS/Linux) will be found in the `dist` folder created by PyInstaller.
