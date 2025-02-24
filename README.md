## Overview

This is a simple bank application implemented using Python's Tkinter library for the graphical user interface. The application allows users to register, log in, and perform basic banking operations like depositing and withdrawing money. In this improved version, the code has been refactored into an object-oriented design for better structure, maintainability, and enhanced error handling.

## Features

- **User Registration:**  
  Create a new account by providing a username, full name, age, gender, initial balance, and password. Input validation ensures that names contain only alphabets and numeric fields are properly checked.
  
- **User Login:**  
  Log in using a username and password. Credentials are validated against the stored user data.
  
- **Home Dashboard:**  
  After logging in, users can view their current balance and navigate to various operations such as personal information, deposit, and withdraw.
  
- **Deposit and Withdraw:**  
  Deposit or withdraw money with validations to prevent negative amounts or overdrafts. The balance is updated in real time and persisted to storage.
  
- **Personal Information:**  
  View your stored personal details, including full name, age, gender, and balance.
  
- **Password Visibility Toggle:**  
  An eye icon is provided next to the password field to toggle between hidden and visible text, enhancing user experience.

## Installation

1. **Prerequisites:**  
   - Python 3.x

2. **Install Required Packages:**  
   The application uses `tkinter` and `pickle`, which are included in the Python standard library.

3. **Run the Application:**  
   Save the provided code into a file named `BankAppWithTkinter.py` and run it using the command:

   ```sh
   python BankAppWithTkinter.py
   ```

## Usage

### Registration
1. From the login screen, click on the **Sign Up** button.
2. Enter the required details: username, full name, age, gender, initial balance, and password.
3. Click **Register** to create your account.

### Login
1. Enter your username and password on the login screen.
2. Click **Login** to access the home dashboard.

### Home Dashboard
- **Personal Info:** View your personal details.
- **Deposit:** Add money to your account.
- **Withdraw:** Remove money from your account.
- **Logout:** Sign out and return to the login screen.

### Password Visibility
- Click the eye icon next to the password field to toggle between hiding and showing your password.

## Code Structure

- **Main Window (`master`):**  
  The initial login window where users can log in or navigate to registration.

- **Registration Screen (`rScreen`):**  
  A separate window for creating a new account with input validations and error handling.

- **Dashboard (`hScreen`):**  
  The main user interface post-login, which provides access to deposit, withdrawal, and personal information functions.

- **Deposit & Withdraw Pages (`dScreen` & `wScreen`):**  
  Separate windows that handle the deposit and withdrawal processes with real-time balance updates.

- **Personal Info Page (`pScreen`):**  
  A window displaying the logged-in user's details.

- **File I/O Helpers:**  
  The functions `load_user_data` and `save_user_data` manage reading from and writing to a binary file (`appData.bin`), encapsulating file operations with error handling.

- **Object-Oriented Design:**  
  The application is encapsulated within a `BankApp` class, which organizes UI functions, event handlers, and user data management for better maintainability.

## File Format

User data is stored in a binary file named `appData.bin` using the `pickle` module. Each user's data is stored as a dictionary in a list, with the following keys:

- **Username (`uname`)**
- **Password (`pass`)**
- **Gender (`gender`)**
- **Age (`age`)**
- **Balance (`balance`)**
- **Full Name (`name`)**

## Error Handling

- **Input Validation:**  
  The application validates numeric inputs for balance and age and ensures that full names contain only alphabetic characters.
  
- **User Feedback:**  
  Informative message boxes alert the user when an error occurs (e.g., invalid inputs, insufficient funds, or duplicate usernames).

- **Robust File I/O:**  
  File operations are managed with helper functions that ensure data integrity and handle missing or corrupted data gracefully.
