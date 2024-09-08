# Bank Application

## Overview

This is a simple bank application implemented using Python's Tkinter library for the graphical user interface. The application allows users to register, log in, and perform basic banking operations like depositing and withdrawing money.

## Features

- **User Registration:** Create a new user account with username, full name, age, gender, balance, and password.
- **User Login:** Log in to the application using a username and password.
- **Home Dashboard:** After logging in, users can view their balance and access options for personal information, depositing, or withdrawing money.
- **Deposit and Withdraw:** Users can deposit or withdraw money from their account.
- **Personal Information:** Users can view their personal details such as name, age, gender, and balance.

## Installation

1. **Prerequisites:** Python 3.x

2. **Install Required Packages:**
   The application uses `tkinter` and `pickle`, which are part of the Python standard library.

3. **Run the Application:**
   Save the provided code into a file named `BankAppWithTkinter.py` and execute it using Python:

   ```sh
   python BankAppWithTkinter.py
   ```

## Usage

### Registration:
1. Click on the "Sign Up" button on the login screen.
2. Enter the required details: username, full name, age, gender, initial balance, and password.
3. Click "Register" to create an account.

### Login:
1. Enter your username and password on the login screen.
2. Click "Login" to access the home dashboard.

### Home Dashboard:
- **Personal Info:** View your personal details.
- **Deposit:** Deposit money into your account.
- **Withdraw:** Withdraw money from your account.
- **Logout:** Log out and return to the login screen.

### Password Visibility:
- Click the eye icon next to the password field to toggle password visibility.

## Code Structure

- **Main Window (`master`):** The initial login window.
- **Registration Screen (`rScreen`):** A separate window for user registration.
- **Home Page (`hScreen`):** The dashboard for logged-in users.
- **Deposit Page (`dScreen`):** A window for depositing money.
- **Withdraw Page (`wScreen`):** A window for withdrawing money.
- **Personal Info Page (`pScreen`):** A window to view personal information.

## File Format

The user data is stored in a binary file named `appData.bin`. Each user's data is stored as a dictionary in a list, including:

- **Username (`uname`)**
- **Password (`pass`)**
- **Gender (`gender`)**
- **Age (`age`)**
- **Balance (`balance`)**
- **Full Name (`name`)**

## Error Handling

- Invalid input for age, balance, or name will prompt error messages.
- Password visibility toggle allows for a better user experience.