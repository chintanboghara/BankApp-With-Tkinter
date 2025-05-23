import os
import pickle
import re
import logging
import hashlib
from datetime import datetime
from tkinter import *
from tkinter import ttk, messagebox

# Configure logging to record events in a log file
logging.basicConfig(
    filename='bankapp.log',
    level=logging.INFO,
    format='%(asctime)s:%(levelname)s:%(message)s'
)

DATA_FILE = 'appData.bin'


def is_number(s: str) -> bool:
    """
    Check if the string can be interpreted as a number.
    
    Args:
        s (str): The string to check.
    
    Returns:
        bool: True if s is numeric, False otherwise.
    """
    try:
        float(s)
        return True
    except ValueError:
        return False


def hash_password(password: str) -> str:
    """
    Return the SHA-256 hash of the given password.
    
    Args:
        password (str): The password to hash.
    
    Returns:
        str: The hexadecimal digest of the password.
    """
    return hashlib.sha256(password.encode()).hexdigest()


def load_user_data() -> list:
    """
    Load user data from a binary file. Returns an empty list if the file does not exist or if an error occurs.
    
    Returns:
        list: A list of user dictionaries.
    """
    if not os.path.exists(DATA_FILE):
        logging.info("Data file does not exist. Returning empty list.")
        return []
    try:
        with open(DATA_FILE, 'rb') as f:
            data = pickle.load(f)
            # Ensure each user has a 'transactions' key
            for user in data:
                if 'transactions' not in user:
                    user['transactions'] = []
            logging.info("User data loaded successfully.")
            return data
    except Exception as e:
        logging.error("Error loading user data: %s", e)
        return []


def save_user_data(data: list) -> None:
    """
    Save user data list to a binary file.
    
    Args:
        data (list): The user data list to save.
    """
    try:
        with open(DATA_FILE, 'wb') as f:
            pickle.dump(data, f)
            logging.info("User data saved successfully.")
    except Exception as e:
        logging.error("Error saving user data: %s", e)


class BankApp:
    """
    A Tkinter-based bank application that allows user registration, login, deposit,
    withdrawal, and viewing of personal information.
    """

    def __init__(self, master: Tk) -> None:
        """
        Initialize the BankApp with a master Tk window.
        
        Args:
            master (Tk): The main Tkinter window.
        """
        self.master = master
        self.master.title("Login Page")
        self.master.geometry("500x450")
        self.master.configure(bg="white")
        self.master.resizable(False, False)

        # Current user info will be stored here after login.
        self.current_user = None

        # Variables for login screen.
        self.username_var = StringVar()
        self.password_var = StringVar()
        
        # Apply a ttk theme
        style = ttk.Style()
        try:
            # Attempt to use 'clam', a common modern theme
            style.theme_use('clam') 
        except Exception as e:
            logging.warning(f"Failed to apply 'clam' theme, using default: {e}")
            # Fallback to default if 'clam' is not available or fails
            # Ensure a theme is actually available before trying to use its name
            available_themes = style.theme_names()
            if available_themes:
                style.theme_use(available_themes[0])
            else:
                logging.error("No ttk themes available.")
        
        # Define custom styles for buttons for better contrast and visual hierarchy
        # Accent button for primary actions (e.g., Login, Register, Deposit, Withdraw)
        style.configure("Accent.TButton", foreground="white", background="#007bff", font=("Arial", 10, "bold"))
        style.map("Accent.TButton",
            background=[('active', '#0056b3'), ('pressed', '#004085')],
            foreground=[('active', 'white')])

        # Link button for secondary actions (e.g., Sign Up, Sign In links)
        style.configure("Link.TButton", foreground="#007bff", relief="flat", borderwidth=0)
        style.map("Link.TButton",
            foreground=[('active', '#0056b3'), ('pressed', '#004085')],
            underline=[('active', True)])
        
        # Standard buttons will use the default 'clam' TButton style which generally has good contrast.
        # If specific adjustments were needed for the eye toggle button, it could be:
        # style.configure("Eye.TButton", font=("Arial", 12), padding=2) 
        # For now, default TButton for the eye toggle.

        self.create_login_screen()

    def create_login_screen(self) -> None:
        """Create and display the login screen."""
        # Clear any existing widgets.
        for widget in self.master.winfo_children():
            widget.destroy()

        Label(self.master, text="LOGIN", font=("Arial", 40), bg="white").pack(pady=30)

        frame = Frame(self.master, bg="white")
        frame.pack()

        Label(frame, text="Username", font=("Arial", 20), bg="white").grid(
            row=0, column=0, pady=10, padx=10, sticky=E
        )
        entry_username = ttk.Entry(frame, font=("Arial", 18), textvariable=self.username_var, justify="center")
        entry_username.grid(row=0, column=1, pady=10, padx=10)

        Label(frame, text="Password", font=("Arial", 20), bg="white").grid(
            row=1, column=0, pady=10, padx=10, sticky=E
        )
        self.entry_password = ttk.Entry(
            frame, font=("Arial", 18), textvariable=self.password_var, show="⭕", justify="center"
        )
        self.entry_password.grid(row=1, column=1, pady=10, padx=10)

        # Toggle password visibility button.
        # Note: ttk.Button may not support bg/fg and border styling as directly as tk.Button.
        # Theme will handle styling. Font can be set via ttk.Style if needed globally.
        btn_toggle = ttk.Button(
            frame, text="👁",
            command=self.toggle_password_visibility
            # Using default TButton style from 'clam', which should be clear.
            # If specific styling like "Eye.TButton" was defined above, it would be used here.
        )
        btn_toggle.grid(row=1, column=2, padx=5)

        ttk.Button(self.master, text="Login", command=self.do_login, style="Accent.TButton").pack(pady=20)

        Label(self.master, text="Don't have an account?", font=("Arial", 15), bg="white").pack()
        ttk.Button(
            self.master, text="Sign Up",
            command=self.create_register_screen, style="Link.TButton"
        ).pack(pady=10)

    def toggle_password_visibility(self) -> None:
        """Toggle between hidden and visible password on the login screen."""
        if self.entry_password.cget("show") == "⭕":
            self.entry_password.config(show="")
        else:
            self.entry_password.config(show="⭕")

    def do_login(self) -> None:
        """Process login using provided credentials."""
        username = self.username_var.get().strip()
        password = self.password_var.get().strip()
        hashed_input = hash_password(password)

        users = load_user_data()
        for user in users:
            if user["uname"] == username and user["pass"] == hashed_input:
                self.current_user = user
                messagebox.showinfo("Success", "Login Successful")
                logging.info("User '%s' logged in successfully.", username)
                self.show_dashboard()
                return
        messagebox.showerror("Login Failed", "Incorrect Username or Password")
        logging.warning("Failed login attempt for username: %s", username)

    def create_register_screen(self) -> None:
        """Display the registration window."""
        self.master.withdraw()
        register_window = Toplevel(self.master)
        register_window.title("Sign Up")
        register_window.geometry("500x550")
        register_window.configure(bg="white")
        register_window.resizable(False, False)

        reg_vars = {
            "username": StringVar(),
            "full_name": StringVar(),
            "age": StringVar(),
            "gender": IntVar(),  # 1 for Male, 0 for Female.
            "balance": StringVar(),
            "password": StringVar()
        }

        def back_to_login() -> None:
            register_window.destroy()
            self.master.deiconify()

        def save_user() -> None:
            uname = reg_vars["username"].get().strip()
            full_name = reg_vars["full_name"].get().strip()
            age_str = reg_vars["age"].get().strip()
            gender = reg_vars["gender"].get()
            balance_str = reg_vars["balance"].get().strip()
            passwd = reg_vars["password"].get().strip()

            if not uname or not full_name or not age_str or not balance_str or not passwd:
                messagebox.showerror("Missing Data", "All fields are required.")
                return

            if not all(part.isalpha() for part in full_name.split()):
                messagebox.showerror("Invalid Name", "Please enter only alphabets in Full Name.")
                return
            if not is_number(balance_str):
                messagebox.showerror("Invalid Balance", "Balance must be numeric.")
                return
            if not is_number(age_str):
                messagebox.showerror("Invalid Age", "Age must be numeric.")
                return

            age = int(age_str)
            if age <= 0 or age >= 150:
                messagebox.showerror("Invalid Age", "Please provide a valid age.")
                return

            balance = int(float(balance_str))
            
            users = load_user_data() # Load existing users to check for duplicates
            for user_check in users: 
                if user_check["uname"] == uname:
                    messagebox.showerror("Invalid Username", "User already exists.")
                    return

            # Confirmation Dialog for Registration
            if messagebox.askyesno("Confirm Registration", "Are you sure you want to register with these details?"):
                new_user = {
                    "uname": uname,
                    "name": full_name,
                    "age": age,
                    "gender": gender,
                    "balance": balance,
                    "pass": hash_password(passwd),
                    "transactions": [] # Ensure new users have transactions list
                }
                users.append(new_user)
                save_user_data(users)
                messagebox.showinfo("Success", "User Registered Successfully")
                logging.info("New user registered: %s", uname)
                back_to_login()
            # If user clicks "No", they remain on the registration screen with data intact.

        Label(register_window, text="Sign Up", font=("Arial", 40), bg="white").pack(pady=20)
        form_frame = Frame(register_window, bg="white")
        form_frame.pack(pady=10)

        Label(form_frame, text="Username", font=("Arial", 20), bg="white").grid(row=0, column=0, pady=5, padx=10, sticky=E)
        ttk.Entry(form_frame, font=("Arial", 18), textvariable=reg_vars["username"], justify="center").grid(row=0, column=1, pady=5, padx=10)

        Label(form_frame, text="Full Name", font=("Arial", 20), bg="white").grid(row=1, column=0, pady=5, padx=10, sticky=E)
        ttk.Entry(form_frame, font=("Arial", 18), textvariable=reg_vars["full_name"], justify="center").grid(row=1, column=1, pady=5, padx=10)

        Label(form_frame, text="Age", font=("Arial", 20), bg="white").grid(row=2, column=0, pady=5, padx=10, sticky=E)
        ttk.Entry(form_frame, font=("Arial", 18), textvariable=reg_vars["age"], justify="center").grid(row=2, column=1, pady=5, padx=10)

        Label(form_frame, text="Gender", font=("Arial", 20), bg="white").grid(row=3, column=0, pady=5, padx=10, sticky=E)
        gender_frame = Frame(form_frame, bg="white") # Frame bg might be overridden by theme on children
        gender_frame.grid(row=3, column=1, pady=5, padx=10)
        # Font for ttk.Radiobutton can be set via style if needed
        ttk.Radiobutton(gender_frame, text="Male", variable=reg_vars["gender"], value=1).pack(side=LEFT, padx=5)
        ttk.Radiobutton(gender_frame, text="Female", variable=reg_vars["gender"], value=0).pack(side=LEFT, padx=5)

        Label(form_frame, text="Balance", font=("Arial", 20), bg="white").grid(row=4, column=0, pady=5, padx=10, sticky=E)
        ttk.Entry(form_frame, font=("Arial", 18), textvariable=reg_vars["balance"], justify="center").grid(row=4, column=1, pady=5, padx=10)

        Label(form_frame, text="Password", font=("Arial", 20), bg="white").grid(row=5, column=0, pady=5, padx=10, sticky=E)
        ttk.Entry(form_frame, font=("Arial", 18), textvariable=reg_vars["password"], justify="center", show="*").grid(row=5, column=1, pady=5, padx=10)

        ttk.Button(register_window, text="Register", command=save_user, style="Accent.TButton").pack(pady=20)
        Label(register_window, text="Already have an account?", font=("Arial", 15), bg="white").pack()
        ttk.Button(register_window, text="Sign In", command=back_to_login, style="Link.TButton").pack(pady=10)

    def show_dashboard(self) -> None:
        """Display the dashboard with options for deposit, withdrawal, and personal information."""
        dashboard = Toplevel(self.master)
        dashboard.title("Dashboard")
        dashboard.geometry("500x350")
        dashboard.configure(bg="white")
        dashboard.resizable(False, False)

        Label(dashboard, text=f"Welcome {self.current_user['uname']}", font=("Arial", 30), bg="white").pack(pady=20)
        balance_label = Label(dashboard, text=f"Balance: {self.current_user['balance']}", font=("Arial", 15), bg="white")
        balance_label.pack()

        def logout() -> None:
            if messagebox.askyesno("Confirm Logout", "Are you sure you want to logout?"):
                self.current_user = None
                dashboard.destroy()
                self.create_login_screen()
                self.master.deiconify()
        
        ttk.Button(dashboard, text="Deposit",
                   command=lambda: self.show_deposit(dashboard, balance_label)).pack(pady=5)
        ttk.Button(dashboard, text="Withdraw",
                   command=lambda: self.show_withdraw(dashboard, balance_label)).pack(pady=5)
        ttk.Button(dashboard, text="Personal Info",
                   command=lambda: self.show_personal_info(dashboard)).pack(pady=5)
        ttk.Button(dashboard, text="Transaction History",
                   command=lambda: self.show_transaction_history(dashboard, balance_label)).pack(pady=5)
        ttk.Button(dashboard, text="Logout", command=logout).pack(pady=20) # Already updated to call the wrapped logout

    def update_user_balance(self, new_balance: int) -> None:
        """
        Update the current user's balance and persist the change.
        
        Args:
            new_balance (int): The new balance value.
        """
        users = load_user_data()
        for user in users:
            if user["uname"] == self.current_user["uname"]:
                user["balance"] = new_balance
                self.current_user["balance"] = new_balance
                break
        save_user_data(users)
        logging.info("User '%s' balance updated to %d", self.current_user["uname"], new_balance)

    def show_deposit(self, parent: Toplevel, balance_label: Label) -> None:
        """Display the deposit window."""
        deposit_win = Toplevel(parent)
        deposit_win.title("Deposit")
        deposit_win.geometry("500x350")
        deposit_win.configure(bg="white")
        deposit_win.resizable(False, False)

        amount_var = StringVar()

        Label(deposit_win, text=f"User: {self.current_user['uname']}", font=("Arial", 12), bg="white").pack(anchor="w", padx=20, pady=10)
        bal_lbl = Label(deposit_win, text=f"Balance: {self.current_user['balance']}", font=("Arial", 12), bg="white")
        bal_lbl.pack(anchor="e", padx=20, pady=10)

        Label(deposit_win, text="Amount:", font=("Arial", 15), bg="white").pack(pady=10)
        ttk.Entry(deposit_win, font=("Arial", 15), textvariable=amount_var, justify="center").pack(pady=10)

        def deposit_process() -> None:
            amount = amount_var.get().strip()
            if not is_number(amount):
                messagebox.showerror("Invalid Amount", "Please provide only numeric data")
                return
            if int(amount) <= 0:
                messagebox.showerror("Invalid Amount", "Amount must be greater than zero")
                return
            
            transaction = {
                'type': 'deposit',
                'amount': int(amount),
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            self.current_user['transactions'].append(transaction)
            
            new_balance = int(self.current_user['balance']) + int(amount)
            self.update_user_balance(new_balance)
            messagebox.showinfo("Success", "Deposit Successful")
            bal_lbl.config(text=f"Balance: {new_balance}")
            balance_label.config(text=f"Balance: {new_balance}")

        ttk.Button(deposit_win, text="Deposit", command=deposit_process, style="Accent.TButton").pack(pady=10)
        ttk.Button(deposit_win, text="Back", command=deposit_win.destroy).pack(side="right", padx=20, pady=20)
        
        def confirm_logout_from_deposit():
            if messagebox.askyesno("Confirm Logout", "Are you sure you want to logout?"):
                deposit_win.destroy()
                parent.destroy() # This is the dashboard window
                self.create_login_screen()
                self.master.deiconify()
        
        ttk.Button(deposit_win, text="Logout", command=confirm_logout_from_deposit).pack(side="left", padx=20, pady=20)

    def show_withdraw(self, parent: Toplevel, balance_label: Label) -> None:
        """Display the withdrawal window."""
        withdraw_win = Toplevel(parent)
        withdraw_win.title("Withdraw")
        withdraw_win.geometry("500x350")
        withdraw_win.configure(bg="white")
        withdraw_win.resizable(False, False)

        amount_var = StringVar()

        Label(withdraw_win, text=f"User: {self.current_user['uname']}", font=("Arial", 12), bg="white").pack(anchor="w", padx=20, pady=10)
        bal_lbl = Label(withdraw_win, text=f"Balance: {self.current_user['balance']}", font=("Arial", 12), bg="white")
        bal_lbl.pack(anchor="e", padx=20, pady=10)

        Label(withdraw_win, text="Amount:", font=("Arial", 15), bg="white").pack(pady=10)
        ttk.Entry(withdraw_win, font=("Arial", 15), textvariable=amount_var, justify="center").pack(pady=10)

        def withdraw_process() -> None:
            amount = amount_var.get().strip()
            if not is_number(amount):
                messagebox.showerror("Invalid Amount", "Please provide only numeric data")
                return
            if int(amount) <= 0:
                messagebox.showerror("Invalid Amount", "Amount must be greater than zero")
                return
            if int(self.current_user['balance']) - int(amount) < 0:
                messagebox.showerror("Invalid Amount", "Insufficient funds")
                return

            transaction = {
                'type': 'withdrawal',
                'amount': int(amount),
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            self.current_user['transactions'].append(transaction)

            new_balance = int(self.current_user['balance']) - int(amount)
            self.update_user_balance(new_balance)
            messagebox.showinfo("Success", f"Withdraw successful of ${amount}")
            bal_lbl.config(text=f"Balance: {new_balance}")
            balance_label.config(text=f"Balance: {new_balance}")

        ttk.Button(withdraw_win, text="Withdraw", command=withdraw_process, style="Accent.TButton").pack(pady=10)
        ttk.Button(withdraw_win, text="Back", command=withdraw_win.destroy).pack(side="right", padx=20, pady=20)

        def confirm_logout_from_withdraw():
            if messagebox.askyesno("Confirm Logout", "Are you sure you want to logout?"):
                withdraw_win.destroy()
                parent.destroy() # This is the dashboard window
                self.create_login_screen()
                self.master.deiconify()

        ttk.Button(withdraw_win, text="Logout", command=confirm_logout_from_withdraw).pack(side="left", padx=20, pady=20)

    def show_personal_info(self, parent: Toplevel) -> None:
        """Display a window showing the personal information of the current user."""
        info_win = Toplevel(parent)
        info_win.title("Personal Information")
        info_win.geometry("500x350")
        info_win.configure(bg="white")
        info_win.resizable(False, False)

        Label(info_win, text=f"Personal Data of {self.current_user['uname']}", font=("Arial", 30), bg="white").pack(pady=10)
        Label(info_win, text=f"Name: {self.current_user['name']}", font=("Arial", 18), bg="white").pack(pady=5)
        Label(info_win, text=f"Age: {self.current_user['age']}", font=("Arial", 18), bg="white").pack(pady=5)
        gender_str = "Male" if self.current_user['gender'] else "Female"
        Label(info_win, text=f"Gender: {gender_str}", font=("Arial", 18), bg="white").pack(pady=5)
        Label(info_win, text=f"Balance: {self.current_user['balance']}", font=("Arial", 18), bg="white").pack(pady=5)

        def back_to_dashboard() -> None:
            info_win.destroy()
            parent.deiconify()

        def confirm_logout_from_personal_info():
            if messagebox.askyesno("Confirm Logout", "Are you sure you want to logout?"):
                info_win.destroy()
                parent.destroy() # This is the dashboard window
                self.create_login_screen()
                self.master.deiconify()
        
        ttk.Button(info_win, text="Back", command=back_to_dashboard).pack(side="right", padx=20, pady=20)
        ttk.Button(info_win, text="Logout", command=confirm_logout_from_personal_info).pack(side="left", padx=20, pady=20)

    def show_transaction_history(self, parent: Toplevel, balance_label: Label) -> None:
        """Display the transaction history window."""
        history_win = Toplevel(parent)
        history_win.title("Transaction History")
        history_win.geometry("600x400")
        history_win.configure(bg="white")
        history_win.resizable(False, False)

        Label(history_win, text=f"Transaction History for {self.current_user['uname']}", font=("Arial", 20), bg="white").pack(pady=10)

        cols = ("Timestamp", "Type", "Amount")
        tree = ttk.Treeview(history_win, columns=cols, show="headings")
        for col in cols:
            tree.heading(col, text=col)
            tree.column(col, width=180, anchor=CENTER)
        
        # Add a scrollbar
        scrollbar = ttk.Scrollbar(history_win, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        tree.pack(expand=True, fill="both", padx=10, pady=10)

        transactions = self.current_user.get('transactions', [])
        if not transactions:
            Label(history_win, text="No transactions yet.", font=("Arial", 15), bg="white").pack(pady=20)
        else:
            for tx in transactions:
                tree.insert("", "end", values=(tx['timestamp'], tx['type'].title(), tx['amount']))

        def confirm_logout_from_history():
            if messagebox.askyesno("Confirm Logout", "Are you sure you want to logout?"):
                history_win.destroy()
                parent.destroy() # This is the dashboard window
                self.create_login_screen()
                self.master.deiconify()

        ttk.Button(history_win, text="Back", command=history_win.destroy).pack(side="right", padx=20, pady=20)
        ttk.Button(history_win, text="Logout", command=confirm_logout_from_history).pack(side="left", padx=20, pady=20)


if __name__ == "__main__":
    root = Tk()
    # It's better to apply the theme once the root window exists,
    # so moving the style initialization here from BankApp.__init__ if it's better suited.
    # However, having it in BankApp.__init__ is also fine as root is passed to it.
    # For now, the change in BankApp.__init__ is kept.
    # If issues arise, this is an alternative spot:
    # style = ttk.Style(root)
    # style.theme_use('clam') # or another theme
    app = BankApp(root)
    root.mainloop()
