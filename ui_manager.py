import logging
import re
from tkinter import Tk, ttk, messagebox, StringVar, IntVar, Frame, Label, LEFT, CENTER, Toplevel
# Removed `from tkinter import *` to be more explicit
# from datetime import datetime # Not directly used by UIManager after refactoring, BankApp handles time
import constants as const # Import constants

# Helper function (can be outside the class or a static method if preferred)
# Moved here as it's primarily used by UI for input validation.
def is_number(s: str) -> bool: # This is also used by BankApp, consider moving to a shared util if it grows
    try:
        float(s)
        return True
    except ValueError:
        return False

def check_password_strength(password: str) -> dict: # This is UI specific for password feedback
    score = 0
    # Use constants for feedback text and levels
    feedback = {'level': const.PASS_LEVEL_NONE, 'text': '', 'color': const.COLOR_BLACK}

    if not password:
        return {'level': const.PASS_LEVEL_NONE, 'text': '', 'color': ''} # Default label color for empty

    # Criteria checks (could also be constants if granular control is needed)
    if len(password) >= 8: score += 1
    if re.search(r"[a-z]", password): score += 1
    if re.search(r"[A-Z]", password): score += 1
    if re.search(r"[0-9]", password): score += 1
    if re.search(r"[!@#$%^&*()_+\-=\[\]{};':"\|,.<>\/?~`]", password): score += 1 # Special chars
    if len(password) >= 12: score += 1 # Bonus for length

    # Map score to feedback using constants
    if score <= 1:
        feedback['level'] = const.PASS_LEVEL_TOO_WEAK
        feedback['text'] = const.PASS_STRENGTH_TOO_WEAK
        feedback['color'] = const.COLOR_RED
    elif score == 2:
        feedback['level'] = const.PASS_LEVEL_WEAK
        feedback['text'] = const.PASS_STRENGTH_WEAK
        feedback['color'] = const.COLOR_ORANGE_RED
    elif score >= 3 and score <= 4:
        feedback['level'] = const.PASS_LEVEL_MEDIUM
        feedback['text'] = const.PASS_STRENGTH_MEDIUM
        feedback['color'] = const.COLOR_GOLD
    elif score >= 5:
        feedback['level'] = const.PASS_LEVEL_STRONG
        feedback['text'] = const.PASS_STRENGTH_STRONG
        feedback['color'] = const.COLOR_FOREST_GREEN

    if not feedback['text']: # Safety net
        if score > 4: feedback['level'] = const.PASS_LEVEL_STRONG; feedback['text'] = const.PASS_STRENGTH_STRONG
        elif score > 2: feedback['level'] = const.PASS_LEVEL_MEDIUM; feedback['text'] = const.PASS_STRENGTH_MEDIUM
        elif score > 1: feedback['level'] = const.PASS_LEVEL_WEAK; feedback['text'] = const.PASS_STRENGTH_WEAK
        else: feedback['level'] = const.PASS_LEVEL_TOO_WEAK; feedback['text'] = const.PASS_STRENGTH_TOO_WEAK
        feedback['color'] = const.COLOR_BLACK

    return feedback

class UIManager:
    def __init__(self, master: Tk, app_callbacks: dict):
        """
        Initialize the UIManager.
        master: The main Tkinter window.
        app_callbacks: A dictionary of callback functions from the main app
                       (e.g., for login, register, deposit actions).
        """
        self.master = master
        self.app_callbacks = app_callbacks # For actions like do_login, save_user, etc.

        # UI state variables that were previously in BankApp
        self.username_var = StringVar()
        self.password_var = StringVar()
        self.entry_password = None # Will be set in create_login_screen

        # To manage open windows, if UIManager needs to track them directly
        self.open_windows = {}

        # Apply a ttk theme (similar to how it was in BankApp)
        style = ttk.Style()
        try:
            style.theme_use('clam') # A common theme
        except Exception as e:
            logging.warning(f"Failed to apply 'clam' theme, using default: {e}")
            available_themes = style.theme_names()
            if available_themes: style.theme_use(available_themes[0])
            else: logging.error("No ttk themes available.")

        style.configure(const.STYLE_ACCENT_BUTTON, foreground=const.COLOR_ACCENT_FG, background=const.COLOR_ACCENT_BG, font=const.FONT_BUTTON)
        style.map(const.STYLE_ACCENT_BUTTON,
            background=[('active', const.COLOR_ACCENT_ACTIVE_BG), ('pressed', const.COLOR_ACCENT_PRESSED_BG)],
            foreground=[('active', const.COLOR_ACCENT_FG)])
        style.configure(const.STYLE_LINK_BUTTON, foreground=const.COLOR_LINK_FG, relief="flat", borderwidth=0) # relief="flat" is tk specific, ttk uses style
        style.map(const.STYLE_LINK_BUTTON,
            foreground=[('active', const.COLOR_LINK_ACTIVE_FG), ('pressed', const.COLOR_LINK_PRESSED_FG)],
            underline=[('active', True)])

    def clear_master_frame(self):
        for widget in self.master.winfo_children():
            widget.destroy()

    def create_login_screen(self) -> None:
        self.clear_master_frame()
        self.master.title(const.LOGIN_WINDOW_TITLE)
        self.master.geometry(const.DEFAULT_WINDOW_GEOMETRY)
        self.master.configure(bg=const.COLOR_WHITE)

        Label(self.master, text=const.TEXT_LOGIN_TITLE, font=const.FONT_TITLE, bg=const.COLOR_WHITE).pack(pady=30)
        frame = Frame(self.master, bg=const.COLOR_WHITE)
        frame.pack()

        Label(frame, text=const.LABEL_USERNAME, font=const.FONT_SUBHEADER, bg=const.COLOR_WHITE).grid(row=0, column=0, pady=10, padx=10, sticky="e")
        ttk.Entry(frame, font=const.FONT_BODY, textvariable=self.username_var, justify="center").grid(row=0, column=1, pady=10, padx=10)

        Label(frame, text=const.LABEL_PASSWORD, font=const.FONT_SUBHEADER, bg=const.COLOR_WHITE).grid(row=1, column=0, pady=10, padx=10, sticky="e")
        self.entry_password = ttk.Entry(frame, font=const.FONT_BODY, textvariable=self.password_var, show="⭕", justify="center")
        self.entry_password.grid(row=1, column=1, pady=10, padx=10)

        ttk.Button(frame, text=const.BUTTON_TOGGLE_VISIBILITY, command=self.toggle_password_visibility).grid(row=1, column=2, padx=5)

        ttk.Button(self.master, text=const.BUTTON_LOGIN, command=self.app_callbacks.get("do_login"), style=const.STYLE_ACCENT_BUTTON).pack(pady=20)
        Label(self.master, text=const.TEXT_NO_ACCOUNT, font=const.FONT_LABEL, bg=const.COLOR_WHITE).pack()
        ttk.Button(self.master, text=const.BUTTON_SIGN_UP, command=self.app_callbacks.get("create_register_screen"), style=const.STYLE_LINK_BUTTON).pack(pady=10)

    def toggle_password_visibility(self) -> None:
        if self.entry_password and self.entry_password.cget("show") == "⭕":
            self.entry_password.config(show="")
        elif self.entry_password:
            self.entry_password.config(show="⭕")

    def create_register_screen(self) -> None:
        self.master.withdraw()
        register_window = Toplevel(self.master)
        self.open_windows['register'] = register_window
        register_window.title(const.REGISTER_WINDOW_TITLE)
        register_window.geometry(const.REGISTER_WINDOW_GEOMETRY)
        register_window.configure(bg=const.COLOR_WHITE)
        register_window.resizable(False, False)

        reg_vars = {
            "username": StringVar(), "full_name": StringVar(), "age": StringVar(),
            "gender": IntVar(), "balance": StringVar(), "password": StringVar()
        }

        def back_to_login_action():
            self.open_windows.pop('register', None)
            register_window.destroy()
            self.master.deiconify()
            if self.app_callbacks.get("show_login_screen_from_other"):
                 self.app_callbacks["show_login_screen_from_other"]()

        Label(register_window, text=const.TEXT_REGISTER_TITLE, font=const.FONT_TITLE, bg=const.COLOR_WHITE).pack(pady=20)
        form_frame = Frame(register_window, bg=const.COLOR_WHITE)
        form_frame.pack(pady=10)

        Label(form_frame, text=const.LABEL_USERNAME, font=const.FONT_SUBHEADER, bg=const.COLOR_WHITE).grid(row=0, column=0, pady=5, padx=10, sticky="e")
        ttk.Entry(form_frame, font=const.FONT_BODY, textvariable=reg_vars["username"], justify="center").grid(row=0, column=1, pady=5, padx=10)
        Label(form_frame, text=const.LABEL_FULL_NAME, font=const.FONT_SUBHEADER, bg=const.COLOR_WHITE).grid(row=1, column=0, pady=5, padx=10, sticky="e")
        ttk.Entry(form_frame, font=const.FONT_BODY, textvariable=reg_vars["full_name"], justify="center").grid(row=1, column=1, pady=5, padx=10)
        Label(form_frame, text=const.LABEL_AGE, font=const.FONT_SUBHEADER, bg=const.COLOR_WHITE).grid(row=2, column=0, pady=5, padx=10, sticky="e")
        ttk.Entry(form_frame, font=const.FONT_BODY, textvariable=reg_vars["age"], justify="center").grid(row=2, column=1, pady=5, padx=10)

        Label(form_frame, text=const.LABEL_GENDER, font=const.FONT_SUBHEADER, bg=const.COLOR_WHITE).grid(row=3, column=0, pady=5, padx=10, sticky="e")
        gender_frame = Frame(form_frame, bg=const.COLOR_WHITE)
        gender_frame.grid(row=3, column=1, pady=5, padx=10)
        ttk.Radiobutton(gender_frame, text=const.TEXT_MALE, variable=reg_vars["gender"], value=1).pack(side=LEFT, padx=5)
        ttk.Radiobutton(gender_frame, text=const.TEXT_FEMALE, variable=reg_vars["gender"], value=0).pack(side=LEFT, padx=5)

        Label(form_frame, text=const.LABEL_BALANCE, font=const.FONT_SUBHEADER, bg=const.COLOR_WHITE).grid(row=4, column=0, pady=5, padx=10, sticky="e")
        ttk.Entry(form_frame, font=const.FONT_BODY, textvariable=reg_vars["balance"], justify="center").grid(row=4, column=1, pady=5, padx=10)

        Label(form_frame, text=const.LABEL_PASSWORD, font=const.FONT_SUBHEADER, bg=const.COLOR_WHITE).grid(row=5, column=0, pady=5, padx=10, sticky="e")
        password_entry_field = ttk.Entry(form_frame, font=const.FONT_BODY, textvariable=reg_vars["password"], justify="center", show="*")
        password_entry_field.grid(row=5, column=1, pady=5, padx=10)

        password_strength_feedback_label = ttk.Label(form_frame, text="", font=const.FONT_FEEDBACK, foreground=const.COLOR_GREY)
        password_strength_feedback_label.grid(row=6, column=1, sticky="w", padx=10, pady=(0,5))

        def update_password_strength_feedback(*args): # Inner function, less reliance on constants for its own logic
            current_password = reg_vars["password"].get()
            feedback = check_password_strength(current_password) # check_password_strength now uses constants
            password_strength_feedback_label.config(text=feedback['text'], foreground=feedback['color'] if feedback['color'] else const.COLOR_GREY)
        reg_vars["password"].trace_add('write', update_password_strength_feedback)

        save_user_callback = self.app_callbacks.get("save_user")
        if save_user_callback:
            ttk.Button(register_window, text=const.BUTTON_REGISTER, command=lambda: save_user_callback(reg_vars, register_window, back_to_login_action), style=const.STYLE_ACCENT_BUTTON).pack(pady=20)

        Label(register_window, text=const.TEXT_HAVE_ACCOUNT, font=const.FONT_LABEL, bg=const.COLOR_WHITE).pack()
        ttk.Button(register_window, text=const.BUTTON_SIGN_IN, command=back_to_login_action, style=const.STYLE_LINK_BUTTON).pack(pady=10)

    def show_dashboard(self, current_user: dict, logout_callback, deposit_callback, withdraw_callback, personal_info_callback, transaction_history_callback) -> None:
        dashboard = Toplevel(self.master)
        if 'dashboard' in self.open_windows and self.open_windows['dashboard'].winfo_exists():
            self.open_windows['dashboard'].destroy()
        self.open_windows['dashboard'] = dashboard

        dashboard.title(const.DASHBOARD_WINDOW_TITLE)
        dashboard.geometry(const.DASHBOARD_GEOMETRY)
        dashboard.configure(bg=const.COLOR_WHITE)
        dashboard.resizable(False, False)

        # Use .get on current_user dict for safety, though 'uname' and 'balance' should exist
        Label(dashboard, text=f"Welcome {current_user.get('uname', 'User')}", font=const.FONT_HEADER, bg=const.COLOR_WHITE).pack(pady=20)
        balance_label = Label(dashboard, text=f"Balance: {current_user.get('balance', 0)}", font=const.FONT_LABEL, bg=const.COLOR_WHITE)
        balance_label.pack()

        def dashboard_logout_action():
            if messagebox.askyesno(const.TITLE_CONFIRM_LOGOUT, const.MSG_CONFIRM_LOGOUT, parent=dashboard):
                self.open_windows.pop('dashboard', None)
                dashboard.destroy()
                logout_callback() # Call the main app's logout logic

        ttk.Button(dashboard, text=const.BUTTON_DEPOSIT, command=lambda: deposit_callback(dashboard, balance_label)).pack(pady=5)
        ttk.Button(dashboard, text=const.BUTTON_WITHDRAW, command=lambda: withdraw_callback(dashboard, balance_label)).pack(pady=5)
        ttk.Button(dashboard, text=const.BUTTON_PERSONAL_INFO, command=lambda: personal_info_callback(dashboard)).pack(pady=5)
        ttk.Button(dashboard, text=const.BUTTON_TRANSACTION_HISTORY, command=lambda: transaction_history_callback(dashboard, balance_label)).pack(pady=5)
        ttk.Button(dashboard, text=const.BUTTON_LOGOUT, command=dashboard_logout_action).pack(pady=20)

    def show_deposit(self, parent: Toplevel, current_user: dict, balance_label_on_dash: Label, deposit_process_callback, logout_from_sub_window_callback) -> None:
        deposit_win = Toplevel(parent)
        deposit_win.title(const.DEPOSIT_WINDOW_TITLE)
        deposit_win.geometry(const.DASHBOARD_GEOMETRY) # Assuming same as dashboard for now
        deposit_win.configure(bg=const.COLOR_WHITE)
        deposit_win.resizable(False, False)
        self.open_windows['deposit'] = deposit_win # Track window

        amount_var = StringVar()

        Label(deposit_win, text=f"User: {current_user.get('uname', 'User')}", font=const.FONT_SMALL, bg=const.COLOR_WHITE).pack(anchor="w", padx=20, pady=10)
        bal_lbl_deposit = Label(deposit_win, text=f"Balance: {current_user.get('balance', 0)}", font=const.FONT_SMALL, bg=const.COLOR_WHITE)
        bal_lbl_deposit.pack(anchor="e", padx=20, pady=10)

        Label(deposit_win, text=const.LABEL_AMOUNT, font=const.FONT_LABEL, bg=const.COLOR_WHITE).pack(pady=10)
        ttk.Entry(deposit_win, font=const.FONT_LABEL, textvariable=amount_var, justify="center").pack(pady=10)

        ttk.Button(deposit_win, text=const.BUTTON_DEPOSIT,
                   command=lambda: deposit_process_callback(amount_var, bal_lbl_deposit, balance_label_on_dash, deposit_win),
                   style=const.STYLE_ACCENT_BUTTON).pack(pady=10)

        def deposit_back_action():
            self.open_windows.pop('deposit', None)
            deposit_win.destroy()

        ttk.Button(deposit_win, text=const.BUTTON_BACK, command=deposit_back_action).pack(side="right", padx=20, pady=20)

        def confirm_logout():
            if messagebox.askyesno(const.TITLE_CONFIRM_LOGOUT, const.MSG_CONFIRM_LOGOUT, parent=deposit_win):
                self.open_windows.pop('deposit', None)
                deposit_win.destroy()
                # parent is dashboard, destroy it too before calling main logout
                if parent and parent.winfo_exists(): parent.destroy()
                self.open_windows.pop('dashboard', None)
                logout_from_sub_window_callback()

        ttk.Button(deposit_win, text=const.BUTTON_LOGOUT, command=confirm_logout).pack(side="left", padx=20, pady=20)

    def show_withdraw(self, parent: Toplevel, current_user: dict, balance_label_on_dash: Label, withdraw_process_callback, logout_from_sub_window_callback) -> None:
        withdraw_win = Toplevel(parent)
        withdraw_win.title(const.WITHDRAW_WINDOW_TITLE)
        withdraw_win.geometry(const.DASHBOARD_GEOMETRY) # Assuming same as dashboard
        withdraw_win.configure(bg=const.COLOR_WHITE)
        withdraw_win.resizable(False, False)
        self.open_windows['withdraw'] = withdraw_win

        amount_var = StringVar()

        Label(withdraw_win, text=f"User: {current_user.get('uname', 'User')}", font=const.FONT_SMALL, bg=const.COLOR_WHITE).pack(anchor="w", padx=20, pady=10)
        bal_lbl_withdraw = Label(withdraw_win, text=f"Balance: {current_user.get('balance',0)}", font=const.FONT_SMALL, bg=const.COLOR_WHITE)
        bal_lbl_withdraw.pack(anchor="e", padx=20, pady=10)

        Label(withdraw_win, text=const.LABEL_AMOUNT, font=const.FONT_LABEL, bg=const.COLOR_WHITE).pack(pady=10)
        ttk.Entry(withdraw_win, font=const.FONT_LABEL, textvariable=amount_var, justify="center").pack(pady=10)

        ttk.Button(withdraw_win, text=const.BUTTON_WITHDRAW,
                   command=lambda: withdraw_process_callback(amount_var, bal_lbl_withdraw, balance_label_on_dash, withdraw_win),
                   style=const.STYLE_ACCENT_BUTTON).pack(pady=10)

        def withdraw_back_action():
            self.open_windows.pop('withdraw', None)
            withdraw_win.destroy()

        ttk.Button(withdraw_win, text=const.BUTTON_BACK, command=withdraw_back_action).pack(side="right", padx=20, pady=20)

        def confirm_logout():
            if messagebox.askyesno(const.TITLE_CONFIRM_LOGOUT, const.MSG_CONFIRM_LOGOUT, parent=withdraw_win):
                self.open_windows.pop('withdraw', None)
                withdraw_win.destroy()
                if parent and parent.winfo_exists(): parent.destroy()
                self.open_windows.pop('dashboard', None)
                logout_from_sub_window_callback()

        ttk.Button(withdraw_win, text=const.BUTTON_LOGOUT, command=confirm_logout).pack(side="left", padx=20, pady=20)

    def show_personal_info(self, parent: Toplevel, current_user: dict, logout_from_sub_window_callback) -> None:
        info_win = Toplevel(parent)
        info_win.title(const.PERSONAL_INFO_WINDOW_TITLE)
        info_win.geometry(const.DASHBOARD_GEOMETRY) # Assuming same as dashboard
        info_win.configure(bg=const.COLOR_WHITE)
        info_win.resizable(False, False)
        self.open_windows['personal_info'] = info_win

        Label(info_win, text=f"Personal Data of {current_user.get('uname','User')}", font=const.FONT_HEADER, bg=const.COLOR_WHITE).pack(pady=10)
        Label(info_win, text=f"Name: {current_user.get('name','N/A')}", font=const.FONT_BODY, bg=const.COLOR_WHITE).pack(pady=5)
        Label(info_win, text=f"Age: {current_user.get('age','N/A')}", font=const.FONT_BODY, bg=const.COLOR_WHITE).pack(pady=5)
        gender_str = const.TEXT_MALE if current_user.get('gender') else const.TEXT_FEMALE
        Label(info_win, text=f"Gender: {gender_str}", font=const.FONT_BODY, bg=const.COLOR_WHITE).pack(pady=5)
        Label(info_win, text=f"Balance: {current_user.get('balance','N/A')}", font=const.FONT_BODY, bg=const.COLOR_WHITE).pack(pady=5)

        def info_back_action():
            self.open_windows.pop('personal_info', None)
            info_win.destroy()

        ttk.Button(info_win, text=const.BUTTON_BACK, command=info_back_action).pack(side="right", padx=20, pady=20)

        def confirm_logout():
            if messagebox.askyesno(const.TITLE_CONFIRM_LOGOUT, const.MSG_CONFIRM_LOGOUT, parent=info_win):
                self.open_windows.pop('personal_info', None)
                info_win.destroy()
                if parent and parent.winfo_exists(): parent.destroy()
                self.open_windows.pop('dashboard', None)
                logout_from_sub_window_callback()

        ttk.Button(info_win, text=const.BUTTON_LOGOUT, command=confirm_logout).pack(side="left", padx=20, pady=20)

    def show_transaction_history(self, parent: Toplevel, current_user_uname: str, transactions_fetch_callback, logout_from_sub_window_callback) -> None:
        history_win = Toplevel(parent)
        history_win.title(const.TRANSACTION_HISTORY_WINDOW_TITLE)
        history_win.geometry(const.TRANSACTION_HISTORY_GEOMETRY)
        history_win.configure(bg=const.COLOR_WHITE)
        history_win.resizable(False, False)
        self.open_windows['history'] = history_win

        Label(history_win, text=f"Transaction History for {current_user_uname}", font=const.FONT_SUBHEADER, bg=const.COLOR_WHITE).pack(pady=10)

        # Column names for Treeview
        cols = ("Timestamp", "Type", "Amount") # These could be constants if they vary or are used elsewhere
        tree = ttk.Treeview(history_win, columns=cols, show="headings")
        for col_name in cols:
            tree.heading(col_name, text=col_name)
            tree.column(col_name, width=180, anchor=CENTER) # `width` could be a constant array/dict

        scrollbar = ttk.Scrollbar(history_win, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        tree.pack(expand=True, fill="both", padx=10, pady=10)

        transactions = transactions_fetch_callback() # Fetch fresh transactions via callback

        if not transactions:
            # Check if a label already exists from a previous call (if this window can be refreshed)
            # For now, assume it's created fresh each time.
            no_tx_label = Label(history_win, text=const.TEXT_NO_TRANSACTIONS, font=const.FONT_LABEL, bg=const.COLOR_WHITE)
            no_tx_label.pack(pady=20)
        else:
            for i in tree.get_children(): tree.delete(i) # Clear existing items
            for tx in transactions: # Populate with new transaction data
                # Ensure 'type' is a string before calling .title()
                tx_type_str = str(tx.get('type', 'N/A')).title()
                tree.insert("", "end", values=(tx.get('timestamp', 'N/A'), tx_type_str, tx.get('amount', 'N/A')))

        def history_back_action():
            self.open_windows.pop('history', None)
            history_win.destroy()

        ttk.Button(history_win, text=const.BUTTON_BACK, command=history_back_action).pack(side="right", padx=20, pady=20)

        def confirm_logout():
            if messagebox.askyesno(const.TITLE_CONFIRM_LOGOUT, const.MSG_CONFIRM_LOGOUT, parent=history_win):
                self.open_windows.pop('history', None)
                history_win.destroy()
                if parent and parent.winfo_exists(): parent.destroy()
                self.open_windows.pop('dashboard', None)
                logout_from_sub_window_callback()

        ttk.Button(history_win, text=const.BUTTON_LOGOUT, command=confirm_logout).pack(side="left", padx=20, pady=20)

    def close_all_secondary_windows(self):
        """Closes all windows tracked in self.open_windows."""
        logging.info("UIManager closing all tracked secondary windows.") # Log message can be constant
        for window_key, window_instance in list(self.open_windows.items()):
            try:
                if window_instance and window_instance.winfo_exists():
                    window_instance.destroy()
            except Exception as e:
                logging.error(f"Error destroying window {window_key} via UIManager: {e}")
        self.open_windows.clear()

    def show_message_box(self, title: str, message: str, msg_type: str = "info", parent=None):
        """
        Displays a message box.
        msg_type can be "info", "warning", "error", "askyesno", "askokcancel", "askretrycancel".
        parent: The parent window for the messagebox. Defaults to master if None.
        """
        target_parent = parent if parent else self.master
        if msg_type == "info":
            messagebox.showinfo(title, message, parent=target_parent)
        elif msg_type == "warning":
            messagebox.showwarning(title, message, parent=target_parent)
        elif msg_type == "error":
            messagebox.showerror(title, message, parent=target_parent)
        elif msg_type == "askyesno":
            return messagebox.askyesno(title, message, parent=target_parent) # Returns True/False
        elif msg_type == "askokcancel":
            return messagebox.askokcancel(title, message, parent=target_parent) # Returns True/False
        elif msg_type == "askretrycancel":
            return messagebox.askretrycancel(title, message, parent=target_parent) # Returns True/False
        else: # Default to info if type is unknown
            logging.warning(f"Unknown message box type: {msg_type}. Defaulting to info.")
            messagebox.showinfo(title, message, parent=target_parent)