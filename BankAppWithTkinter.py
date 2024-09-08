# main(master)-->register,login
#  register(screen)--->name,age,gender,balance,password(Entry)

# log(screen)--->name,password
# register(button)--->authenticate-name in alphabet,bal in digit
#                  --->create file of name with all information
# dashboard: Buttons(personalinfo , withdraw, deposit)

from tkinter import *
from time import sleep
from tkinter.ttk import Entry as entry, Button as button
import tkinter.messagebox as mb
from pickle import load, dump
from re import match,compile

def isNumber(s: str) -> bool:
            if s.isnumeric():
                return True 
            return True if match(compile(r'^[-+]?(?:\d+(\.\d*)?|\.\d+)(?:[eE][-+]?\d+)?$'), s) else False



master = Tk()
userPersonalData = Variable(master,value=None)
master.minsize(500,450)
master.maxsize(500,450)
master.title('Login Page')
master.configure(bg='white')

userName = StringVar()
nameData = StringVar()
ageData = StringVar()
genderData = IntVar()
balanceData = StringVar()
passw = StringVar()

master.geometry('500x450')

msg = Label(master, text='', font=('arial', 17), bg='white')
msg.place(anchor=CENTER, relx=.5, rely=.75)



def homePage():
    print(userPersonalData.get(),type((userPersonalData.get())))
    hScreen = Toplevel(master)
    master.withdraw()
    hScreen.minsize(500,350)
    hScreen.maxsize(500,350)
    hScreen.title('Home Page')
    hScreen.configure(bg='white')
    hBalLb = Label(hScreen, text='Balance: '+balanceData.get(), font=('arial', 15),
          bg='white')
    hBalLb.place(anchor=CENTER, relx=.83, rely=.2)
    def logOut():
        hScreen.destroy()
        userPersonalData.set(None)
        master.deiconify()

    def personalInfo():
      pScreen = Toplevel(hScreen)
      hScreen.withdraw()
      pScreen.minsize(500,350)
      pScreen.maxsize(500,350)
      pScreen.title('Home Page')
      pScreen.configure(bg='white')
      
      def logOut():
            pScreen.destroy()
            master.deiconify()
            nameData.set('')
            ageData.set('')
            balanceData.set('')
            genderData.set('')
      def backToHome():
            pScreen.destroy()
            hScreen.deiconify()
      
      Label(pScreen, text='Personal Data of '+userName.get(), font=('arial', 30),
            bg='white').place(anchor=CENTER, relx=.5, rely=.07)
      
      Label(pScreen, text='Name: '+nameData.get(), font=('arial', 18),
            bg='white').place(anchor=CENTER, relx=.5, rely=.2)
      
      Label(pScreen, text='Age: '+ageData.get(), font=('arial', 18),
            bg='white').place(anchor=CENTER, relx=.5, rely=.4)
      
      Label(pScreen, text='Gender: '+('Male' if genderData.get() else 'Female'), font=('arial', 18),
            bg='white').place(anchor=CENTER, relx=.5, rely=.6)
      
      Label(pScreen, text='Balance: '+balanceData.get(), font=('arial', 18),
            bg='white').place(anchor=CENTER, relx=.5, rely=.8)
      
      Button(pScreen, text='Back', font=('arial', 15), bg='black', fg='white',
            cursor="circle", command=backToHome).place(anchor=CENTER, relx=.65, rely=.9)
      
      Button(pScreen, text='Logout', font=('arial', 15), bg='black', fg='white',
            cursor="circle", command=logOut).place(anchor=CENTER, relx=.35, rely=.9)
      
      pScreen.mainloop()
    
    def DepositPage():
      dScreen = Toplevel(hScreen)
      hScreen.withdraw()
      dScreen.minsize(500,350)
      dScreen.maxsize(500,350)
      dScreen.title('Deposit Page')
      dScreen.configure(bg='white')
      
      amount = StringVar()
      Label(dScreen, text='User: '+userName.get(), font=('arial', 12),
            bg='white').place(anchor=CENTER, relx=.1, rely=.16)
      dBalLb = Label(dScreen, text='Balance: '+balanceData.get(), font=('arial', 12),
            bg='white')
      dBalLb.place(anchor=CENTER, relx=.8, rely=.16)
      
      def depositProcess():
            if not isNumber(amount.get()):
                  mb.askokcancel('Invalid Amount','Please provide only numeic data in Amount Field ')
            elif int(amount.get())<=0:
                  mb.askokcancel('Invalid Amount','Please provide amount larger than Zero(0)')
            else:
                  dataFile = open('appData.bin','rb+')
                  allUserData: list = load(dataFile)
                  balanceData.set(str(int(amount.get()) + int(balanceData.get())))
                  dataFile.seek(0)
                  for i in range(len(allUserData)):
                        if allUserData[i]['uname'] == userName.get():
                              allUserData[i]['balance'] = balanceData.get()
                              break
                  dump(file=dataFile,obj=allUserData)
                  mb.askyesno('Success','Deposit Successfull')
                  dBalLb.config(text='Balance: '+balanceData.get())
                  hBalLb.config(text='Balance: '+balanceData.get())
                  return
      def logOut():
            nameData.set('')
            ageData.set('')
            balanceData.set('')
            genderData.set('')
            dScreen.destroy()
            hScreen.destroy()
            master.deiconify()

      def backToHome():
            dScreen.destroy()
            hScreen.deiconify()

      
      Label(dScreen, text='DEPOSIT', font=('arial', 20),
            bg='white').place(anchor=CENTER, relx=.5, rely=.07)
      
     
      Label(dScreen, text='Amount: ', font=('arial', 15),
            bg='white').place(anchor=CENTER, relx=.2, rely=.3)
      entry(dScreen, font=('arial', 15), textvariable=amount).place(anchor=CENTER, relx=.65, rely=.3)
      
      
      Label(dScreen, text='', font=('arial', 18),
            bg='white').place(anchor=CENTER, relx=.5, rely=.4)
      
      Button(dScreen, text='DEPOSIT', font=('arial', 15), bg='black', fg='white',
            cursor="circle", command=depositProcess).place(anchor=CENTER, relx=.5, rely=.5)
      
      Button(dScreen, text='Back', font=('arial', 15), bg='black', fg='white',
            cursor="circle", command=backToHome).place(anchor=CENTER, relx=.65, rely=.9)
      
      Button(dScreen, text='Logout', font=('arial', 15), bg='black', fg='white',
            cursor="circle", command=logOut).place(anchor=CENTER, relx=.35, rely=.9)
      
      dScreen.mainloop()

    def WithdrawPage():
      wScreen = Toplevel(hScreen)
      hScreen.withdraw()
      wScreen.minsize(500,350)
      wScreen.maxsize(500,350)
      wScreen.title('Withdraw Page')
      wScreen.configure(bg='white')
      
      amount = StringVar()
      Label(wScreen, text='User: '+userName.get(), font=('arial', 12),
            bg='white').place(anchor=CENTER, relx=.1, rely=.16)
      wBalLb = Label(wScreen, text='Balance: '+balanceData.get(), font=('arial', 12),
            bg='white')
      wBalLb.place(anchor=CENTER, relx=.8, rely=.16)
      
      def withdrawProcess():
            if not isNumber(amount.get()):
                  mb.askokcancel('Invalid Amount','Please provide only numeic data in Amount Field ')
            elif int(amount.get())<=0:
                  mb.askokcancel('Invalid Amount','Please provide amount larger than Zero(0)')
            elif (int(balanceData.get()) - int(amount.get()))<0:
                  mb.askokcancel('Invalid Amount','Balance cannot be negative.\nPlease Provide feasible amount🙏.')
            else:
                  dataFile = open('appData.bin','rb+')
                  allUserData: list = load(dataFile)
                  balanceData.set(str(int(balanceData.get()) - int(amount.get())) )
                  dataFile.seek(0)
                  for i in range(len(allUserData)):
                        if allUserData[i]['uname'] == userName.get():
                              allUserData[i]['balance'] = balanceData.get()
                              break
                  dump(file=dataFile,obj=allUserData)
                  mb.askyesno('Success','Withdraw Successfull of 💲'+amount.get())
                  wBalLb.config(text='Balance: '+balanceData.get())
                  hBalLb.config(text='Balance: '+balanceData.get())
                  return
      def logOut():
            nameData.set('')
            ageData.set('')
            balanceData.set('')
            genderData.set('')
            wScreen.destroy()
            hScreen.destroy()
            master.deiconify()

      def backToHome():
            wScreen.destroy()
            hScreen.deiconify()

      
      Label(wScreen, text='WITHDRAW', font=('arial', 20),
            bg='white').place(anchor=CENTER, relx=.5, rely=.07)
      
     
      Label(wScreen, text='Amount: ', font=('arial', 15),
            bg='white').place(anchor=CENTER, relx=.2, rely=.3)
      entry(wScreen, font=('arial', 15), textvariable=amount).place(anchor=CENTER, relx=.65, rely=.3)
      
      
      Label(wScreen, text='', font=('arial', 18),
            bg='white').place(anchor=CENTER, relx=.5, rely=.4)
      
      Button(wScreen, text='Withdraw', font=('arial', 15), bg='black', fg='white',
            cursor="circle", command=withdrawProcess).place(anchor=CENTER, relx=.5, rely=.5)
      
      Button(wScreen, text='Back', font=('arial', 15), bg='black', fg='white',
            cursor="circle", command=backToHome).place(anchor=CENTER, relx=.65, rely=.9)
      
      Button(wScreen, text='Logout', font=('arial', 15), bg='black', fg='white',
            cursor="circle", command=logOut).place(anchor=CENTER, relx=.35, rely=.9)
      
      wScreen.mainloop()
    
    Label(hScreen, text='Welcome '+userName.get(), font=('arial', 30),
          bg='white').place(anchor=CENTER, relx=.5, rely=.07)
    
    Label(hScreen, text='Username: '+userName.get(), font=('arial', 15),
          bg='white').place(anchor=CENTER, relx=.2, rely=.2)
    
    
    
    Button(hScreen, text='Deposit', font=('arial', 15), bg='black', fg='white',
           cursor="circle", command=DepositPage).place(anchor=CENTER, relx=.5, rely=.3)
    
    Button(hScreen, text='Withdraw', font=('arial', 15), bg='black', fg='white',
           cursor="circle", command=WithdrawPage).place(anchor=CENTER, relx=.5, rely=.4)
    
    Button(hScreen, text='Personal Info', font=('arial', 15), bg='black', fg='white',
           cursor="circle", command=personalInfo).place(anchor=CENTER, relx=.5, rely=.5)
    
    Button(hScreen, text='Logout', font=('arial', 15), bg='black', fg='white',
           cursor="circle", command=logOut).place(anchor=CENTER, relx=.5, rely=.9)
    
    hScreen.mainloop()

def doLogin():
    print(userName.get(), passw.get())
    appFile = None
    listData = []
    try:
        appFile = open('appData.bin', 'rb')
        listData = load(appFile)
        for data in listData:
            if data['uname'] == userName.get() and data['pass'] == passw.get():
                 nameData.set(data['name'])
                 ageData.set(data['age'])
                 balanceData.set(data['balance'])
                 genderData.set(data['gender'])
                 
                 mb.askokcancel('Success', 'Login Successful')
                
                 homePage()
                 return
        mb.askokcancel('Failed','Incorrect Username or Password')
        return
    except:
        mb.askokcancel('Not Exist','No User Exist\nPlease Register First')
        return

def doRegister():
    # master.state(newstate='iconic')
    master.withdraw()
    rScreen = Toplevel(master)
    rScreen.minsize(500, 550)
    rScreen.configure(bg='white')

    userName = StringVar()
    name = StringVar()
    passw = StringVar()
    age = StringVar()
    gender = IntVar()
    balance = StringVar()

    def doStackWindow():
        rScreen.destroy()
        master.deiconify()

    def saveUserData():
        
        if (not [s.isalpha() for s in name.get().split()].count(True)==len(name.get().split())):
            mb.askokcancel('Invalid Name','Please enter only alphabets in Full Name')
            return
            
        if (not isNumber(balance.get())):
                mb.askokcancel('Invalid Balance','Balance can only be of Type Numeric')
                return
        
        if (not isNumber(age.get())):
            mb.askokcancel('Invalid Age','Age can only be of Type Numeric')
            return
        elif int(age.get())<=0 or int(age.get()) >= 150:
            mb.askokcancel('Invalid Age','Please Provide appropriate Age')
            return
        
        appFile = None
        listData = []
        try:
            appFile = open('appData.bin', 'rb+')
            listData = load(appFile)
            for data in listData:
                if data['uname'] == userName.get():
                    mb.askokcancel('Invalid Username', 'User Already Exist')
                    return
            appFile.seek(0)
        except:
            appFile = open('appData.bin', 'wb')
        listData.append({
            'uname': userName.get(),
            'pass': passw.get(),
            'gender': gender.get(),
            'age': age.get(),
            'balance': balance.get(),
            'name': name.get()
        })
        dump(file=appFile, obj=listData)
        
        
        msg.config(text='User Registered Succesfully', fg='blue')
        doStackWindow()
        return
    Label(rScreen, text='Sign Up', font=('arial', 40),
          bg='white').place(anchor=CENTER, relx=.5, rely=.07)

    Label(rScreen, text='Username', font=('arial', 20),
          bg='white').place(anchor=CENTER, relx=.2, rely=.2)
    entry(rScreen, font=('arial', 18), justify="center",
          textvariable=userName).place(anchor=CENTER, relx=.65, rely=.2)

    Label(rScreen, text='Full Name', font=('arial', 20),
          bg='white').place(anchor=CENTER, relx=.2, rely=.3)
    entry(rScreen, font=('arial', 18), justify="center",
          textvariable=name).place(anchor=CENTER, relx=.65, rely=.3)

    Label(rScreen, text='Age', font=('arial', 20), bg='white').place(
        anchor=CENTER, relx=.2, rely=.4)
    entry(rScreen, font=('arial', 18), justify="center",
          textvariable=age).place(anchor=CENTER, relx=.65, rely=.4)

    Label(rScreen, text='Gender', font=('arial', 20),
          bg='white').place(anchor=CENTER, relx=.2, rely=.5)
    Radiobutton(rScreen, text="Male", font=('arial', 20), bg='white',
                variable=gender, value=1).place(anchor=CENTER, relx=.48, rely=.5)
    Radiobutton(rScreen, text="Female", font=('arial', 20), bg='white',
                variable=gender, value=0).place(anchor=CENTER, relx=.77, rely=.5)

    Label(rScreen, text='Balance', font=('arial', 20),
          bg='white').place(anchor=CENTER, relx=.2, rely=.6)
    entry(rScreen, font=('arial', 18), justify="center",
          textvariable=balance).place(anchor=CENTER, relx=.65, rely=.6)

    Label(rScreen, text='Password', font=('arial', 20),
          bg='white').place(anchor=CENTER, relx=.2, rely=.7)
    entry(rScreen, font=('arial', 18), justify="center",
          textvariable=passw).place(anchor=CENTER, relx=.65, rely=.7)

    Button(rScreen, text='Register', font=('arial', 18), bg='black', fg='white',
           cursor="circle", command=saveUserData).place(anchor=CENTER, relx=.5, rely=.8)
    Label(rScreen, text='Already have an account then ', font=(
        'arial', 15), bg='white').place(anchor=CENTER, relx=.4, rely=.89)
    Button(rScreen, text='Sign In', font=('arial', 15), borderwidth=0, bg='white', fg='blue',
           cursor="circle", command=doStackWindow).place(anchor=CENTER, relx=.73, rely=.89)

    rScreen.mainloop()


Label(master, text='LOGIN', font=('arial', 40),
      bg='white').place(anchor=CENTER, relx=.5, rely=.12)


Label(master, text='Username', font=('arial', 20),
      bg='white').place(anchor=CENTER, relx=.2, rely=.3)
entry(master, font=('arial', 18), justify="center",
      textvariable=userName).place(anchor=CENTER, relx=.65, rely=.3)

Label(master, text='Password', font=('arial', 20),
      bg='white').place(anchor=CENTER, relx=.2, rely=.4)
passEntry = entry(master, font=('arial', 18), justify="center", textvariable=passw,
      show="⭕")
passEntry.place(anchor=CENTER, relx=.65, rely=.4)

def toggle_password_visibility():
    if passEntry.cget("show") == "⭕":
        passEntry.config(show="")
        passEye.config(fg='red')
    else:
        passEye.config(fg='white')
        passEntry.config(show="⭕")
passEye = Button(master,text='👁',font=('arial',14),bg='black',fg='white',command=toggle_password_visibility,border=0,borderwidth=0)
passEye.place(anchor = CENTER, relx = .88, rely = .4)

Button(master, text='Login', font=('arial', 18), fg='white', bg='black',
       cursor="circle", command=doLogin).place(anchor=CENTER, relx=.5, rely=.55)
Label(master, text="Don't have an account then", font=('arial', 15),
      bg='white').place(anchor=CENTER, relx=.4, rely=.66)
Button(master, text='Sign Up', font=('arial', 15), fg='blue', borderwidth=0, bg='white',
       cursor="circle", command=doRegister).place(anchor=CENTER, relx=.72, rely=.66)
master.mainloop()