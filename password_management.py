import tkinter as tk
from tkinter import font  as tkfont 
from PIL import ImageTk,Image
import os
import os.path as p
from tkinter import messagebox
import hashlib
import json
import tkinter.ttk as ttk
import time
import pyperclip
import base64
#from Crypto.Cipher import AES

class Storage :
    password = None
    username = None
    data=None
    def setData(self,d):
        Storage.data=d
    def setUsername(self,us):
        Storage.username = us
    def setPassword(self,pw):
        Storage.password = pw
    def getUsername(self):
        return Storage.username
    def getPassword(self):
        return Storage.password    
    def getData(self):
        return Storage.data
    @staticmethod
    def writeData(data):
        path=os.getcwd()+'/bin/'+Storage.username+'.json'
        f=open(path,'w',encoding='utf-8')
        data=json.dumps(data)
        f.write(data)
        f.close()
    @staticmethod
    def loadData():
        path = os.getcwd()+'/bin/'+Storage.username+'.json'
        fn = open(path,'r')
        f = fn.read()
        data = json.loads(f)
        return data

    
    @staticmethod
    def sortDict(data):
        l=list(data[1].items())
        l.sort()
        data[1]=dict(l)
        


class SampleApp(tk.Tk):

    def __init__(self, *args, **kwargs):
        self.createSafe()
        tk.Tk.__init__(self, *args, **kwargs)  

        self.title_font = tkfont.Font(family='Calibri', size=18, weight="bold")
        self.geometry("620x450+650+150")
        self.resizable(0,0)
        self.iconbitmap("icons/lock.ico")
        self.title("Paaword Manager")
   
        container = tk.Frame(self)
        container.pack(side="top", fill="both", expand=True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        self.frames = {}
        for F in (StartPage, Register, Login, ShowFrame):
            page_name = F.__name__
            frame = F(parent=container, controller=self)
            self.frames[page_name] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        self.show_frame("StartPage")



    def show_frame(self, page_name):
        '''Show a frame for the given page name'''
        frame = self.frames[page_name]
        frame.tkraise()
    
    def createSafe(self):
        self.path=os.getcwd()+'/bin/'
        if p.exists(self.path):
            pass
        else:
            os.mkdir(self.path)
            os.system("attrib +h self.path")  


class StartPage(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        label = tk.Label(self, text="Password Management System", font=controller.title_font, bg = "grey", fg = "white")
        
        bg_image = ImageTk.PhotoImage(Image.open("icons/bg1.gif"))
        xy = tk.Label (self,image = bg_image)
        xy.place(x=0,y=0,relwidth=1,relheight=1)
        xy.image=bg_image
        
        self.register=tk.Button(self)
        self.register.place(relx=0.163,rely=0.620,height=43,width=156)
        self.register.configure(text='Register',command=lambda : controller.show_frame("Register"))
        self.lab1=tk.Label(self)
        self.lab1.place(relx=0.176,rely=0.724,height=26,width=137)
        self.lab1.configure(text="New User? Register.")
        
        
        self.login=tk.Button(self)
        self.login.place(relx=0.580,rely=0.620,height=43,width=156)
        self.login.configure(text="Login",command =  lambda : controller.show_frame("Login"))
        self.lab2=tk.Label(self)
        self.lab2.place(relx=0.660,rely=0.724,width=76,height=26)
        self.lab2.configure(text='Login here')
        
        
        


class Register(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        label = tk.Label(self, text="Enter your username and password!", font=controller.title_font)
        label.pack(side="top", fill="x", pady=10)
        
        
        self.Label1 = tk.Label(self)
        self.Label1.place(relx=0.197, rely=0.156, height=26, width=83)
        self.Label1.configure(text='''Username :''')
        self.Label2 = tk.Label(self)
        self.Label2.place(relx=0.205, rely=0.247, height=26, width=78)
        self.Label2.configure(text='''Password :''')
        self.Label3 = tk.Label(self)
        self.Label3.place(relx=0.182, rely=0.336, height=26, width=92)
        self.Label3.configure(text='''Enter again :''')
        self.Button1 = tk.Button(self)
        self.Button1.place(relx=0.629, rely=0.511, height=43, width=116)
        self.Button1.configure(text='''Register''',command=self.createUser)
        self.Button2 = tk.Button(self)
        self.Button2.place(relx=0.629, rely=0.64, height=43, width=116)
        self.Button2.configure(text='''Back to Login''',command = lambda : controller.show_frame("Login"))
        
        self.Entry1 = tk.Entry(self)
        self.Entry1.place(relx=0.355, rely=0.16,height=24, relwidth=0.329)
        self.Entry1.configure(background="white")
        self.Entry1.configure(insertbackground="black")
        self.Entry2 = tk.Entry(self)
        self.Entry2.place(relx=0.355, rely=0.251,height=24, relwidth=0.329)
        self.Entry2.configure(background="white")
        self.Entry2.configure(insertbackground="black",show="*")
        self.Entry3 = tk.Entry(self)
        self.Entry3.place(relx=0.355, rely=0.344,height=24, relwidth=0.329)
        self.Entry3.configure(insertbackground="black",show="*")
    def createUser(self):
        username=self.Entry1.get()
        p1=self.Entry2.get()
        p2=self.Entry3.get()
        if(p1!=p2):
            messagebox.showerror('Error',"Password did not match")
        else:
            password=(p1).encode('utf-8')
            hashed_password=hashlib.sha512(password).hexdigest()
            l=[]
            l.append(hashed_password)
            l.append(dict())
            path=os.getcwd()+'/bin/'+username+'.json'
            if p.exists(path):
                messagebox.showinfo('exists','An account with similar user name already exists\nPlease go to login page')
                self.Entry1.delete(0,tk.END)
                self.Entry2.delete(0,tk.END)
                self.Entry3.delete(0,tk.END)
            else:
                f=open(path,'w')
                data=json.dumps(l,indent=4)
                f.write(data)
                f.close()
                messagebox.showinfo('Done','You have been succesfully registered!. Please go to login page')
                self.Entry1.delete(0,tk.END)
                self.Entry2.delete(0,tk.END)
                self.Entry3.delete(0,tk.END)            
  


class Login(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        
        label = tk.Label(self, text="Account Verification", font=controller.title_font)
        label.pack(side="top", fill="x", pady=10)
        
        
        self.Label2 = tk.Label(self)
        self.Label2.place(relx=0.21, rely=0.333, height=26, width=78)
        self.Label2.configure(text='''Password :''')
        self.Label3 = tk.Label(self)
        self.Label3.place(relx=0.194, rely=0.244, height=26, width=92)
        self.Label3.configure(text='''Username :''')
  
        self.Button1 = tk.Button(self)
        self.Button1.place(relx=0.602, rely=0.511, height=43, width=115)
        self.Button1.configure(text='''Login''',command=lambda : self.verify(controller))
        self.Button2 = tk.Button(self)
        self.Button2.place(relx=0.180,rely=0.511,height=43,width=115)
        self.Button2.configure(text="Back",command = lambda : controller.show_frame("StartPage"))
        
        #global Entry2,Entry3
        self.Entry2 = tk.Entry(self)
        self.Entry2.place(relx=0.355, rely=0.251,height=24, relwidth=0.329)
        self.Entry2.configure(background="white")

        self.Entry3 = tk.Entry(self)
        self.Entry3.place(relx=0.355, rely=0.344,height=24, relwidth=0.329)
        self.Entry3.configure(background="white",show="*")
    #function to verify the username and password and logs the user in.
    def verify(self,controller):
        us = self.Entry2.get()
        pw = self.Entry3.get()
        pw=pw.encode('utf-8')
        s = Storage()
        s.setUsername(us)
        s.setPassword(pw)
        path=os.getcwd()+'/bin/'+us+'.json'
        if p.exists(path):
            file=open(path,'r')
            f=file.read()
            file.close()
            data=json.loads(f)
            has_pw=hashlib.sha512(pw).hexdigest()
            if has_pw==data[0]:
                s.setData(data)
                controller.show_frame('ShowFrame')
            else:
                messagebox.showinfo('Error','Incorrect Password')
        else:
            messagebox.showinfo('MisMatch',"Incorrect username")
        self.Entry3.delete(0,tk.END)
        self.Entry2.delete(0,tk.END)


class ShowFrame(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        s=Storage()

        #Under development, want to add a heading here
        #That is, when showing the accounts it should display heading ---website--Username---(encryted password)

        self.data=s.getData()
        self.Button1_0 = tk.Button(self)
        self.Button1_0.place(relx=0.761, rely=0.100, height=33, width=131) 
        self.Button1_0.configure(pady="0")
        self.Button1_0.configure(text='''Load''',command=self.loadlbox)

        self.Button1_1 = tk.Button(self)
        self.Button1_1.place(relx=0.761, rely=0.420, height=33, width=131)
        self.Button1_1.configure(pady="0")
        self.Button1_1.configure(text='''Add''',command=self.addWindow) 
        
        self.Button1_2 = tk.Button(self)
        self.Button1_2.place(relx=0.761, rely=0.250, height=33, width=131)
        self.Button1_2.configure(pady="0")
        self.Button1_2.configure(text='''Delete''',command = self.deleteSite)
        self.Button1_3 = tk.Button(self)
        self.Button1_3.place(relx=0.761,rely=0.570,height=33,width=133)
        self.Button1_3.configure(text="Logout",command=lambda : controller.show_frame("StartPage"))
        self.Button1_4 = tk.Button(self)
        self.Button1_4.place(relx=0.751,rely=0.7100,height=33,width=150)
        self.Button1_4.configure(text='''Change Master password''',command= self.changeMasterPassword)
        self.open=False
        
        #to be modified.. 
        self.lbox = tk.Listbox(self,selectmode = "browse")
        self.lbox.place(relx=0.026,rely=0.036,relheight=0.923,relwidth=0.658)
        self.lbox.bind("<<ListboxSelect>>",self.popUpWindow)
        
        self.open=False
        self.list_sites = []

    def showWindow(self,site):
        """Window to display.....
        Still to add verification here before it can display

        """
        if not self.open:
            self.open = True

            
            self.swindow = tk.Toplevel(self)
            self.swindow.geometry("485x293+650+150")
            self.swindow.resizable(0,0)
            self.swindow.iconbitmap("icons/lock.ico")
            self.swindow.title("Your Credentials")
            self.swindow.protocol('WM_DELETE_WINDOW', self.closeShowWindow)

            self.e1 = tk.Entry(self.swindow)
            self.e1.place(relx=0.066,rely=0.14,height=24,relwidth=0.421)
            self.e2 = tk.Entry(self.swindow)
            self.e2.place(relx=0.066,rely=0.369,height=24,relwidth=0.421)
            self.e3 = tk.Entry(self.swindow)
            self.e3.place(relx=0.066,rely=0.597,height=24,relwidth=0.421)
         
            self.Label1 = tk.Label(self.swindow)
            self.Label1.place(relx=0.052, rely=0.048, height=26, width=66)
            self.Label1.configure(text='''Website''')
            self.Label2 = tk.Label(self.swindow)
            self.Label2.place(relx=0.054, rely=0.28, height=26, width=68)
            self.Label2.configure(text='''Username''')
            self.Label3 = tk.Label(self.swindow)
            self.Label3.place(relx=0.062, rely=0.509, height=26, width=64)
            self.Label3.configure(text='''Password''')

            self.Button1 = tk.Button(self.swindow)
            self.Button1.place(relx=0.573, rely=0.348, height=33, width=56)
            self.Button1.configure(text='''Copy''',command=self.copyUsername)
            self.Decrypt_Button = tk.Button(self.swindow)
            self.Decrypt_Button.place(relx=0.575, rely=0.577, height=33, width=56)
            self.Decrypt_Button.configure(text='''Decrypt''',command=self.decrypted)
            self.Button2 = tk.Button(self.swindow)
            self.Button2.place(relx=0.775, rely=0.577, height=33, width=56)
            self.Button2.configure(text='''Copy''',command=self.copyPassword)
            self.Button3 = tk.Button(self.swindow)
            self.Button3.place(relx=0.425, rely=0.802, height=43, width=130)
            self.Button3.configure(text='''Save Changes''',command = self.saveChanges)
            self.data = Storage.loadData()
            self.cred=[]
            self.cred = self.data[1][site]
            self.username = self.cred[0]
            self.password = self.cred[1]
            self.e1.insert(tk.END,site)
            self.e2.insert(tk.END,self.username)
            self.e3.insert(tk.END,self.password)
    #function to decrypt the password
    def decrypted(self):
        self.e3.delete(0,tk.END)
        self.dec_password = self.decrypt(self.e3.get())
        self.e3.insert(0,self.dec_password)
    #functions to copy username/password from the showwindow.
    def copyUsername(self):
        pyperclip.copy(self.e2.get())
        messagebox.showinfo("Message","Username has been copied to clipboard!")
    def copyPassword(self):
        pyperclip.copy(self.e3.get())
        messagebox.showinfo("Message","Password has been copied to clipboard!")
    #function to delete the selected site from the listbox.    
    def deleteSite(self):
        self.site = self.list_sites[self.lbox.curselection()[-1]]
        s = Storage()
        self.data = s.getData()
        del self.data[1][self.site]
        self.list_sites.remove(self.site)
        messagebox.showinfo("Deleted",self.site+" has been deleted successfully!")
        Storage.writeData(self.data)
        self.lbox.delete(0,tk.END)
        for k in self.list_sites:      # for loop to refresh the list box and load the remaining sites.
            self.lbox.insert(tk.END,k)
            
        
    def changeMasterPassword(self):
        if not self.open:
            sobj = Storage()
            user = sobj.getUsername()
            self.open=True
            self.cha=tk.Toplevel(self)
            self.cha.iconbitmap("icons/lock.ico")
            self.cha.title("Change the master password")
            self.cha.geometry("562x355+321+137")
            self.cha.resizable(False,False)
            self.cha.protocol('WM_DELETE_WINDOW', self.closeCha)
            b2 = tk.Button(self.cha)
            b2.place(relx=0.726, rely=0.691, height=36, width=106)
            b2.configure(text='''Cancel''', command= self.closeCha)
            b1 = tk.Button(self.cha)
            b1.place(relx=0.443, rely=0.691, height=36, width=106)
            b1.configure(text='''Change''',command=self.changeAndSave )
    
            self.entry2 = tk.Entry(self.cha)
            self.entry2.place(relx=0.39, rely=0.24, height=24, relwidth=0.356)
            self.entry2.configure(background="white")
            self.entry2.insert(0,user)
            self.entry3 = tk.Entry(self.cha)
            self.entry3.place(relx=0.391, rely=0.373, height=24, relwidth=0.356)
            self.entry3.configure(background="white", show="*")
            self.entry4 = tk.Entry(self.cha)
            self.entry4.place(relx=0.391, rely=0.512, height=24, relwidth=0.356)
            self.entry4.configure(background="white", show="*")

            la2 = tk.Label(self.cha)
            la2.place(relx=0.222, rely=0.235, height=26, width=92)
            la2.configure(text='''Username :''')
            la3 = tk.Label(self.cha)
            la3.place(relx=0.242, rely=0.371, height=26, width=75)
            la3.configure(text='''Password :''')
            la4 = tk.Label(self.cha)
            la4.place(relx=0.249, rely=0.507, height=26, width=70)
            la4.configure(text='''Re-Enter :''')
    

    #function to save the changes has been made.
    def saveChanges(self):
        self.website = self.e1.get()
        self.data = Storage.loadData()
        self.data[1][self.website] = [self.e2.get(),self.e3.get()]
        Storage.writeData(self.data)
        messagebox.showinfo("Success","Details have been updated!")
        self.closeShowWindow()
    #function to destroy the add password window.    
    def closeAddWindow(self):
        self.open=False
        self.win.destroy()
    #function to destroy the changeMasterPassword window.   
    def closeCha(self):
        self.open=False
        self.cha.destroy()
    #function to close showwindow.
    def closeShowWindow(self):
        self.open=False
        self.swindow.destroy()    
    #function to change master password.
    def changeAndSave(self):
        p= Storage()
        self.data=p.getData()
        self.user = p.getUsername()   
        if self.entry3.get()==self.entry4.get():
            if self.entry2.get()!=self.user:
                new_user = self.entry2.get()
                path1 = os.getcwd()+"/bin/"+self.user+'.json'
                path2 = os.getcwd()+"/bin/"+new_user+'.json'
                os.rename(path1,path2)
                p.setUsername(new_user)
            pas=self.entry3.get()
            pas=pas.encode('utf-8')
            pas=hashlib.sha512(pas).hexdigest()
            self.data[0]=pas 
            p.setData(self.data)
            Storage.writeData(self.data)
            messagebox.showinfo('Success',"Master password has been successfully changed!")
            self.closeCha()
        else:
            messagebox.showinfo('Mismatch','the password did not match')
    ################################
    """def encode(self, string, key="hyzeeck"):
        encoded_chars = []
        for i in range(len(string)):
            key_c = key[i % len(key)]
            # ord() gives the respective ascii value
            encoded_c = chr(ord(string[i]) + ord(key_c) % 256)
            encoded_chars.append(encoded_c)
        encoded_string = "".join(encoded_chars)
        string_bytes = encoded_string.encode("utf-8")   #This line is to be checked and modify
        return base64.urlsafe_b64encode(string_bytes)


    def decode(self, string, key="hyzeeck"):
        decoded_chars = []
        # utf-8 to avoid character mapping errors
        string = base64.urlsafe_b64decode(string.encode("utf-8"))
        for i in xrange(len(string)):
            key_c = key[i % len(key)]
            encoded_c = chr(abs(ord(string[i]) - ord(key_c) % 256))
            decoded_chars.append(encoded_c)
        decoded_string = "".join(decoded_chars)
        return decoded_string
    """
    def encrypt(self, data):
        str =""
        temp =0
        k=0
        for i in data:
            if i==" ":
                str+=i
                continue
            if ord(i)%2==0:
                k=1
            else:
                k=-1
            temp = (ord(i))%32+k
            if(temp>26):
                temp = temp-26
                str+= chr(((ord(i))/32)*32+temp)
            elif(temp<=0):
                temp = temp+26
                str += chr(((ord(i)) / 32) * 32 + temp)
            else:
                str+=chr(ord(i)+k)
        return str
    def decrypt(self, data):
        str=""
        temp=0
        k=0
        for i in data:
            if i==" ":
                str+=i
                continue
            if ord(i)%2==0:
                k=-1
            else:
                k=1
            temp = (ord(i))%32
            if(temp>=26):
                str+=chr(((ord(i))/32)*32-k)
            elif(temp<=1):
                str+=chr(((ord(i)/32)*32)+26)
            else:
                str+=chr(ord(i)-k)
        return str
    #function to add the new passwords.
    def saveAndClose(self):
        
        p= Storage()
        self.data = p.getData()
        website=self.en1.get()
        username=self.en2.get()
        password=self.en3.get()
        re_entry=self.en4.get()
        if len(password)+len(username)+len(website)>3 and password==re_entry :
            """encry_password=(password).encode('utf-8')
            hashed_password=hashlib.sha512(encry_password).hexdigest()
            l=[]
            l.append(hashed_password)
            l.append(dict())
            path=os.getcwd()+'/SAFE/'+username+'.json' """
            
            encoded_pass=self.encrypt(password)
            """
            line = json.dumps(item) + ' '
            self.file.write(line)
            cipher = AES.new(secret_key,AES.MODE_ECB) # never use ECB in strong systems obviously
            encoded_pass = base64.b64encode(password.encode("utf-8")) """
            if website not in self.data[1]:
                self.list_sites.append(website)
                #self.detail=[username,encoded_pass]
                self.data[1][website]=[username,encoded_pass]  #json.dumps(self.detail)
                Storage.writeData(self.data)
                self.closeAddWindow()
                self.lbox.delete(0,tk.END)
                for k in self.list_sites:
                    self.lbox.insert(tk.END,k)
            else:
                self.condition = messagebox.askyesnocancel("already exists","Do you want to rewrite an existing account?if not provide a unique identifier.")
                if self.condition :
                    self.data[1][website]=[username,encoded_pass]
                    Storage.writeData(self.data)
                    self.closeAddWindow()
                    self.lbox.delete(0,tk.END)
                    self.list_sites=list(set(self.list_sites))
                    for k in self.list_sites:
                        self.lbox.insert(tk.END,k)

            
        else:
            if password!=re_entry:
                messagebox.showinfo('Mismatch',"Passwords did not match")
            else:            
                messagebox.showinfo('unfilled entries','Please make sure you have Entered all the fields')

    def addWindow(self):

        if not self.open:
            self.open=True
            self.win = tk.Toplevel(self)
            self.win.title('Add the password')
            self.win.geometry("562x375+321+157")
            self.win.resizable(False,False)
            self.win.protocol('WM_DELETE_WINDOW',self.closeAddWindow)

            self.b2 = tk.Button(self.win)
            self.b2.place(relx=0.726,rely=0.691,height=36,width=106)
            self.b2.configure(text = '''Cancel''',command =   self.closeAddWindow)
            self.b1 = tk.Button(self.win)
            self.b1.place(relx=0.443,rely=0.691,height=36,width=106)
            self.b1.configure(text = '''Add''',command = self.saveAndClose)

            self.en1 = tk.Entry(self.win)
            self.en1.place(relx=0.391,rely=0.107,relwidth=0.356,height=24)
            self.en1.configure(background = "white")
            self.en2 = tk.Entry(self.win)
            self.en2.place(relx=0.39,rely=0.24,height=24,relwidth=0.356)
            self.en2.configure(background="white")
            self.en3 = tk.Entry(self.win)
            self.en3.place(relx=0.391,rely=0.373,height=24,relwidth=0.356) 
            self.en3.configure(background = "white",show="*")
            self.en4 = tk.Entry(self.win)
            self.en4.place(relx=0.391,rely=0.512,height=24,relwidth=0.356)  
            self.en4.configure(background = "white",show="*")

            self.la1 = tk.Label(self.win)
            self.la1.place(relx=0.253,rely=0.101,height=26,width=67) 
            self.la1.configure(text='''Website :''')
            self.la2 = tk.Label(self.win)
            self.la2.place(relx=0.222,rely=0.235,height=26,width=92)
            self.la2.configure(text='''Username :''')  
            self.la3 = tk.Label(self.win)
            self.la3.place(relx=0.242,rely=0.371,height=26,width=75)
            self.la3.configure(text='''Password :''')
            self.la4 = tk.Label(self.win)
            self.la4.place(relx=0.249,rely=0.507,height=26,width=70)    
            self.la4.configure(text='''Re-Enter :''')
    def loadlbox(self):
        self.data = Storage.loadData()
        #verify self.data[1] if it is empty then display a message box.  
        if(len(self.data[1])!=0):
            if(self.lbox.size()==0 or self.lbox.size()!=len(self.data[1])):   #the newly added passwords will be added to listbox.
                for k in self.data[1].keys():
                    if k not in self.list_sites:
                        self.list_sites.append(k)
                        self.lbox.insert(tk.END,k)
            else:
                pass 
           
        else:
            messagebox.showinfo("Add some passwords"," No Credentials of yours have been saved. ")
    def popUpWindow(self,event):
        l = event.widget # this line gives stores the widget which is related to the event in the local variable 
        if(len(l.curselection())!=0):
            index = int(l.curselection()[0])
            self.showWindow(l.get(index))

            
if __name__ == "__main__":
    app = SampleApp()
    app.mainloop()

    
