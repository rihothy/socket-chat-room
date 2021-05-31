# 1. 实验名称
## 基于python Tkinter和python socket的网络聊天室
# 2. 实验目的
### 1.了解并掌握python Tkinter模块的使用，并能熟练利用Tkinter模块快速搭建GUI应用。
### 2.理解并掌握TCP/IP网络传输的工作原理。
### 3.掌握python socket模块的使用，能用python socket模块快速实现数据的TCP、UDP传输。
### 4.了解基本的数据加密算法（如AES，MD5等），并能应用于本项目中。
### 5.掌握python多线程处理问题的方法。
# 3. 实验内容
## 基于python Tkinter和python socket实现一个网络聊天室，可进行世界聊天和一对一聊天。
### 1.精美的UI。本项目用python的Tkinter模块进行GUI开发。经过本人的不懈努力，最终绘制出了赏心悦目的界面。
### 2.能处理并发请求的服务端。服务端能处理并发请求，每当有客户端请求连接时，服务端都会开启一个线程进行处理，因此当有多个客户端同时请求服务时不会造成阻塞。
### 3.实现用户注册功能。用户输入账号和密码，点击注册，如果账号在后台中不存在，则进行注册，将账号和密码的MD5值以key-value的形式保存。
### 4.实现用户登录功能。用户输入账号和密码，点击登录，如果账号在后台存在，并且用户输入的密码的MD5值与后台一致，则登录成功。
### 5.世界聊天功能。任何已登录的用户都能在世界聊天窗口发送消息，且该消息能被其他所有用户看到。任何已登录的用户都能在世界聊天窗口看到其他用户在世界聊天窗口发送的消息。
### 6.一对一聊天功能。所有已登录的其他用户都显示在在线用户列表中，用户可以点击任意其他已登录用户与其进行一对一聊天。
### 7.文件发送功能。在一对一聊天功能中，用户不止能与其他用户发送接收文本，还能与其他用户发送接收文件。
### 8.保存历史聊天记录功能。无论是世界聊天还是一对一聊天，期间的所有聊天记录都会保存在后台中。用户一旦登录便会加载过往的聊天记录。
### 9.数据传输加密功能。本项目所有在网络上传输的数据都用AES算法进行加密。
# 4. 实验源代码及注解
### 1.加密解密函数
encrypt函数对数据进行加密，decrypt函数对数据进行解密。
```python
from Crypto.Cipher import AES
from Crypto import Random

key = b'fdj27pFJ992FkHQb'

def encrypt(data):

    code = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CFB, code)

return code + cipher.encrypt(data)


def decrypt(data):
    return AES.new(key, AES.MODE_CFB, data[:16]).decrypt(data[16:])
```
### 2.用socket发送、接收数据函数
发送数据前会在数据前部加上指明数据大小的一个二字节数。接收数据时先接收这个二字节数，获取将要接收的数据包的大小，然后接收这个大小的数据作为本次接收的数据包。
```python
import struct
import json

max_buff_size = 1024

def pack(data):
    return struct.pack('>H', len(data)) + data


def send(socket, data_dict):
    socket.send(pack(encrypt(json.dumps(data_dict).encode('utf-8'))))


def recv(socket):
    data = b''
    surplus = struct.unpack('>H', socket.recv(2))[0]
    socket.settimeout(5)

    while surplus:
        recv_data = socket.recv(max_buff_size if surplus > max_buff_size else surplus)
        data += recv_data
        surplus -= len(recv_data)

    socket.settimeout(None)

    return json.loads(decrypt(data))
```
### 3.用户管理相关函数
包含从文件中加载所有已注册用户的信息（账号和密码对应的MD5值）、注册用户、验证用户（看看密码的MD5值是否和文件中的值相同）、将所有已注册用户的信息保存到文件中。
```python
import pickle

users = None

def load_users():
    try:
        return pickle.load(open('users.dat', 'rb'))
    except:
        return {}


def register(usr, pwd):
    if usr not in users.keys():
        users[usr] = pwd
        save_users()
        return True
    else:
        return False


def validate(usr, pwd):
    if usr in users.keys() and users[usr] == pwd:
        return True

    return False


def save_users():
    pickle.dump(users, open('users.dat', 'wb'))
```
### 4.聊天记录管理相关函数
每条聊天记录为key-value形式，key为（sender，receiver），value为（sender，time，msg）
相关函数包含从文件中加载所有用户的所有聊天记录、把一条聊天记录存入内存中，返回某用户对某用户的聊天记录、将所有用户的所有聊天记录保存到文件中。
```python
import pickle
import time

history = None

def load_history():
    try:
        return pickle.load(open('history.dat', 'rb'))
    except:
        return {}


def get_key(u1, u2):
    return (u1, u2) if (u2, u1) not in history.keys() else (u2, u1)


def append_history(sender, receiver, msg):
    if receiver == '':
        key = ('','')
    else:
        key = get_key(sender, receiver)

    if key not in history.keys():
        history[key] = []

    history[key].append((sender, time.strftime('%m月%d日%H:%M', time.localtime(time.time())), msg))

    save_history()


def get_history(sender, receiver):
    if receiver == '':
        key = ('','')
    else:
        key = get_key(sender, receiver)

    return history[key] if key in history.keys() else []


def save_history():
    pickle.dump(history, open('history.dat', 'wb'))
```
### 5.服务端
服务端采用socketserver的BaseRequestHandler类，可自动处理并发请求，即每有一个客户端请求连接时，都会new一个BaseRequestHandler类，然后在一个线程中处理相关请求。
服务端能处理登录请求、注册请求、获取所有已登录用户的列表、获取连接中的用户与其他用户的聊天记录、将连接中的用户的消息发给其期望接收的用户、将连接中的用户的发送文件请求发给其期望接收的用户……
```python
import socketserver
import utils

class Handler(socketserver.BaseRequestHandler):
    clients = {}

    def setup(self):
        self.user = ''
        self.file_peer = ''
        self.authed = False


    def handle(self):
        while True:
            data = utils.recv(self.request)

            if not self.authed:
                self.user = data['user']

                if data['cmd'] == 'login':
                    if validate(data['user'], data['pwd']):
                        utils.send(self.request, {'response': 'ok'})
                        self.authed = True

                        for user in Handler.clients.keys():
                            utils.send(Handler.clients[user].request, {'type': 'peer_joined', 'peer': self.user})

                        Handler.clients[self.user] = self
                    else:
                        utils.send(self.request, {'response': 'fail', 'reason': '账号或密码错误！'})
                elif data['cmd'] == 'register':
                    if register(data['user'], data['pwd']):
                        utils.send(self.request, {'response': 'ok'})
                    else:
                        utils.send(self.request, {'response': 'fail', 'reason': '账号已存在！'})
            else:
                if data['cmd'] == 'get_users':
                    users = []

                    for user in Handler.clients.keys():
                        if user != self.user:
                            users.append(user)

                    utils.send(self.request, {'type': 'get_users', 'data': users})
                elif data['cmd'] == 'get_history':
                    utils.send(self.request, {'type': 'get_history', 'peer': data['peer'], 'data': get_history(self.user, data['peer'])})
                elif data['cmd'] == 'chat' and data['peer'] != '':
                    utils.send(Handler.clients[data['peer']].request, {'type': 'msg', 'peer': self.user, 'msg': data['msg']})
                    append_history(self.user, data['peer'], data['msg'])
                elif data['cmd'] == 'chat' and data['peer'] == '':
                    for user in Handler.clients.keys():
                        if user != self.user:
                            utils.send(Handler.clients[user].request, {'type': 'broadcast', 'peer': self.user, 'msg': data['msg']})
                            
                    append_history(self.user, '', data['msg'])
                elif data['cmd'] == 'file_request':
                    Handler.clients[data['peer']].file_peer = self.user
                    utils.send(Handler.clients[data['peer']].request, {'type': 'file_request', 'peer': self.user, 'filename': data['filename'], 'size': data['size'], 'md5': data['md5']})
                elif data['cmd'] == 'file_deny' and data['peer'] == self.file_peer:
                    self.file_peer = ''
                    utils.send(Handler.clients[data['peer']].request, {'type': 'file_deny', 'peer': self.user})
                elif data['cmd'] == 'file_accept' and data['peer'] == self.file_peer:
                    self.file_peer = ''
                    utils.send(Handler.clients[data['peer']].request, {'type': 'file_accept', 'ip': self.client_address[0]})
                elif data['cmd'] == 'close':
                    self.finish()


    def finish(self):
        if self.authed:
            self.authed = False

            if self.user in Handler.clients.keys():
                del Handler.clients[self.user]

            for user in Handler.clients.keys():
                utils.send(Handler.clients[user].request, {'type': 'peer_left', 'peer': self.user})
```
### 6.登录界面
基于tkinter模块搭建，含有账号输入框、密码输入框、登录按钮、注册按钮。
```python
import tkinter as tk

class Login_win:
    def show(self):
        self.win.mainloop()


    def destroy(self):
        self.win.destroy()


    def __init__(self):
        self.win = tk.Tk()
        self.user = tk.StringVar()
        self.pwd = tk.StringVar()
        self.win.geometry("320x240")
        self.win.title("登录")
        self.win.resizable(width=False, height=False)
        self.label1 = tk.Label(self.win)
        self.label1.place(relx=0.055, rely=0.1, height=31, width=89)
        self.label1.configure(text='账号')
        self.entry_user = tk.Entry(self.win)
        self.entry_user.place(relx=0.28, rely=0.11, height=26, relwidth=0.554)
        self.entry_user.configure(textvariable=self.user)
        self.label2 = tk.Label(self.win)
        self.label2.place(relx=0.055, rely=0.27, height=31, width=89)
        self.label2.configure(text='密码')
        self.entry_pwd = tk.Entry(self.win)
        self.entry_pwd.place(relx=0.28, rely=0.28, height=26, relwidth=0.554)
        self.entry_pwd.configure(show="*")
        self.entry_pwd.configure(textvariable=self.pwd)
        self.btn_login = tk.Button(self.win)
        self.btn_login.place(relx=0.13, rely=0.6, height=32, width=88)
        self.btn_login.configure(text='登录')
        self.btn_reg = tk.Button(self.win)
        self.btn_reg.place(relx=0.6, rely=0.6, height=32, width=88)
        self.btn_reg.configure(text='注册')
```
### 7.聊天窗口界面
基于tkinter模块搭建，含有其他已登录用户列表显示框、聊天记录显示框、发送消息输入框、发送消息按钮等。
```python
import tkinter as tk

class Main_win:
    closed_fun = None

    def show(self):
        self.win.mainloop()


    def destroy(self):
        try:
            self.closed_fun()
        except:
            pass

        self.win.destroy()


    def __init__(self):
        self.win = tk.Tk()
        self.win.protocol('WM_DELETE_WINDOW', self.destroy)
        self.win.geometry("480x320")
        self.win.title("聊天室")
        self.win.resizable(width=False,height=False)
        self.msg = tk.StringVar()
        self.name = tk.StringVar()
        self.user_list = tk.Listbox(self.win)
        self.user_list.place(relx=0.75, rely=0.15, relheight=0.72, relwidth=0.23)
        self.label1 = tk.Label(self.win)
        self.label1.place(relx=0.76, rely=0.075, height=21, width=101)
        self.label1.configure(text='在线用户列表')
        self.history = tk.Text(self.win)
        self.history.place(relx=0.02, rely=0.24, relheight=0.63, relwidth=0.696)
        self.history.configure(state='disabled')
        self.entry_msg = tk.Entry(self.win)
        self.entry_msg.place(relx=0.02, rely=0.9, height=24, relwidth=0.59)
        self.entry_msg.configure(textvariable=self.msg)
        self.btn_send = tk.Button(self.win)
        self.btn_send.place(relx=0.62, rely=0.89, height=28, width=45)
        self.btn_send.configure(text='发送')
        self.btn_file = tk.Button(self.win)
        self.btn_file.place(relx=0.752, rely=0.89, height=28, width=108)
        self.btn_file.configure(text='发送文件')
        self.btn_file.configure(state='disabled')
        self.label2 = tk.Label(self.win)
        self.label2.place(relx=0.24, rely=0.0, height=57, width=140)
        self.label2.configure(textvariable=self.name)
```
### 8.客户端相关函数
登录按钮点击事件：当登录按钮点击时向服务端请求登录，如果登录成功则关闭登录页面，开启聊天页面。
注册按钮点击事件：当注册按钮点击时向服务端请求注册，得到回应后显示回应的消息（注册成功或注册失败、账号已存在等消息）。
刷新所有已登录用户列表。当开启聊天页面或收到服务端发来的新用户登录/登出的消息时刷新用户列表。
将聊天记录加入聊天记录显示框。当用户刚登录时显示世界聊天聊天记录，当用户点击其他用户与其一对一聊天时显示与其的聊天记录。
当点击用户列表中的某用户时，显示与其一对一聊天的窗口。
接收服务端消息函数。该函数运行在一个独立的线程中，不断接收服务端发来的消息。
```python
import tkinter.filedialog
import tkinter.messagebox
import tkinter as tk
import threading
import hashlib
import socket
import time
import sys
import os

import utils

login_win = None
main_win = None
my_socket = None
user_name = ''
current_session = ''
users = {}
filename = ''
filename_short = ''
file_transfer_pending = False

server_ip = "127.0.0.1"
server_port = "8888"


def close_socket():
    utils.send(my_socket, {'cmd': 'close'})
    my_socket.shutdown(2)
    my_socket.close()


def on_btn_login_clicked():
    global my_socket, user_name, login_win, main_win
    my_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    my_socket.settimeout(5)
    if login_win.user.get() != '' and login_win.pwd != '':
        my_socket.connect((server_ip, int(server_port)))
        utils.send(my_socket, {'cmd': 'login', 'user': login_win.user.get(), 'pwd': hashlib.sha1(login_win.pwd.get().encode('utf-8')).hexdigest()})
        server_response = utils.recv(my_socket)
        if server_response['response'] == 'ok':
            user_name = login_win.user.get()
            login_win.destroy()
            main_win = Main_win()
            main_win.closed_fun = on_closed
            main_win.name.set('Hi!\n%s' % user_name)
            main_win.btn_file.configure(command=on_btn_file_clicked)
            main_win.btn_send.configure(command=on_btn_send_clicked)
            main_win.user_list.bind('<<ListboxSelect>>', on_session_select)
            utils.send(my_socket, {'cmd': 'get_users'})
            utils.send(my_socket, {'cmd': 'get_history', 'peer': ''})
            t = threading.Thread(target=recv_async, args=())
            t.setDaemon(True)
            t.start()
            main_win.show()
        elif server_response['response'] == 'fail':
            tkinter.messagebox.showerror('警告', '登录失败：' + server_response['reason'])
            close_socket()
    else:
        tkinter.messagebox.showerror('警告', '账号和密码不能为空！')


def on_btn_reg_clicked():
    global my_socket, login_win
    my_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    my_socket.settimeout(5)
    if login_win.user.get() != '' and login_win.pwd.get() != '':
        my_socket.connect((server_ip, int(server_port)))
        utils.send(my_socket, {'cmd': 'register', 'user': login_win.user.get(), 'pwd': hashlib.sha1(login_win.pwd.get().encode('utf-8')).hexdigest()})
        server_response = utils.recv(my_socket)
        if server_response['response'] == 'ok':
            tkinter.messagebox.showinfo('注意', '注册成功！')
        elif server_response['response'] == 'fail':
            tkinter.messagebox.showerror('警告', '注册失败：' + server_response['reason'])
    else:
        tkinter.messagebox.showerror('警告', '账号和密码不能为空！')
    close_socket()


def recv_async():
    global my_socket, users, main_win, current_session, file_transfer_pending, filename_short, filename
    while True:
        data = utils.recv(my_socket)
        if data['type'] == 'get_users':
            users = {}
            for user in [''] + data['data']:
                users[user] = False
            refresh_user_list()
        elif data['type'] == 'get_history':
            if data['peer'] == current_session:
                main_win.history['state'] = 'normal'
                main_win.history.delete('1.0', 'end')
                main_win.history['state'] = 'disabled'
                for entry in data['data']:
                    append_history(entry[0], entry[1], entry[2])
        elif data['type'] == 'peer_joined':
            users[data['peer']] = False
            refresh_user_list()
        elif data['type'] == 'peer_left':
            if data['peer'] in users.keys():
                del users[data['peer']]
            if data['peer'] == current_session:
                current_session = ''
                main_win.btn_file.configure(state='disabled')
                main_win.name.set('%s -> global' % user_name)
                users[''] = False
                utils.send(my_socket, {'cmd': 'get_history', 'peer': ''})
            refresh_user_list()
        elif data['type'] == 'msg':
            if data['peer'] == current_session:
                append_history(data['peer'], time.strftime('%m月%d日%H:%M', time.localtime(time.time())), data['msg'])
            else:
                users[data['peer']] = True
                refresh_user_list()
        elif data['type'] == 'broadcast':
            if current_session == '':
                append_history(data['peer'], time.strftime('%m月%d日%H:%M', time.localtime(time.time())), data['msg'])
            else:
                users[''] = True
                refresh_user_list()
        elif data['type'] == 'file_request':
            if tkinter.messagebox.askyesno('注意', '%s 想要发文件给你\文件名：%s\n大小: %s\n接收?' % (data['peer'], data['filename'], data['size'])):
                utils.send(my_socket, {'cmd': 'file_accept', 'peer': data['peer']})
                try:
                    total_bytes = 0
                    addr = ('0.0.0.0', 1031)
                    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    server.bind(addr)
                    server.listen(5)
                    client_socket, addr = server.accept()
                    starttime = time.time()
                    with open(data['filename'], "wb") as f:
                        while True:
                            fdata = client_socket.recv(1024)
                            total_bytes += len(fdata)
                            if not fdata:
                                break
                            f.write(fdata)
                    f.close()
                    client_socket.close()
                    server.close()
                    endtime = time.time()
                    received_md5 = get_file_md5(data['filename'])
                    if received_md5 == data['md5']:
                        tkinter.messagebox.showinfo('注意', '文件接收成功！')
                    main_win.history['state'] = 'normal'
                    main_win.history.insert('end', 'Received %s bytes from %s in %s seconds\n\n' % (
                        total_bytes, data['peer'], format(endtime - starttime, '.2f')), 'hint')
                    main_win.history.see('end')
                    main_win.history['state'] = 'disabled'
                except:
                    pass
            else:
                utils.send(my_socket, {'cmd': 'file_deny', 'peer': data['peer']})
        elif data['type'] == 'file_deny':
            main_win.btn_file.configure(text='发送文件')
            if current_session == '':
                main_win.btn_file.configure(state='disabled')
            else:
                main_win.btn_file.configure(state='normal')
            tkinter.messagebox.showinfo('警告', '对方拒绝接收！')
        elif data['type'] == 'file_accept':
            try:
                total_bytes = 0
                starttime = time.time()
                addr = (data['ip'], 1031)
                client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client.connect(addr)
                with open(filename, 'rb') as f:
                    while True:
                        fdata = f.read(1024)
                        if not fdata:
                            break
                        total_bytes += len(fdata)
                        client.send(fdata)
                f.close()
                client.close()
                endtime = time.time()
                main_win.history['state'] = 'normal'
                main_win.history.insert('end', 'Sent %s bytes in %s seconds\n\n' % (
                    total_bytes, format(endtime - starttime, '.2f')), 'hint')
                main_win.history.see('end')
                main_win.history['state'] = 'disabled'
            finally:
                filename = ''
                filename_short = ''
                file_transfer_pending = False
            main_win.btn_file.configure(text='发送文件')
            if current_session == '':
                main_win.btn_file.configure(state='disabled')
            else:
                main_win.btn_file.configure(state='normal')
            tkinter.messagebox.showinfo('注意', '文件发送成功！')

def refresh_user_list():
    main_win.user_list.delete(0, 'end')
    for user in users.keys():
        name = '世界聊天室' if user == '' else user
        if users[user]:
            name += ' (*)'
        main_win.user_list.insert('end', name)


def append_history(sender, time, msg):
    main_win.history['state'] = 'normal'
    main_win.history.insert('end', '%s - %s\n' % (sender, time))
    main_win.history.insert('end', msg + '\n\n', 'text')
    main_win.history.see('end')
    main_win.history['state'] = 'disabled'


def on_btn_file_clicked():
    global my_socket, main_win, filename, filename_short, file_transfer_pending
    try:
        filename = tkinter.filedialog.askopenfilename()
        if filename == '': return
        filename_short = ''
        if len(filename.split('/')) < len(filename.split('\\')):
            filename_short = filename.split('\\')[-1]
        else:
            filename_short = filename.split('/')[-1]
        size = os.path.getsize(filename)
        count = 0
        while not 1 < size < 1024 and count < 6:
            size /= 1024
            count += 1
        size = str(format(size, '.2f')) + ['B', 'KB', 'MB', 'GB', 'TB', 'PB'][count]
        md5_checksum = get_file_md5(filename)
        utils.send(my_socket, {'cmd': 'file_request', 'peer': current_session, 'filename': filename_short, 'size': size, 'md5': md5_checksum})
        main_win.btn_file.configure(text='等待中...')
        main_win.btn_file.configure(state='disabled')
        file_transfer_pending = True
    except:
        sys.exit(1)


def on_btn_send_clicked():
    global my_socket, user_name, current_session, main_win
    if main_win.msg.get() != '':
        utils.send(my_socket, {'cmd': 'chat', 'peer': current_session, 'msg': main_win.msg.get()})
        append_history(user_name, time.strftime('%m月%d日%H:%M', time.localtime(time.time())), main_win.msg.get())
        main_win.msg.set('')
    else:
        tkinter.messagebox.showinfo('警告', '消息不能为空！')


def on_session_select(event):
    global current_session, main_win, user_name, users, file_transfer_pending
    w = event.widget
    changed = False
    if len(w.curselection()) != 0:
        index = int(w.curselection()[0])
        if index != 0:
            if current_session != w.get(index).rstrip(' (*)'):
                changed = True
                current_session = w.get(index).rstrip(' (*)')
                if not file_transfer_pending:
                    main_win.btn_file.configure(state='normal')
                main_win.name.set('%s -> %s' % (user_name, current_session))
                users[current_session] = False
                refresh_user_list()
        elif index == 0:
            if current_session != '':
                changed = True
                current_session = ''
                main_win.btn_file.configure(state='disabled')
                main_win.name.set('%s -> global' % user_name)
                users[''] = False
                refresh_user_list()
        if changed:
            utils.send(my_socket, {'cmd': 'get_history', 'peer': current_session})


def on_closed():
    close_socket()


def get_file_md5(file_path):
    md5obj = hashlib.md5()
    maxbuf = 8192
    f = open(file_path, 'rb')
    while True:
        buf = f.read(maxbuf)
        if not buf:
            break
        md5obj.update(buf)
    f.close()
    hash = md5obj.hexdigest()
    return str(hash).upper()


if __name__ == '__main__':
    login_win = Login_win()
    login_win.btn_login.configure(command=on_btn_login_clicked)
    login_win.btn_reg.configure(command=on_btn_reg_clicked)
    login_win.show()
```
