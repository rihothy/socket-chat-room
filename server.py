import socketserver
import pickle
import time

import utils

users = None
history = None

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


if __name__ == '__main__':
    users = load_users()
    history = load_history()

    app = socketserver.ThreadingTCPServer(('0.0.0.0', 8888), Handler)
    app.serve_forever()