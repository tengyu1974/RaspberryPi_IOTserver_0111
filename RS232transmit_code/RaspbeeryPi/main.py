import time
import os
import serial
import json
import yaml
import pprint
import hashlib
import threading as th


# {cmdline:, payload:, num:, hash:}
'''
# 建立 MD5 物件
m = hashlib.sha256()

# 要計算 MD5 雜湊值的資料
data = "G. T. Wang"

# 更新 MD5 雜湊值
m.update(data)

# 取得 MD5 雜湊值
h = m.hexdigest()
print(h)
cmdline
0 = resend command payload = miss num (option)
'''


def hash_file(filepath):
    m = hashlib.sha256()
    with open(filepath, 'rb') as f:
        m.update(f.read())
    h = m.hexdigest()
    return h


def hash_cmd(command):
    m = hashlib.sha256()
    m.update(command.encode())
    h = m.hexdigest()
    return h

def dir_check(dir):
    if not os.path.isdir(dir):
        os.mkdir(dir)
    else:
        pass
    return True

class transerver:
    def __init__(self, port, baudrate, retry_delay=20, timeout=None):
        self.port = port
        self.baud_rate = baudrate
        self.timeout = timeout
        self.retry_delay = retry_delay
        self.ser = serial.Serial(self.port, self.baud_rate, timeout=self.timeout)
        self.ser.flush()
        self.p = th.Thread(target=self.get_command, daemon=True)
        self.file_buff = b''
        self.num = 0
        self.rece_cmd = []
        self.trans_cmd = []
        self.read_flag = False
        self.read_start()
        self.write_flag = False
        self.download_path = config['File']['download_path']

    def trans_file(self, file_path):
        del self.file_buff
        with open(file_path, 'rb') as f:
            self.file_buff = f.read()
        cmd = {'cmdline': 'write_file', 'payload': self.file_buff.hex(), 'filename': file_path,
               'sha256': hash_file(file_path)}
        self.trans_handle(cmd)
        print(f'傳送成功: {file_path}')
        return True

    def get_command(self):
        try:
            while self.read_flag:
                while self.ser.in_waiting > 0:
                    st = time.time()
                    cmd = self.ser.readline().decode().replace('\n', '')
                    try:
                        if len(cmd) > 0:
                            print('reading cmd')
                            cmd = json.loads(cmd)
                        else:
                            continue
                    except:
                        print(f'Error packet {cmd}')
                        continue
                    if 'cmdline' in cmd.keys() and 'num' in cmd.keys():
                        print(f'Get Command : {cmd["cmdline"]}')
                        self.rece_cmd.append(cmd)
                        if cmd['cmd_hash'] == hash_cmd(str(cmd['cmdline']) + str(cmd['payload']) + str(cmd['num'])):
                            print('Command hash Conform')
                            if not cmd['cmdline'] == 'Success Receive':
                                re_cmd = {}
                                re_cmd['cmdline'] = 'Success Receive'
                                re_cmd['payload'] = hash_cmd(str(cmd['cmdline']) +
                                                             str(cmd['payload']) + str(cmd['num']))
                                re_cmd['num'] = self.num
                                re_cmd['cmd_hash'] = hash_cmd(str(re_cmd['cmdline']) +
                                                              str(re_cmd['payload']) + str(re_cmd['num']))
                                self.ser.write('\n'.encode())
                                self.ser.write(json.dumps(re_cmd).encode())
                                self.ser.write('\n'.encode())
                                self.num = self.num + 1
                            self.run_cmd(cmd)
                            #self.run_cmd(cmd)
                        else:
                            print(cmd)
                    else:
                        print(cmd)
                    print(f'用時{time.time() - st}')
        except:
            print(f'Error with Serial Status is {self.ser.is_open}')
        return f'read stop'

    def read_start(self):
        self.read_flag = True
        self.p = th.Thread(target=self.get_command, daemon=True)
        self.p.start()
        return True

    def read_stop(self):
        self.read_flag = False
        self.p.join()
        return True

    def trans_command(self, cmd):
        self.read_stop()
        if type(cmd) is dict:
            if 'cmdline' in cmd.keys() and 'payload' in cmd.keys():
                cmd['num'] = self.num
                cmd['cmd_hash'] = hash_cmd(str(cmd['cmdline']) + str(cmd['payload']) + str(cmd['num']))
                self.num = self.num + 1
                self.ser.write('\n'.encode())
                self.ser.write(json.dumps(cmd).encode())
                self.ser.write('\n'.encode())
                self.trans_cmd.append(cmd)
            self.read_start()
            return True, cmd
        else:
            self.read_start()
            return False, cmd

    def trans_handle(self, cmd):
        while not self.read_flag:
            time.sleep(0.1)
        count = 1
        handle = self.trans_command(cmd)
        while True:
            if count % self.retry_delay == 0:
                handle = self.trans_command(cmd)
            count = count + 1
            if handle[0]:
                if handle[1]['cmd_hash'] in [x["payload"] for x in self.rece_cmd if x["cmdline"] == 'Success Receive']:
                    print(f'trans success: {cmd["cmd_hash"]}')
                    print('Conform')
                    break
            else:
                print(f'trans fail: {cmd["cmd_hash"]}')
                print(f'Retry in 5s')
                time.sleep(5)
                count = 0
                handle = self.trans_command(cmd)
            time.sleep(1)
        return True

    def run_cmd(self, command):
        if command['cmdline'] == 'write_file':
            dir_check(self.download_path)
            if 'filename' in command.keys():
                print(f'Start Write File : {command["filename"]}')
                with open(os.path.join(self.download_path, command['filename']), 'wb') as f:
                    f.write(bytes.fromhex(command['payload']))
                if command['sha256'] == hash_file(os.path.join(self.download_path, command['filename'])):
                    return True, f'接收並驗證正確'
                else:
                    return False, f'sha256較驗錯誤'
            else:
                print(f'Start Write File : {command["sha256"]}')
                with open(os.path.join(self.download_path, str(command['sha256'])), 'wb') as f:
                    f.write(bytes.fromhex(command['payload']))
        elif command['cmdline'] == 'Success Receive':
            print(f'解析接收事件: {command["payload"] in [x["cmd_hash"] for x in self.trans_cmd]}')
        else:
            print(f'*********************{command}*********************')
        return True


if __name__ == '__main__':
    with open('config', 'r', encoding="utf-8") as f:
        config = yaml.full_load(f)
    finish_log = []
    if os.path.exists('history'):
        with open('history', 'r', encoding="utf-8") as f:
            finish_log = f.readlines()
            finish_log = [x.replace('\n', '') for x in finish_log]
    pprint.pprint(config)
    tr = transerver(config['Serial']['COM'], config['Serial']['baudrate'],
                    retry_delay=config['Serial']['Conform_timeout'])
    if config['Serial']['Mode'] == 1:
        print(f'Write Mode ON')
        trans_file_list = []
        for root, dirs, files in os.walk(".", topdown=False):
            for name in files:
                if root == '.':
                    for i in config['File']['file_type']:
                        if name.endswith(i):
                            print(f'搜尋到新檔案: {name}')
                            trans_file_list.append(name)
        count_new = 0
        count_old = 0
        print(finish_log)
        print(trans_file_list)
        with open('history', 'w', encoding="utf-8") as f:
            for i in trans_file_list:
                f.write(i)
                f.write('\n')
                if i not in finish_log:
                    tr.trans_file(i)
                    count_new = count_new + 1
                else:
                    count_old = count_old + 1
        print(f'任務完成, 共掃描\n{count_new}個新檔案\n{count_old}個舊檔案')
    else:
        print(f'couch potato')
        while True:
            time.sleep(60)


