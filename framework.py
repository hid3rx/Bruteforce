# coding=utf-8
#
# ============================================================================
#   framework.py — 爆破框架核心（一般不需要修改）
#
#   本文件包含：默认配置、日志输出、字典加载、线程池调度、进度汇报
#   如需针对具体网站开发检测脚本，请修改 target.py
# ============================================================================
#

import os, time, threading, traceback
from concurrent import futures
from curl_cffi.requests.exceptions import ConnectionError, Timeout
from datetime import datetime

#
# =================== [ 默认配置 ] ===================
#

configs = \
{
    "account_list": {
        "username": [],
        "password": []
    },

    "account_file": {
        "username": r"",
        "password": r""
    },

    "mode": "clusterbomb",

    "timeout": 10,

    "threads": 10,

    "delay": 1,

    "logfile": {
        "found": "found.txt",
        "exception": "exception.txt",
    },

    "use_proxy": False,

    "proxies": {
        "http": "http://127.0.0.1:8080",
        "https": "http://127.0.0.1:8080"
    },

    "headers": {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/114.0",
        "Connection": "close",
    },

    "cookies": {}
}

#
# =================== [ 日志输出 ] ===================
#

message_output_locks = {
    "found": threading.Lock(),
    "exception": threading.Lock()
}

def info_message(message: str):
    with message_output_locks["found"]:
        print(message)
        with open(configs["logfile"]["found"], "a", encoding="utf-8") as fout:
            fout.write(message + "\n")

def exception_message(message: str):
    with message_output_locks["exception"]:
        print(message)
        with open(configs["logfile"]["exception"], "a", encoding="utf-8") as fout:
            fout.write(message + "\n")

#
# =================== [ 多线程信号控制 ] ===================
#

concurrent_control_signals = \
{
    "thread_pool_stop_signal": threading.Event(),
    "report_thread_stop_signal": threading.Event(),
    "total_login_count": 0,
    "login_finished_count": 0,
    "login_finished_count_lock": threading.Lock(),
    "login_exception_count": 0,
    "login_exception_count_lock": threading.Lock()
}

#
# =================== [ 工具函数 ] ===================
#

def strfdelta(delta, fmt):
    d = dict()
    d["days"] = delta.days
    d["hours"], rem = divmod(delta.seconds, 3600)
    d["minutes"], d["seconds"] = divmod(rem, 60)
    return fmt.format(**d)

#
# =================== [ 字典加载 ] ===================
#

def load_dictionaries():
    usernames = configs["account_list"]["username"].copy()
    if configs["account_file"]["username"]:
        try:
            with open(configs["account_file"]["username"], "r", encoding="utf-8") as fin:
                for line in fin:
                    line = line.strip()
                    if not line:
                        continue
                    usernames.append(line)
        except Exception as e:
            print(f'[x] Cannot open \'{configs["account_file"]["username"]}\' username file {e}')
            os._exit(0)

    passwords = configs["account_list"]["password"].copy()
    if configs["account_file"]["password"]:
        try:
            with open(configs["account_file"]["password"], "r", encoding="utf-8") as fin:
                for line in fin:
                    line = line.strip()
                    if not line:
                        continue
                    passwords.append(line)
        except Exception as e:
            print(f'[x] Cannot open \'{configs["account_file"]["password"]}\' password file {e}')
            os._exit(0)

    return usernames, passwords

#
# =================== [ 异常处理包装 ] ===================
#

def run_wrapper(run_func, username, password):
    time.sleep(configs["delay"])
    try:
        run_func(username, password)
        # 未发生异常，重置连续异常计数
        with concurrent_control_signals["login_exception_count_lock"]:
            concurrent_control_signals["login_exception_count"] = 0

    except (ConnectionError, Timeout) as e:
        exception_message(f"{username}:{password}")
        print(f"[x] {datetime.now().strftime('%H:%M:%S')} {username}:{password} Error: {e}")
        with concurrent_control_signals["login_exception_count_lock"]:
            concurrent_control_signals["login_exception_count"] += 1

    except Exception as e:
        exception_message(f"{username}:{password}")
        print(f"[x] {datetime.now().strftime('%H:%M:%S')} {username}:{password} Error: {e}, detail:")
        print(traceback.format_exc())
        with concurrent_control_signals["login_exception_count_lock"]:
            concurrent_control_signals["login_exception_count"] += 1

    finally:
        # 连续异常超过10次则停止所有线程
        with concurrent_control_signals["login_exception_count_lock"]:
            if concurrent_control_signals["login_exception_count"] > 10:
                print(f"[x] {datetime.now().strftime('%H:%M:%S')} Too much error. Quiting.")
                concurrent_control_signals["thread_pool_stop_signal"].set()
        # 完成计数+1
        with concurrent_control_signals["login_finished_count_lock"]:
            concurrent_control_signals["login_finished_count"] += 1

#
# =================== [ 线程池调度 ] ===================
#

def concurrent_run(executor, tasks, usernames, passwords, run_func):
    if configs["mode"] == "clusterbomb":
        for password in passwords:
            for username in usernames:
                if len(tasks) >= configs["threads"]:
                    _, tasks = futures.wait(tasks, return_when=futures.FIRST_COMPLETED)
                if concurrent_control_signals["thread_pool_stop_signal"].is_set():
                    return
                tasks.add(executor.submit(run_wrapper, run_func, username, password))
    elif configs["mode"] == "pitchfork":
        count = min(len(usernames), len(passwords))
        for i in range(count):
            if len(tasks) >= configs["threads"]:
                _, tasks = futures.wait(tasks, return_when=futures.FIRST_COMPLETED)
            if concurrent_control_signals["thread_pool_stop_signal"].is_set():
                return
            tasks.add(executor.submit(run_wrapper, run_func, usernames[i], passwords[i]))
    else:
        print(f'[x] Unknown mode: {configs["mode"]}')

def report_elapsed_time():
    now = datetime.now()
    start_at = now
    print(f"[+] {now.strftime('%H:%M:%S')} task start")

    total = concurrent_control_signals["total_login_count"]
    finished = concurrent_control_signals["login_finished_count"]
    print(f"[!] {now.strftime('%H:%M:%S')} {finished}/{total} ({finished * 100 // total}%) finished")
    while True:
        if True == concurrent_control_signals["report_thread_stop_signal"].wait(timeout=600.0):
            break
        finished = concurrent_control_signals["login_finished_count"]
        print(f"[!] {datetime.now().strftime('%H:%M:%S')} {finished}/{total} ({finished * 100 // total}%) finished")

    now = datetime.now()
    end_at = now
    elapsed = strfdelta(end_at - start_at, "{days} days {hours}:{minutes}:{seconds}")
    print(f"[+] {now.strftime('%H:%M:%S')} task finished, elapsed {elapsed}")

#
# =================== [ 主入口 ] ===================
#

def start(run_func):
    usernames, passwords = load_dictionaries()

    if configs["mode"] == "clusterbomb":
        concurrent_control_signals["total_login_count"] = len(usernames) * len(passwords)
    elif configs["mode"] == "pitchfork":
        concurrent_control_signals["total_login_count"] = min(len(usernames), len(passwords))
    else:
        print(f'[x] Unknown mode: {configs["mode"]}')
        os._exit(0)

    if concurrent_control_signals["total_login_count"] == 0:
        print("[!] The total number of login attempts required is 0, so the program exits.")
        os._exit(0)

    info_message(f"\n# Begin at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    exception_message(f"\n# Begin at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    report_thread = threading.Thread(target=report_elapsed_time)
    report_thread.start()

    tasks = set()
    with futures.ThreadPoolExecutor(max_workers=configs["threads"]) as executor:
        try:
            concurrent_run(executor, tasks, usernames, passwords, run_func)
            print("[!] Wait for all threads exit.")
            futures.wait(tasks, return_when=futures.ALL_COMPLETED)
        except KeyboardInterrupt:
            print("[!] Get Ctrl-C, wait for all threads exit.")
            futures.wait(tasks, return_when=futures.ALL_COMPLETED)

    concurrent_control_signals["report_thread_stop_signal"].set()
    report_thread.join()
