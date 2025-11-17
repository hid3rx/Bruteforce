from selenium.webdriver.chrome.options import Options
from selenium import webdriver

# 初始化Chrome浏览器，selenium支持自动下载浏览器驱动，但如果遇到网络问题，会导致程序卡住不动，因此这里选择手动下载浏览器驱动
# 手动安装Chrome驱动步骤如下：
# 1. 访问 https://googlechromelabs.github.io/chrome-for-testing/ 查看自己浏览器的适配驱动
# 2. 选择对应操作系统的stable版本驱动，如： 
#       https://storage.googleapis.com/chrome-for-testing-public/142.x.x/win64/chromedriver-win64.zip
# 3. 把驱动文件chromedriver.exe放置在任意目录下（建议放在chrome.exe的同级目录中）
# 4. 把chrome.exe和chromedriver.exe的所在目录加入环境变量
def init():
    # 启动参数
    options = Options()
    # options.add_experimental_option('detach', True) # 调试用
    options.add_argument('--allow-running-insecure-content')
    options.add_argument('--disable-gpu')
    options.add_argument('--disable-site-isolation-trials')
    options.add_argument('--disable-web-security')
    options.add_argument('--headless')
    options.add_argument('--ignore-certificate-errors')
    # 加载JS文件，可以从本地加载，也可以从目标网站直接加载
    driver = webdriver.Chrome(options=options)
    driver.get('data:text/html;charset=utf-8,<script src="http://127.0.0.1/signature.js"></script>')
    return driver

# 执行特定功能，需要针对目标场景自行编写函数
def signature(driver, data):
    # 这里 selenium 可以自动将 arguments[0] 替换成 data 参数，并自动加上双引号
    return driver.execute_script('return go(arguments[0])', data)
