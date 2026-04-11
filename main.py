# coding=utf-8
#
# ============================================================================
#   main.py — 程序入口
#
#   运行方式: python main.py
#
#   【重要】如需针对新网站开发检测脚本，请修改 target.py，不要修改本文件
# ============================================================================
#

from framework import start
from target import run

if __name__ == "__main__":
    start(run)
