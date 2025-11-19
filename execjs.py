import shlex, subprocess

# 本模块负责执行JS代码，需要手动下载 QuickJS 并将路径添加到环境变量中，并确保 QuickJS 的程序名与 quickjs 变量一致
# 仓库地址：https://github.com/quickjs-ng/quickjs
quickjs = "qjs.exe"

# 执行特定功能，需要针对目标场景自行编写函数
# QuickJS 的常规用法，代码必须加上引号，并且为了获得结果，必须得用 console.log() 函数将结果输出：
# qjs -I signature.js -e "console.log('123456')"
def signature(data):
    # 这里引号有点复杂，建议用三引号处理
    evalcode = f'''qjs --std -I signature.js -e "var s=go('{data}');std.puts(s);"'''
    # print(evalcode)
    output = subprocess.check_output(shlex.split(evalcode))
    return output.decode("utf-8")
