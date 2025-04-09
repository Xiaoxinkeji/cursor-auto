#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import imaplib
import socket
import sys
import time
import logging

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# QQ邮箱配置
SERVER = "imap.qq.com"
PORT = 993
USERNAME = "3264913523@qq.com"
PASSWORD = "avvttgebfmlodbfc"

def main():
    print(f"开始测试连接到QQ邮箱: {SERVER}:{PORT}")
    
    # 测试基本连接
    try:
        print("\n1. 测试基本网络连接...")
        sock = socket.create_connection((SERVER, PORT), timeout=10)
        print(f"基本连接成功: {SERVER}:{PORT}")
        sock.close()
    except Exception as e:
        print(f"基本连接失败: {e}")
        return
    
    # 测试IMAP连接
    try:
        print("\n2. 测试IMAP连接...")
        mail = imaplib.IMAP4_SSL(SERVER, PORT)
        print("SSL连接成功")
        
        print(f"尝试登录: {USERNAME}")
        mail.login(USERNAME, PASSWORD)
        print("登录成功")
        
        print("列出邮箱文件夹:")
        status, mailboxes = mail.list()
        if status == 'OK':
            for i, mailbox in enumerate(mailboxes[:5]):
                print(f"  - {mailbox.decode()}")
            if len(mailboxes) > 5:
                print(f"  ... 等 {len(mailboxes) - 5} 个文件夹")
        
        print("\n尝试选择收件箱...")
        status, count = mail.select('INBOX')
        if status == 'OK':
            print(f"成功打开收件箱，包含 {count[0].decode()} 封邮件")
        
        print("\n搜索邮件...")
        status, messages = mail.search(None, 'ALL')
        if status == 'OK':
            mail_ids = messages[0].split()
            print(f"找到 {len(mail_ids)} 封邮件")
            
            if mail_ids:
                latest_id = mail_ids[-1]
                print(f"获取最新邮件 (ID: {latest_id.decode()})...")
                status, msg_data = mail.fetch(latest_id, '(RFC822.HEADER)')
                if status == 'OK':
                    print("成功获取邮件")
        
        mail.close()
        mail.logout()
        print("\n测试完成: QQ邮箱连接正常!")
        
    except Exception as e:
        print(f"IMAP连接失败: {e}")

if __name__ == "__main__":
    main()