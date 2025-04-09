#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Gmail连接测试工具

此脚本用于测试与Gmail IMAP服务器的连接，帮助用户排查配置问题。
"""

import imaplib
import socket
import sys
import logging
import time
import os
from get_email_code import print_network_troubleshooting_guide

# 配置基本日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()]
)

# Gmail连接参数
GMAIL_HOST = "imap.gmail.com"
GMAIL_PORT = 993
GMAIL_USER = "asdijnk@gmail.com"
GMAIL_PASS = "falrrhcacotxsiyv"

def test_connection(host, port, timeout=10):
    """测试基本网络连接"""
    try:
        print(f"\n[1/4] 测试基本网络连接到 {host}:{port}...")
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
        print(f"✅ 连接成功: 可以访问 {host}:{port}")
        return True
    except Exception as e:
        print(f"❌ 连接失败: {host}:{port} - {str(e)}")
        return False


def test_ssl_connection(host, port, timeout=10):
    """测试SSL连接"""
    try:
        print(f"\n[2/4] 测试SSL连接到 {host}:{port}...")
        import ssl
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                print(f"✅ SSL连接成功: {host}:{port}")
                expiry = cert.get('notAfter', 'Unknown')
                print(f"   证书过期时间: {expiry}")
                return True
    except Exception as e:
        print(f"❌ SSL连接失败: {host}:{port} - {str(e)}")
        return False


def test_imap_connection(host, port, user, password):
    """测试IMAP连接"""
    try:
        print(f"\n[3/4] 测试IMAP连接到 {host}:{port}...")
        # 启用详细调试
        if '--debug' in sys.argv:
            imaplib.Debug = 4
            
        mail = imaplib.IMAP4_SSL(host, port)
        print(f"✅ IMAP服务器连接成功")
        
        print(f"   尝试登录: {user}")
        mail.login(user, password)
        print(f"✅ IMAP登录成功")
        
        # 列出邮箱
        print("\n   邮箱文件夹列表:")
        status, mailboxes = mail.list()
        if status == 'OK':
            for i, mailbox in enumerate(mailboxes[:10]):  # 只显示前10个
                print(f"   {i+1}. {mailbox.decode()}")
            if len(mailboxes) > 10:
                print(f"   ...等 {len(mailboxes)-10} 个文件夹未显示")
        
        # 检查INBOX
        print("\n   检查INBOX文件夹...")
        status, count = mail.select('INBOX')
        if status == 'OK':
            print(f"✅ INBOX访问成功，包含 {count[0].decode()} 封邮件")
        else:
            print(f"❌ 无法访问INBOX: {status}")
            
        mail.close()
        mail.logout()
        return True
    except Exception as e:
        print(f"❌ IMAP连接测试失败: {str(e)}")
        return False


def test_receive_email(user):
    """测试接收邮件功能"""
    try:
        print(f"\n[4/4] 测试接收邮件功能...")
        print("   此测试将检查是否能成功搜索邮件")
        
        mail = imaplib.IMAP4_SSL(GMAIL_HOST, GMAIL_PORT)
        mail.login(GMAIL_USER, GMAIL_PASS)
        mail.select('INBOX')
        
        # 搜索最近的5封邮件
        status, messages = mail.search(None, 'ALL')
        if status != 'OK':
            print(f"❌ 搜索邮件失败: {status}")
            mail.logout()
            return False
            
        mail_ids = messages[0].split()
        if not mail_ids:
            print("   INBOX中没有邮件")
        else:
            print(f"   找到 {len(mail_ids)} 封邮件")
            
            # 尝试获取最新邮件
            latest_id = mail_ids[-1]
            print(f"   获取最新邮件 (ID: {latest_id.decode()})...")
            status, msg_data = mail.fetch(latest_id, '(RFC822.HEADER)')
            
            if status == 'OK':
                print("✅ 成功获取邮件内容")
            else:
                print(f"❌ 获取邮件内容失败: {status}")
                
        mail.logout()
        print("✅ 接收邮件测试完成")
        return True
    except Exception as e:
        print(f"❌ 接收邮件测试失败: {str(e)}")
        return False


def run_all_tests():
    """运行所有测试"""
    print("\n" + "="*50)
    print("Gmail连接测试工具")
    print("="*50)
    
    print(f"\n当前测试配置:")
    print(f"- 服务器: {GMAIL_HOST}")
    print(f"- 端口: {GMAIL_PORT}")
    print(f"- 用户名: {GMAIL_USER}")
    print(f"- 密码: {'*' * len(GMAIL_PASS)}")
    
    # 设置超时
    socket.setdefaulttimeout(30)
    
    # 运行测试
    basic_conn = test_connection(GMAIL_HOST, GMAIL_PORT)
    if not basic_conn:
        print("\n❌ 基本连接测试失败，跳过后续测试")
        return False
        
    ssl_conn = test_ssl_connection(GMAIL_HOST, GMAIL_PORT)
    if not ssl_conn:
        print("\n❌ SSL连接测试失败，跳过后续测试")
        return False
        
    imap_conn = test_imap_connection(GMAIL_HOST, GMAIL_PORT, GMAIL_USER, GMAIL_PASS)
    if not imap_conn:
        print("\n❌ IMAP连接测试失败，跳过后续测试")
        return False
        
    email_test = test_receive_email(GMAIL_USER)
    
    # 总结
    print("\n" + "="*50)
    print("测试结果摘要:")
    print(f"基本网络连接: {'✅ 成功' if basic_conn else '❌ 失败'}")
    print(f"SSL连接: {'✅ 成功' if ssl_conn else '❌ 失败'}")
    print(f"IMAP连接: {'✅ 成功' if imap_conn else '❌ 失败'}")
    print(f"接收邮件测试: {'✅ 成功' if email_test else '❌ 失败'}")
    
    if basic_conn and ssl_conn and imap_conn and email_test:
        print("\n✅ 全部测试通过! Gmail配置可以正常使用。")
        return True
    else:
        print("\n❌ 部分测试失败，请查看详细信息进行排查。")
        print_network_troubleshooting_guide()
        return False


if __name__ == "__main__":
    try:
        # 检查参数
        if len(sys.argv) > 1 and sys.argv[1] == '--help':
            print("使用方法: python test_gmail_connection.py [选项]")
            print("选项:")
            print("  --debug    启用详细的IMAP调试输出")
            print("  --help     显示此帮助信息")
            sys.exit(0)
            
        # 运行测试
        success = run_all_tests()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n测试被用户中断")
        sys.exit(1)
    except Exception as e:
        print(f"\n测试过程中发生错误: {str(e)}")
        print_network_troubleshooting_guide()
        sys.exit(1) 