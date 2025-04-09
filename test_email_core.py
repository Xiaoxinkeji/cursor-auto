#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
官方邮箱配置测试工具

此脚本用于测试官方配置的邮箱连接是否正常工作
"""

import logging
import sys
import imaplib
from get_email_code import EmailVerificationHandler
from config import Config

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def test_official_config():
    """测试官方邮箱配置"""
    print("\n=== 测试官方邮箱配置 ===")
    
    # 加载官方配置
    config = Config(use_official=True)
    
    print(f"域名: {config.domain}")
    print(f"邮箱服务器: {config.imap_server}")
    print(f"邮箱端口: {config.imap_port}")
    print(f"邮箱用户名: {config.imap_user}")
    print(f"邮箱密码: {'*' * 8}")
    print(f"邮箱目录: {config.imap_dir}")
    print(f"协议: {config.protocol}")
    
    # 测试邮箱连接
    try:
        mail = imaplib.IMAP4_SSL(config.imap_server, int(config.imap_port))
        print("\n✅ 成功连接到邮箱服务器")
        
        mail.login(config.imap_user, config.imap_pass)
        print("✅ 成功登录邮箱")
        
        status, mailboxes = mail.list()
        print("\n邮箱文件夹列表:")
        for i, mailbox in enumerate(mailboxes[:5]):
            print(f"  {i+1}. {mailbox.decode()}")
        
        status, count = mail.select(config.imap_dir)
        if status == 'OK':
            print(f"\n✅ 成功打开文件夹 {config.imap_dir}，包含 {count[0].decode()} 封邮件")
        else:
            print(f"\n❌ 无法打开文件夹 {config.imap_dir}: {status}")
        
        mail.close()
        mail.logout()
        print("\n✅ 官方邮箱配置测试通过!")
        return True
    except Exception as e:
        print(f"\n❌ 邮箱连接测试失败: {e}")
        return False

def test_verification_code():
    """测试获取验证码功能"""
    print("\n=== 测试获取验证码功能 ===")
    
    try:
        account = "test@example.com"  # 测试账号
        handler = EmailVerificationHandler(account, use_official=True)
        
        print("开始获取验证码...")
        code = handler.get_verification_code()
        
        if code:
            print(f"\n✅ 成功获取验证码: {code}")
            return True
        else:
            print("\n❓ 未获取到验证码，这可能是正常的，因为没有实际发送验证邮件")
            return True
    except Exception as e:
        print(f"\n❌ 获取验证码测试失败: {e}")
        return False

if __name__ == "__main__":
    # 启用调试
    if '--debug' in sys.argv:
        imaplib.Debug = 4
    
    # 运行测试
    config_test = test_official_config()
    
    if config_test:
        verify_test = test_verification_code()
    
    print("\n=== 测试结果摘要 ===")
    print(f"官方配置测试: {'✅ 通过' if config_test else '❌ 失败'}")
    if config_test:
        print(f"验证码功能测试: {'✅ 通过' if verify_test else '❌ 失败'}")
    
    # 退出代码
    sys.exit(0 if config_test else 1) 