import os
from dotenv import load_dotenv
from get_email_code import EmailVerificationHandler
import logging

def test_email_server():
    """测试邮箱服务器连接（POP3/IMAP）"""
    account = os.getenv('IMAP_USER')  # 使用配置的邮箱作为测试账号
    handler = EmailVerificationHandler(account)
    protocol = os.getenv('IMAP_PROTOCOL', 'POP3')
    print(f"\n=== 测试 {protocol} 模式 ===")
    print(f"邮箱服务器: {os.getenv('IMAP_SERVER')}")
    print(f"邮箱账号: {os.getenv('IMAP_USER')}")
    print(f"协议类型: {protocol}")
    
    try:
        print("尝试连接邮箱服务器...")
        if protocol.upper() == 'IMAP':
            result = handler._get_mail_code_by_imap(retry=0)
        else:
            result = handler._get_mail_code_by_pop3(retry=0)
        
        print(f"连接测试完成: {'成功' if result is not None else '未找到验证码邮件'}")
        print("注意: 如未找到验证码邮件属于正常情况，因为此时没有新的验证码邮件")
    except Exception as e:
        print(f"连接测试失败: {str(e)}")

def print_config():
    """打印当前配置"""
    print("\n当前环境变量配置:")
    print(f"IMAP_SERVER: {os.getenv('IMAP_SERVER')}")
    print(f"IMAP_PORT: {os.getenv('IMAP_PORT')}")
    print(f"IMAP_USER: {os.getenv('IMAP_USER')}")
    print(f"IMAP_PROTOCOL: {os.getenv('IMAP_PROTOCOL', 'POP3')}")
    print(f"DOMAIN: {os.getenv('DOMAIN')}")

def main():
    # 加载环境变量
    load_dotenv()
    
    # 打印初始配置
    print_config()
    
    try:
        # 测试邮箱服务器连接
        test_email_server()
    except Exception as e:
        print(f"测试过程中发生错误: {str(e)}")

if __name__ == "__main__":
    main() 