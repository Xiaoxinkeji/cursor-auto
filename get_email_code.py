from datetime import datetime
import logging
import time
import re
from config import Config
import email
import imaplib
import poplib
from email.parser import Parser
import socket


class EmailVerificationHandler:
    def __init__(self, account, use_official=False):
        try:
            config = Config(use_official=use_official)
            self.imap_config = config.get_imap()
            self.protocol = config.get_protocol() or 'POP3'
        except Exception as e:
            # 如果配置加载失败，使用默认值
            logging.error(f"加载邮箱验证配置失败: {e}")
            logging.warning("使用默认邮箱配置")
            self.imap_config = {
                "imap_server": "imap.qq.com",
                "imap_port": "993",
                "imap_user": "3264913523@qq.com",
                "imap_pass": "avvttgebfmlodbfc",
                "imap_dir": "inbox"
            }
            self.protocol = 'IMAP'
            
        self.account = account
        self.using_official = use_official

    def get_verification_code(self, max_retries=5, retry_interval=60):
        """
        获取验证码，带有重试机制。

        Args:
            max_retries: 最大重试次数。
            retry_interval: 重试间隔时间（秒）。

        Returns:
            验证码 (字符串或 None)。
        """
        for attempt in range(max_retries):
            try:
                logging.info(f"尝试获取验证码 (第 {attempt + 1}/{max_retries} 次)...")

                # 根据协议选择获取邮件的方式
                if self.protocol.upper() == 'IMAP':
                    verify_code = self._get_mail_code_by_imap()
                else:
                    verify_code = self._get_mail_code_by_pop3()
                
                if verify_code is not None:
                    return verify_code

                if attempt < max_retries - 1:  # 除了最后一次尝试，都等待
                    logging.warning(f"未获取到验证码，{retry_interval} 秒后重试...")
                    time.sleep(retry_interval)

            except Exception as e:
                logging.error(f"获取验证码失败: {e}")  # 记录更一般的异常
                if attempt < max_retries - 1:
                    logging.error(f"发生错误，{retry_interval} 秒后重试...")
                    time.sleep(retry_interval)
                else:
                    raise Exception(f"获取验证码失败且已达最大重试次数: {e}") from e

        raise Exception(f"经过 {max_retries} 次尝试后仍未获取到验证码。")

    # 使用imap获取邮件
    def _get_mail_code_by_imap(self, retry = 0):
        if retry > 0:
            time.sleep(3)
        if retry >= 20:
            raise Exception("获取验证码超时")
        try:
            # 连接到IMAP服务器
            logging.info(f"尝试连接到IMAP服务器: {self.imap_config['imap_server']}:{self.imap_config['imap_port']}")
            
            # 使用SSL连接
            mail = imaplib.IMAP4_SSL(self.imap_config['imap_server'], self.imap_config['imap_port'])
            
            # 对于Gmail，需要特殊处理
            is_gmail = 'gmail' in self.imap_config['imap_server'].lower()
            if is_gmail:
                logging.info("检测到Gmail邮箱，使用特殊连接设置")
            
            logging.info(f"正在登录邮箱: {self.imap_config['imap_user']}")
            mail.login(self.imap_config['imap_user'], self.imap_config['imap_pass'])
            logging.info("邮箱登录成功")
            
            search_by_date=False
            # 针对网易系邮箱，imap登录后需要附带联系信息，且后续邮件搜索逻辑更改为获取当天的未读邮件
            if self.imap_config['imap_user'].endswith(('@163.com', '@126.com', '@yeah.net')):                
                imap_id = ("name", self.imap_config['imap_user'].split('@')[0], "contact", self.imap_config['imap_user'], "version", "1.0.0", "vendor", "imaplib")
                mail.xatom('ID', '("' + '" "'.join(imap_id) + '")')
                search_by_date=True
            
            logging.info(f"选择邮箱文件夹: {self.imap_config['imap_dir']}")
            mail.select(self.imap_config['imap_dir'])
            
            if search_by_date:
                date = datetime.now().strftime("%d-%b-%Y")
                logging.info(f"搜索当天({date})未读邮件")
                status, messages = mail.search(None, f'ON {date} UNSEEN')
            else:
                logging.info(f"搜索发送至 {self.account} 的邮件")
                status, messages = mail.search(None, 'TO', '"'+self.account+'"')
                
            logging.info(f"搜索状态: {status}, 找到 {len(messages[0].split()) if status == 'OK' else 0} 封邮件")
            
            if status != 'OK':
                return None

            mail_ids = messages[0].split()
            if not mail_ids:
                # 没有获取到，就在获取一次
                logging.info("未找到邮件，稍后重试")
                return self._get_mail_code_by_imap(retry=retry + 1)

            for mail_id in reversed(mail_ids):
                logging.info(f"读取邮件 ID: {mail_id}")
                status, msg_data = mail.fetch(mail_id, '(RFC822)')
                if status != 'OK':
                    logging.warning(f"获取邮件内容失败，状态: {status}")
                    continue
                raw_email = msg_data[0][1]
                email_message = email.message_from_bytes(raw_email)

                # 如果是按日期搜索的邮件，需要进一步核对收件人地址是否对应
                if search_by_date and email_message['to'] !=self.account:
                    logging.info(f"邮件收件人不匹配，期望: {self.account}, 实际: {email_message['to']}")
                    continue
                body = self._extract_imap_body(email_message)
                if body:
                    code_match = re.search(r"\b\d{6}\b", body)
                    if code_match:
                        code = code_match.group()
                        logging.info(f"找到验证码: {code}")
                        # 删除找到验证码的邮件
                        mail.store(mail_id, '+FLAGS', '\\Deleted')
                        mail.expunge()
                        mail.logout()
                        return code
            # print("未找到验证码")
            logging.info("未在邮件中找到验证码")
            mail.logout()
            return None
        except Exception as e:
            logging.error(f"发生错误: {e}")
            return None

    def _extract_imap_body(self, email_message):
        # 提取邮件正文
        if email_message.is_multipart():
            for part in email_message.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition"))
                if content_type == "text/plain" and "attachment" not in content_disposition:
                    charset = part.get_content_charset() or 'utf-8'
                    try:
                        body = part.get_payload(decode=True).decode(charset, errors='ignore')
                        return body
                    except Exception as e:
                        logging.error(f"解码邮件正文失败: {e}")
        else:
            content_type = email_message.get_content_type()
            if content_type == "text/plain":
                charset = email_message.get_content_charset() or 'utf-8'
                try:
                    body = email_message.get_payload(decode=True).decode(charset, errors='ignore')
                    return body
                except Exception as e:
                    logging.error(f"解码邮件正文失败: {e}")
        return ""

    # 使用 POP3 获取邮件
    def _get_mail_code_by_pop3(self, retry = 0):
        if retry > 0:
            time.sleep(3)
        if retry >= 20:
            raise Exception("获取验证码超时")
        
        pop3 = None
        try:
            # 连接到服务器
            pop3 = poplib.POP3_SSL(self.imap_config['imap_server'], int(self.imap_config['imap_port']))
            pop3.user(self.imap_config['imap_user'])
            pop3.pass_(self.imap_config['imap_pass'])
            
            # 获取最新的10封邮件
            num_messages = len(pop3.list()[1])
            for i in range(num_messages, max(1, num_messages-9), -1):
                response, lines, octets = pop3.retr(i)
                msg_content = b'\r\n'.join(lines).decode('utf-8')
                msg = Parser().parsestr(msg_content)
                
                # 检查发件人
                if 'no-reply@cursor.sh' in msg.get('From', ''):
                    # 提取邮件正文
                    body = self._extract_pop3_body(msg)
                    if body:
                        # 查找验证码
                        code_match = re.search(r"\b\d{6}\b", body)
                        if code_match:
                            code = code_match.group()
                            pop3.quit()
                            return code
            
            pop3.quit()
            return self._get_mail_code_by_pop3(retry=retry + 1)
            
        except Exception as e:
            print(f"发生错误: {e}")
            if pop3:
                try:
                    pop3.quit()
                except:
                    pass
            return None

    def _extract_pop3_body(self, email_message):
        # 提取邮件正文
        if email_message.is_multipart():
            for part in email_message.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition"))
                if content_type == "text/plain" and "attachment" not in content_disposition:
                    try:
                        body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                        return body
                    except Exception as e:
                        logging.error(f"解码邮件正文失败: {e}")
        else:
            try:
                body = email_message.get_payload(decode=True).decode('utf-8', errors='ignore')
                return body
            except Exception as e:
                logging.error(f"解码邮件正文失败: {e}")
        return ""


def print_network_troubleshooting_guide():
    """打印网络问题解决指南"""
    print("\n" + "="*50)
    print("Gmail连接故障排除指南")
    print("="*50)
    print("\n1. 防火墙设置:")
    print("   - 确保您的防火墙允许连接到 imap.gmail.com:993")
    print("   - 检查是否有安全软件阻止了该连接")
    
    print("\n2. Gmail账户设置:")
    print("   - 确保您的Gmail账户已启用IMAP访问:")
    print("     登录Gmail > 设置 > 查看所有设置 > 转发和POP/IMAP > 启用IMAP")
    print("   - 确保您使用的是应用专用密码而非常规密码")
    print("   - 创建应用专用密码: https://myaccount.google.com/apppasswords")
    
    print("\n3. 网络连接:")
    print("   - 尝试在浏览器中访问 https://gmail.com 确认基本连接")
    print("   - 如果在公司或学校网络，请咨询网络管理员")
    
    print("\n4. 代理设置:")
    print("   - 如果您使用代理上网，请在.env文件中配置代理设置:")
    print("     BROWSER_PROXY='http://user:pass@host:port'")
    
    print("\n5. 测试其他邮箱:")
    print("   - 尝试使用其他邮箱服务如QQ邮箱或Outlook")
    print("   - 修改 official_config.json 或 .env 文件更改配置")
    
    print("\n6. 使用SSL调试:")
    print("   - 启用SSL调试可获取更多信息:")
    print("     import imaplib; imaplib.Debug = 4")
    
    print("="*50)
    print("注意: 某些网络环境可能完全阻止了对Gmail的访问，")
    print("在这种情况下，请考虑使用其他邮箱服务。")
    print("="*50 + "\n")


if __name__ == "__main__":
    # 测试邮箱验证功能
    import sys
    import socket
    
    def test_connection(host, port):
        """测试网络连接"""
        try:
            logging.info(f"测试连接到 {host}:{port}...")
            sock = socket.create_connection((host, port), timeout=10)
            sock.close()
            logging.info(f"连接成功: {host}:{port}")
            return True
        except Exception as e:
            logging.error(f"连接失败: {host}:{port} - {e}")
            return False
    
    def test_gmail_settings():
        """测试Gmail连接设置"""
        gmail_host = "imap.gmail.com"
        gmail_port = 993
        gmail_user = "asdijnk@gmail.com"
        gmail_pass = "falrrhcacotxsiyv"
        
        logging.info("=== Gmail 连接测试 ===")
        
        # 测试网络连通性
        if not test_connection(gmail_host, gmail_port):
            logging.error("无法连接到Gmail服务器")
            return False
        
        try:
            # 尝试使用imaplib直接连接
            logging.info("尝试IMAP连接...")
            mail = imaplib.IMAP4_SSL(gmail_host, gmail_port)
            
            logging.info(f"尝试登录: {gmail_user}")
            mail.login(gmail_user, gmail_pass)
            logging.info("登录成功!")
            
            # 列出邮箱文件夹
            logging.info("列出邮箱文件夹:")
            status, mailboxes = mail.list()
            if status == 'OK':
                for mailbox in mailboxes:
                    logging.info(f"  {mailbox.decode()}")
            
            # 检查INBOX
            logging.info("尝试选择INBOX文件夹...")
            status, count = mail.select('INBOX')
            if status == 'OK':
                logging.info(f"INBOX中有 {count[0].decode()} 封邮件")
            else:
                logging.error(f"选择INBOX失败: {status}")
            
            mail.logout()
            logging.info("Gmail连接测试成功!")
            return True
        except Exception as e:
            logging.error(f"Gmail连接测试失败: {e}")
            return False
    
    # 检查是否提供了命令行参数
    use_official = False
    if len(sys.argv) > 1 and sys.argv[1] == '--official':
        use_official = True
    
    # 添加全局超时设置
    socket.setdefaulttimeout(30)  # 设置30秒超时
    
    # 启用详细的IMAP调试输出
    if len(sys.argv) > 1 and (sys.argv[1] == '--debug' or '--debug' in sys.argv):
        imaplib.Debug = 4
        logging.info("已启用IMAP调试模式")
    
    # 如果使用官方配置，先测试Gmail连接
    if use_official:
        logging.info("使用官方配置，先测试Gmail连接...")
        if not test_gmail_settings():
            logging.error("Gmail连接测试失败，请检查网络连接和Gmail设置")
            print_network_troubleshooting_guide()
            sys.exit(1)
    
    account = "test@example.com"  # 使用一个测试账号
    email_handler = EmailVerificationHandler(account, use_official=use_official)
    try:
        code = email_handler.get_verification_code()
        print(f"获取到验证码: {code}")
    except Exception as e:
        print(f"获取验证码失败: {e}")
        print_network_troubleshooting_guide()
