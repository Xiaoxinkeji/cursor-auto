from datetime import datetime
import logging
import time
import re
from config import Config
import email
import imaplib
import poplib
from email.parser import Parser


class EmailVerificationHandler:
    def __init__(self, account, use_official=False):
        config = Config(use_official=use_official)
        self.imap_config = config.get_imap()
        self.protocol = config.get_protocol() or 'POP3'
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
            mail = imaplib.IMAP4_SSL(self.imap_config['imap_server'], self.imap_config['imap_port'])
            mail.login(self.imap_config['imap_user'], self.imap_config['imap_pass'])
            search_by_date=False
            # 针对网易系邮箱，imap登录后需要附带联系信息，且后续邮件搜索逻辑更改为获取当天的未读邮件
            if self.imap_config['imap_user'].endswith(('@163.com', '@126.com', '@yeah.net')):                
                imap_id = ("name", self.imap_config['imap_user'].split('@')[0], "contact", self.imap_config['imap_user'], "version", "1.0.0", "vendor", "imaplib")
                mail.xatom('ID', '("' + '" "'.join(imap_id) + '")')
                search_by_date=True
            mail.select(self.imap_config['imap_dir'])
            if search_by_date:
                date = datetime.now().strftime("%d-%b-%Y")
                status, messages = mail.search(None, f'ON {date} UNSEEN')
            else:
                status, messages = mail.search(None, 'TO', '"'+self.account+'"')
            if status != 'OK':
                return None

            mail_ids = messages[0].split()
            if not mail_ids:
                # 没有获取到，就在获取一次
                return self._get_mail_code_by_imap(retry=retry + 1)

            for mail_id in reversed(mail_ids):
                status, msg_data = mail.fetch(mail_id, '(RFC822)')
                if status != 'OK':
                    continue
                raw_email = msg_data[0][1]
                email_message = email.message_from_bytes(raw_email)

                # 如果是按日期搜索的邮件，需要进一步核对收件人地址是否对应
                if search_by_date and email_message['to'] !=self.account:
                    continue
                body = self._extract_imap_body(email_message)
                if body:
                    code_match = re.search(r"\b\d{6}\b", body)
                    if code_match:
                        code = code_match.group()
                        # 删除找到验证码的邮件
                        mail.store(mail_id, '+FLAGS', '\\Deleted')
                        mail.expunge()
                        mail.logout()
                        return code
            # print("未找到验证码")
            mail.logout()
            return None
        except Exception as e:
            print(f"发生错误: {e}")
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


if __name__ == "__main__":
    # 测试邮箱验证功能
    import sys
    
    # 检查是否提供了命令行参数
    use_official = False
    if len(sys.argv) > 1 and sys.argv[1] == '--official':
        use_official = True
    
    account = "test@example.com"  # 使用一个测试账号
    email_handler = EmailVerificationHandler(account, use_official=use_official)
    try:
        code = email_handler.get_verification_code()
        print(f"获取到验证码: {code}")
    except Exception as e:
        print(f"获取验证码失败: {e}")
