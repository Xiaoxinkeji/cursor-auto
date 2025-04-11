from dotenv import load_dotenv
import os
import sys
import json
from logger import logging
import base64


class Config:
    def __init__(self, use_official=False):
        # 记录使用的是官方配置还是自定义配置
        self.using_official = use_official
        
        # 检查是否在CI环境中
        if os.environ.get('CI') == 'true' or os.environ.get('GITHUB_ACTIONS') == 'true':
            self.using_official = True
            logging.info("检测到CI环境，使用官方配置")
        
        # 获取应用程序的根目录路径
        if getattr(sys, "frozen", False):
            # 如果是打包后的可执行文件
            application_path = os.path.dirname(sys.executable)
        else:
            # 如果是开发环境
            application_path = os.path.dirname(os.path.abspath(__file__))

        # 官方配置路径
        official_config_path = os.path.join(application_path, "official_config.json")
        
        # 自定义配置路径
        dotenv_path = os.path.join(application_path, ".env")

        # 根据配置模式加载不同的配置
        if self.using_official:
            # 加载官方配置
            self._load_official_config(official_config_path)
            logging.info("使用官方配置")
        else:
            # 尝试加载自定义配置
            try:
                if not os.path.exists(dotenv_path):
                    # 如果找不到.env文件，尝试复制示例文件
                    example_path = os.path.join(application_path, ".env.example")
                    if os.path.exists(example_path):
                        import shutil
                        shutil.copy(example_path, dotenv_path)
                        logging.info(f"已创建配置文件: {dotenv_path}")
                    else:
                        # 如果.env和.env.example都不存在，记录警告并回退到官方配置
                        logging.warning(f"配置文件不存在: {dotenv_path}，自动回退到官方配置")
                        self.using_official = True
                        self._load_official_config(official_config_path)
                        return  # 已加载官方配置，直接返回

                # 加载.env文件
                load_dotenv(dotenv_path)
                self._load_env_config()
                logging.info("使用自定义配置")
            except Exception as e:
                # 如果加载自定义配置失败，记录错误并回退到官方配置
                logging.error(f"加载自定义配置失败: {e}")
                logging.warning("自动回退到官方配置")
                self.using_official = True
                self._load_official_config(official_config_path)
                return  # 已加载官方配置，直接返回

        self.check_config()

    @staticmethod
    def _decode_value(encoded_value):
        """解码加密的配置值"""
        try:
            # 简单的Base64解码
            decoded_bytes = base64.b64decode(encoded_value)
            return decoded_bytes.decode('utf-8')
        except Exception as e:
            logging.error(f"解码配置值失败: {e}")
            return "<解码失败>"

    def _load_official_config(self, config_path):
        """从官方配置文件加载配置"""
        try:
            # 优先使用内置配置，不再写入本地文件
            # 检查是否在GitHub Actions环境中
            if os.environ.get('CI') == 'true' or os.environ.get('GITHUB_ACTIONS') == 'true':
                # 在CI环境中尝试加载文件
                if os.path.exists(config_path):
                    logging.info("CI环境: 使用workflow创建的配置文件")
                    with open(config_path, 'r', encoding='utf-8') as file:
                        config = json.load(file)
                else:
                    logging.error("CI环境: 配置文件未找到，请检查GitHub Secrets是否正确设置")
                    # 使用内置默认配置作为备用
                    config = self._get_default_config()
            elif os.path.exists(config_path):
                # 如果本地存在配置文件，读取它（确保向后兼容）
                with open(config_path, 'r', encoding='utf-8') as file:
                    config = json.load(file)
                logging.info("使用现有的官方配置文件")
            else:
                # 使用内置默认配置
                logging.info("使用内置官方配置")
                config = self._get_default_config()
                
            # 设置配置项
            self.domain = config.get("DOMAIN", "")
            self.imap_server = config.get("IMAP_SERVER", "")
            self.imap_port = config.get("IMAP_PORT", "")
            
            # 解码敏感信息
            encoded_user = config.get("IMAP_USER", "")
            encoded_pass = config.get("IMAP_PASS", "")
            
            if encoded_user.startswith("BASE64:"):
                self.imap_user = self._decode_value(encoded_user[7:])
            else:
                self.imap_user = encoded_user
                
            if encoded_pass.startswith("BASE64:"):
                self.imap_pass = self._decode_value(encoded_pass[7:])
            else:
                self.imap_pass = encoded_pass
                
            self.imap_dir = config.get("IMAP_DIR", "inbox")
            self.protocol = config.get("IMAP_PROTOCOL", "POP3")
        except Exception as e:
            logging.error(f"加载官方配置失败: {e}")
            # 加载失败后回退到内置配置
            config = self._get_default_config()
            self.domain = config.get("DOMAIN", "")
            self.imap_server = config.get("IMAP_SERVER", "")
            self.imap_port = config.get("IMAP_PORT", "")
            
            # 解码敏感信息
            encoded_user = config.get("IMAP_USER", "")
            encoded_pass = config.get("IMAP_PASS", "")
            
            if encoded_user.startswith("BASE64:"):
                self.imap_user = self._decode_value(encoded_user[7:])
            else:
                self.imap_user = encoded_user
                
            if encoded_pass.startswith("BASE64:"):
                self.imap_pass = self._decode_value(encoded_pass[7:])
            else:
                self.imap_pass = encoded_pass
                
            self.imap_dir = config.get("IMAP_DIR", "inbox")
            self.protocol = config.get("IMAP_PROTOCOL", "POP3")
    
    def _get_default_config(self):
        """返回内置的默认配置，使用BASE64编码敏感信息"""
        # 原始值为 3264913523@qq.com 和 avvttgebfmlodbfc
        # Base64编码后: MzI2NDkxMzUyM0BxcS5jb20= 和 YXZ2dHRnZWJmbWxvZGJmYw==
        return {
            "DOMAIN": "xiao09.icu",
            "IMAP_SERVER": "imap.qq.com",
            "IMAP_PORT": "993",
            "IMAP_USER": "BASE64:MzI2NDkxMzUyM0BxcS5jb20=",
            "IMAP_PASS": "BASE64:YXZ2dHRnZWJmbWxvZGJmYw==",
            "IMAP_DIR": "inbox",
            "IMAP_PROTOCOL": "IMAP"
        }

    def _load_env_config(self):
        """从.env文件加载配置"""
        try:
            # 加载基础配置，提供合理的默认值
            self.domain = os.getenv("DOMAIN", "").strip()
            if not self.domain:
                logging.warning("DOMAIN环境变量未设置或为空，使用默认域名")
                self.domain = "bsmail.xyz"  # 默认域名
            
            # 加载IMAP/POP3配置，提供合理的默认值
            self.imap_server = os.getenv("IMAP_SERVER", "").strip()
            if not self.imap_server:
                logging.warning("IMAP_SERVER环境变量未设置或为空，使用默认服务器")
                self.imap_server = "imap.qq.com"  # 默认IMAP服务器
                
            self.imap_port = os.getenv("IMAP_PORT", "").strip()
            if not self.imap_port:
                logging.warning("IMAP_PORT环境变量未设置或为空，使用默认端口")
                self.imap_port = "993"  # 默认IMAP端口
                
            self.imap_user = os.getenv("IMAP_USER", "").strip()
            if not self.imap_user:
                logging.warning("IMAP_USER环境变量未设置或为空")
                self.imap_user = "<请在配置文件中设置>"  # 安全的默认值
                
            self.imap_pass = os.getenv("IMAP_PASS", "").strip()
            if not self.imap_pass:
                logging.warning("IMAP_PASS环境变量未设置或为空")
                self.imap_pass = "<请在配置文件中设置>"  # 安全的默认值
                
            self.imap_dir = os.getenv("IMAP_DIR", "inbox").strip()
            self.protocol = os.getenv("IMAP_PROTOCOL", "IMAP").strip()
        except Exception as e:
            logging.error(f"加载环境变量失败: {e}")
            # 如果加载失败，设置默认值
            self.domain = "xiao09.icu"
            self.imap_server = "imap.qq.com"
            self.imap_port = "993"
            self.imap_user = "<请在配置文件中设置>"
            self.imap_pass = "<请在配置文件中设置>"
            self.imap_dir = "inbox"
            self.protocol = "IMAP"

    def get_imap(self):
        return {
            "imap_server": self.imap_server,
            "imap_port": self.imap_port,
            "imap_user": self.imap_user,
            "imap_pass": self.imap_pass,
            "imap_dir": self.imap_dir,
        }

    def get_domain(self):
        return self.domain

    def get_protocol(self):
        """获取邮件协议类型
        
        Returns:
            str: 'IMAP' 或 'POP3'
        """
        return self.protocol

    def is_using_official(self):
        """检查是否使用官方配置
        
        Returns:
            bool: 是否使用官方配置
        """
        return self.using_official

    def check_config(self):
        """检查配置项是否有效

        检查规则：
        1. 基础配置需要设置DOMAIN
        2. 邮箱配置需要 IMAP_SERVER、IMAP_PORT、IMAP_USER、IMAP_PASS
        3. IMAP_DIR 是可选的
        """
        # 基础配置检查
        required_configs = {
            "domain": "域名",
        }

        # 检查基础配置
        for key, name in required_configs.items():
            if not self.check_is_valid(getattr(self, key)):
                raise ValueError(f"{name}未配置，请在配置文件中设置 {key.upper()}")

        # 检查邮箱配置 - IMAP/POP3模式
        imap_configs = {
            "imap_server": "邮箱服务器",
            "imap_port": "邮箱端口",
            "imap_user": "邮箱用户名",
            "imap_pass": "邮箱密码",
        }

        for key, name in imap_configs.items():
            value = getattr(self, key)
            if value == "null" or not self.check_is_valid(value):
                raise ValueError(
                    f"{name}未配置，请在配置文件中设置 {key.upper()}"
                )

        # IMAP_DIR 是可选的，如果设置了就检查其有效性
        if self.imap_dir != "null" and not self.check_is_valid(self.imap_dir):
            raise ValueError(
                "收件箱目录配置无效，请在配置文件中正确设置 IMAP_DIR"
            )

    def check_is_valid(self, value):
        """检查配置项是否有效

        Args:
            value: 配置项的值

        Returns:
            bool: 配置项是否有效
        """
        return isinstance(value, str) and len(str(value).strip()) > 0

    def print_config(self):
        """打印当前配置信息（隐藏敏感信息）"""
        source = "官方配置" if self.using_official else "自定义配置"
        logging.info(f"配置来源: {source}")
        logging.info(f"邮箱协议: {self.protocol.upper()}")
        
        # 隐藏敏感信息
        hidden_user = self._hide_email(self.imap_user)
        hidden_pass = "********" # 完全隐藏密码
        
        # 只打印必要的信息
        logging.info(f"邮箱服务器: {self.imap_server}")
        logging.info(f"邮箱用户名: {hidden_user}")
        logging.info(f"域名: {self.domain}")
    
    def _hide_email(self, email):
        """隐藏邮箱地址中间部分"""
        if not email or '@' not in email:
            return "********"
        
        parts = email.split('@')
        username = parts[0]
        domain = parts[1]
        
        if len(username) <= 3:
            hidden_username = username[0] + "*" * (len(username) - 1)
        else:
            hidden_username = username[0] + "*" * (len(username) - 2) + username[-1]
            
        return f"{hidden_username}@{domain}"


# 使用示例
if __name__ == "__main__":
    try:
        # 测试自定义配置
        config = Config(use_official=False)
        print("环境变量加载成功！")
        config.print_config()
        
        # 也可以测试官方配置
        # config = Config(use_official=True)
        # print("官方配置加载成功！")
        # config.print_config()
    except ValueError as e:
        print(f"错误: {e}")
