from dotenv import load_dotenv
import os
import sys
import json
from logger import logging


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
            # 加载自定义配置
            if not os.path.exists(dotenv_path):
                # 如果找不到.env文件，尝试复制示例文件
                example_path = os.path.join(application_path, ".env.example")
                if os.path.exists(example_path):
                    import shutil
                    shutil.copy(example_path, dotenv_path)
                    logging.info(f"已创建配置文件: {dotenv_path}")
                else:
                    raise FileNotFoundError(f"配置文件不存在: {dotenv_path}")

            # 加载.env文件
            load_dotenv(dotenv_path)
            self._load_env_config()
            logging.info("使用自定义配置")

        self.check_config()

    def _load_official_config(self, config_path):
        """从官方配置文件加载配置"""
        try:
            # 检查官方配置文件是否存在
            if not os.path.exists(config_path):
                # 尝试使用示例配置
                example_path = config_path.replace('.json', '.example.json')
                if os.path.exists(example_path):
                    logging.warning(f"官方配置文件不存在，尝试使用示例配置: {example_path}")
                    with open(example_path, 'r', encoding='utf-8') as file:
                        config = json.load(file)
                else:
                    raise FileNotFoundError(f"官方配置文件不存在: {config_path}，也找不到示例配置")
            else:
                with open(config_path, 'r', encoding='utf-8') as file:
                    config = json.load(file)
                
            # 设置配置项
            self.domain = config.get("DOMAIN", "")
            self.imap_server = config.get("IMAP_SERVER", "")
            self.imap_port = config.get("IMAP_PORT", "")
            self.imap_user = config.get("IMAP_USER", "")
            self.imap_pass = config.get("IMAP_PASS", "")
            self.imap_dir = config.get("IMAP_DIR", "inbox")
            self.protocol = config.get("IMAP_PROTOCOL", "POP3")
        except Exception as e:
            logging.error(f"加载官方配置失败: {e}")
            # 加载失败后回退到自定义配置
            self.using_official = False
            self._load_env_config()

    def _load_env_config(self):
        """从.env文件加载配置"""
        # 加载基础配置
        self.domain = os.getenv("DOMAIN", "").strip()
        
        # 加载IMAP/POP3配置
        self.imap_server = os.getenv("IMAP_SERVER", "").strip()
        self.imap_port = os.getenv("IMAP_PORT", "").strip()
        self.imap_user = os.getenv("IMAP_USER", "").strip()
        self.imap_pass = os.getenv("IMAP_PASS", "").strip()
        self.imap_dir = os.getenv("IMAP_DIR", "inbox").strip()
        self.protocol = os.getenv("IMAP_PROTOCOL", "POP3").strip()

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
        """打印当前配置信息"""
        source = "官方配置" if self.using_official else "自定义配置"
        logging.info(f"\033[32m配置来源: {source}\033[0m")
        logging.info(f"\033[32m邮箱协议: {self.protocol.upper()}\033[0m")
        logging.info(f"\033[32m邮箱服务器: {self.imap_server}\033[0m")
        logging.info(f"\033[32m邮箱端口: {self.imap_port}\033[0m")
        logging.info(f"\033[32m邮箱用户名: {self.imap_user}\033[0m")
        logging.info(f"\033[32m邮箱密码: {'*' * len(self.imap_pass)}\033[0m")
        logging.info(f"\033[32m收件箱目录: {self.imap_dir}\033[0m")
        logging.info(f"\033[32m域名: {self.domain}\033[0m")


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
