import os
import platform
import json
import sys
import ctypes
from colorama import Fore, Style
from enum import Enum
from typing import Optional
import sqlite3

from exit_cursor import ExitCursor
import go_cursor_help
import patch_cursor_get_machine_id
from reset_machine import MachineIDResetter

os.environ["PYTHONVERBOSE"] = "0"
os.environ["PYINSTALLER_VERBOSE"] = "0"

import time
import random
from cursor_auth_manager import CursorAuthManager
import os
from logger import logging
from browser_utils import BrowserManager
from get_email_code import EmailVerificationHandler
from logo import print_logo
from config import Config
from datetime import datetime
import threading
import webbrowser

# 定义 EMOJI 字典
EMOJI = {"ERROR": "❌", "WARNING": "⚠️", "INFO": "ℹ️"}


def is_admin():
    """检查程序是否以管理员权限运行"""
    try:
        if platform.system() == "Windows":
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            # Unix系统通常检查EUID是否为0
            return os.geteuid() == 0
    except Exception:
        return False


def run_as_admin():
    """尝试以管理员权限重新启动程序"""
    try:
        if platform.system() == "Windows":
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
            sys.exit(0)
        else:
            # 在macOS和Linux上尝试用sudo重启
            if os.path.exists("/usr/bin/sudo") or os.path.exists("/bin/sudo"):
                os.system(f"sudo {sys.executable} {' '.join(sys.argv)}")
                sys.exit(0)
    except Exception as e:
        logging.error(f"提升权限失败: {e}")
        return False
    return True


class VerificationStatus(Enum):
    """验证状态枚举"""

    PASSWORD_PAGE = "@name=password"
    CAPTCHA_PAGE = "@data-index=0"
    ACCOUNT_SETTINGS = "Account Settings"


class TurnstileError(Exception):
    """Turnstile 验证相关异常"""

    pass


def save_screenshot(tab, stage: str, timestamp: bool = True) -> None:
    """
    保存页面截图

    Args:
        tab: 浏览器标签页对象
        stage: 截图阶段标识
        timestamp: 是否添加时间戳
    """
    try:
        # 创建 screenshots 目录
        screenshot_dir = "screenshots"
        if not os.path.exists(screenshot_dir):
            os.makedirs(screenshot_dir)

        # 生成文件名
        if timestamp:
            filename = f"turnstile_{stage}_{int(time.time())}.png"
        else:
            filename = f"turnstile_{stage}.png"

        filepath = os.path.join(screenshot_dir, filename)

        # 保存截图
        tab.get_screenshot(filepath)
        logging.debug(f"截图已保存: {filepath}")
    except Exception as e:
        logging.warning(f"截图保存失败: {str(e)}")


def check_verification_success(tab) -> Optional[VerificationStatus]:
    """
    检查验证是否成功

    Returns:
        VerificationStatus: 验证成功时返回对应状态，失败返回 None
    """
    for status in VerificationStatus:
        if tab.ele(status.value):
            logging.info(f"验证成功 - 已到达{status.name}页面")
            return status
    return None


def handle_turnstile(tab, max_retries: int = 2, retry_interval: tuple = (1, 2)) -> bool:
    """
    处理 Turnstile 验证

    Args:
        tab: 浏览器标签页对象
        max_retries: 最大重试次数
        retry_interval: 重试间隔时间范围(最小值, 最大值)

    Returns:
        bool: 验证是否成功

    Raises:
        TurnstileError: 验证过程中出现异常
    """
    logging.info("正在检测 Turnstile 验证...")
    save_screenshot(tab, "start")

    retry_count = 0

    try:
        while retry_count < max_retries:
            retry_count += 1
            logging.debug(f"第 {retry_count} 次尝试验证")

            try:
                # 定位验证框元素
                challenge_check = (
                    tab.ele("@id=cf-turnstile", timeout=2)
                    .child()
                    .shadow_root.ele("tag:iframe")
                    .ele("tag:body")
                    .sr("tag:input")
                )

                if challenge_check:
                    logging.info("检测到 Turnstile 验证框，开始处理...")
                    # 随机延时后点击验证
                    time.sleep(random.uniform(1, 3))
                    challenge_check.click()
                    time.sleep(2)

                    # 保存验证后的截图
                    save_screenshot(tab, "clicked")

                    # 检查验证结果
                    if check_verification_success(tab):
                        logging.info("Turnstile 验证通过")
                        save_screenshot(tab, "success")
                        return True

            except Exception as e:
                logging.debug(f"当前尝试未成功: {str(e)}")

            # 检查是否已经验证成功
            if check_verification_success(tab):
                return True

            # 随机延时后继续下一次尝试
            time.sleep(random.uniform(*retry_interval))

        # 超出最大重试次数
        logging.error(f"验证失败 - 已达到最大重试次数 {max_retries}")
        logging.error(
            "请前往开源项目查看更多信息：https://github.com/xiaoxinkeji/cursor-auto"
        )
        save_screenshot(tab, "failed")
        return False

    except Exception as e:
        error_msg = f"Turnstile 验证过程发生异常: {str(e)}"
        logging.error(error_msg)
        save_screenshot(tab, "error")
        raise TurnstileError(error_msg)


def get_cursor_session_token(tab, max_attempts=3, retry_interval=2):
    """
    获取Cursor会话token，带有重试机制
    :param tab: 浏览器标签页
    :param max_attempts: 最大尝试次数
    :param retry_interval: 重试间隔(秒)
    :return: session token 或 None
    """
    logging.info("开始获取cookie")
    attempts = 0

    while attempts < max_attempts:
        try:
            cookies = tab.cookies()
            for cookie in cookies:
                if cookie.get("name") == "WorkosCursorSessionToken":
                    return cookie["value"].split("%3A%3A")[1]

            attempts += 1
            if attempts < max_attempts:
                logging.warning(
                    f"第 {attempts} 次尝试未获取到CursorSessionToken，{retry_interval}秒后重试..."
                )
                time.sleep(retry_interval)
            else:
                logging.error(
                    f"已达到最大尝试次数({max_attempts})，获取CursorSessionToken失败"
                )

        except Exception as e:
            logging.error(f"获取cookie失败: {str(e)}")
            attempts += 1
            if attempts < max_attempts:
                logging.info(f"将在 {retry_interval} 秒后重试...")
                time.sleep(retry_interval)

    return None


def update_cursor_auth(email=None, access_token=None, refresh_token=None):
    """
    更新Cursor的认证信息的便捷函数
    """
    auth_manager = CursorAuthManager()
    return auth_manager.update_auth(email, access_token, refresh_token)


def sign_up_account(browser, tab, sign_up_url, first_name, last_name, account, password, email_handler, settings_url):
    logging.info("=== 开始注册账号流程 ===")
    logging.info(f"正在访问注册页面: {sign_up_url}")
    tab.get(sign_up_url)

    try:
        if tab.ele("@name=first_name"):
            logging.info("正在填写个人信息...")
            tab.actions.click("@name=first_name").input(first_name)
            logging.info(f"已输入名字: {first_name}")
            time.sleep(random.uniform(1, 3))

            tab.actions.click("@name=last_name").input(last_name)
            logging.info(f"已输入姓氏: {last_name}")
            time.sleep(random.uniform(1, 3))

            tab.actions.click("@name=email").input(account)
            logging.info(f"已输入邮箱: {account}")
            time.sleep(random.uniform(1, 3))

            logging.info("提交个人信息...")
            tab.actions.click("@type=submit")

    except Exception as e:
        logging.error(f"注册页面访问失败: {str(e)}")
        return False

    handle_turnstile(tab)

    try:
        if tab.ele("@name=password"):
            logging.info("正在设置密码...")
            tab.ele("@name=password").input(password)
            time.sleep(random.uniform(1, 3))

            logging.info("提交密码...")
            tab.ele("@type=submit").click()
            logging.info("密码设置完成，等待系统响应...")

    except Exception as e:
        logging.error(f"密码设置失败: {str(e)}")
        return False

    if tab.ele("This email is not available."):
        logging.error("注册失败：邮箱已被使用")
        return False

    handle_turnstile(tab)

    while True:
        try:
            if tab.ele("Account Settings"):
                logging.info("注册成功 - 已进入账户设置页面")
                break
            if tab.ele("@data-index=0"):
                logging.info("正在获取邮箱验证码...")
                code = email_handler.get_verification_code()
                if not code:
                    logging.error("获取验证码失败")
                    return False

                logging.info(f"成功获取验证码: {code}")
                logging.info("正在输入验证码...")
                i = 0
                for digit in code:
                    tab.ele(f"@data-index={i}").input(digit)
                    time.sleep(random.uniform(0.1, 0.3))
                    i += 1
                logging.info("验证码输入完成")
                break
        except Exception as e:
            logging.error(f"验证码处理过程出错: {str(e)}")

    handle_turnstile(tab)
    wait_time = random.randint(3, 6)
    for i in range(wait_time):
        logging.info(f"等待系统处理中... 剩余 {wait_time-i} 秒")
        time.sleep(1)

    logging.info("正在获取账户信息...")
    tab.get(settings_url)
    try:
        usage_selector = (
            "css:div.col-span-2 > div > div > div > div > "
            "div:nth-child(1) > div.flex.items-center.justify-between.gap-2 > "
            "span.font-mono.text-sm\\/\\[0\\.875rem\\]"
        )
        usage_ele = tab.ele(usage_selector)
        if usage_ele:
            usage_info = usage_ele.text
            total_usage = usage_info.split("/")[-1].strip()
            logging.info(f"账户可用额度上限: {total_usage}")
            logging.info(
                "请前往开源项目查看更多信息：https://github.com/xiaoxinkeji/cursor-auto"
            )
    except Exception as e:
        logging.error(f"获取账户额度信息失败: {str(e)}")

    logging.info("\n=== 注册完成 ===")
    account_info = f"Cursor 账号信息:\n邮箱: {account}\n密码: {password}"
    logging.info(account_info)
    time.sleep(5)
    return True


class EmailGenerator:
    def __init__(
        self,
        use_official=False,
        password="".join(
            random.choices(
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*",
                k=12,
            )
        ),
    ):
        try:
            # 显式记录使用的配置模式
            logging.info(f"EmailGenerator正在初始化，使用配置模式: {'官方' if use_official else '自定义'}")
            configInstance = Config(use_official=use_official)
            
            # 保存domain和其他必要信息
            self.domain = configInstance.get_domain()
            if not self.domain:  # 如果domain为空，使用默认域名
                logging.warning("配置中的域名为空，使用默认域名")
                self.domain = "xiao89.site"
        except Exception as e:
            # 如果配置加载失败，使用默认值
            logging.error(f"加载配置失败: {e}")
            logging.warning("使用默认域名")
            self.domain = "xiao89.site"
        
        try:
            self.names = self.load_names()
        except Exception as e:
            logging.error(f"加载名称数据集失败: {e}")
            # 提供默认名称列表
            self.names = ["john", "alice", "bob", "emma", "james", "lily", "mike", "sarah"]
            
        self.default_password = password
        self.default_first_name = self.generate_random_name()
        self.default_last_name = self.generate_random_name()

    def load_names(self):
        try:
            with open("names-dataset.txt", "r") as file:
                return file.read().split()
        except Exception as e:
            logging.error(f"无法读取名称数据集: {e}")
            # 提供一个默认的名称列表作为备用
            return ["john", "alice", "bob", "emma", "james", "lily", "mike", "sarah"]

    def generate_random_name(self):
        """生成随机用户名"""
        return random.choice(self.names)

    def generate_email(self, length=4):
        """生成随机邮箱地址"""
        length = random.randint(0, length)  # 生成0到length之间的随机整数
        timestamp = str(int(time.time()))[-length:]  # 使用时间戳后length位
        return f"{self.default_first_name}{timestamp}@{self.domain}"  #

    def get_account_info(self):
        """获取完整的账号信息"""
        return {
            "email": self.generate_email(),
            "password": self.default_password,
            "first_name": self.default_first_name,
            "last_name": self.default_last_name,
        }


def get_user_agent():
    """获取user_agent"""
    try:
        # 使用JavaScript获取user agent
        browser_manager = BrowserManager()
        browser = browser_manager.init_browser()
        user_agent = browser.latest_tab.run_js("return navigator.userAgent")
        browser_manager.quit()
        return user_agent
    except Exception as e:
        logging.error(f"获取user agent失败: {str(e)}")
        return None


def check_cursor_version():
    """检查cursor版本"""
    pkg_path, main_path = patch_cursor_get_machine_id.get_cursor_paths()
    with open(pkg_path, "r", encoding="utf-8") as f:
        version = json.load(f)["version"]
    return patch_cursor_get_machine_id.version_check(version, min_version="0.45.0")


def reset_machine_id_func(greater_than_0_45):
    """
    重置机器码
    """
    if greater_than_0_45:
        # 提示请手动执行脚本 https://github.com/xiaoxinkeji/cursor-auto/blob/main/patch_cursor_get_machine_id.py
        go_cursor_help.go_cursor_help()
    else:
        MachineIDResetter().reset_machine_ids()


def print_end_message():
    logging.info("\n\n\n\n\n")
    logging.info("=" * 30)
    logging.info("所有操作已完成")
    logging.info("=" * 30)
    logging.info(
        "请前往开源项目查看更多信息：https://github.com/xiaoxinkeji/cursor-auto"
    )


def select_config_mode():
    """提示用户选择配置模式，返回是否使用官方配置"""
    # 检查是否在CI环境中
    if os.environ.get('CI') == 'true' or os.environ.get('GITHUB_ACTIONS') == 'true':
        logging.info("检测到CI环境，自动使用官方配置")
        return True
        
    print("\n请选择配置模式:")
    print("1. 官方配置 (使用预配置的QQ邮箱，开箱即用)")
    print("2. 自定义配置 (使用您自己的邮箱配置)")
    
    while True:
        try:
            config_choice = int(input("请输入选项 (1 或 2): ").strip())
            if config_choice in [1, 2]:
                return config_choice == 1
            else:
                print("无效的选项，请重新输入")
        except ValueError:
            print("请输入有效的数字")


def restart_cursor():
    """
    重启Cursor应用
    
    Returns:
        bool: 是否成功重启
    """
    try:
        logging.info("正在准备重启Cursor...")
        # 先确保Cursor已关闭
        ExitCursor()
        
        # 获取Cursor可执行文件路径
        cursor_exec = ""
        if platform.system() == "Windows":
            app_path = os.path.join(os.environ.get("LOCALAPPDATA", ""), "Programs", "Cursor", "Cursor.exe")
            if os.path.exists(app_path):
                cursor_exec = f'"{app_path}"'
        elif platform.system() == "Darwin":  # macOS
            app_path = "/Applications/Cursor.app"
            if os.path.exists(app_path):
                cursor_exec = f'open "{app_path}"'
        else:  # Linux
            app_path = os.path.expanduser("~/.local/share/cursor-browser/cursor-browser")
            if os.path.exists(app_path):
                cursor_exec = f'"{app_path}"'
        
        if cursor_exec:
            logging.info("Cursor已完全关闭，准备重新启动...")
            
            # 通过子进程启动Cursor，不等待其完成
            if platform.system() == "Darwin":  # macOS
                os.system(cursor_exec)
            else:
                import subprocess
                subprocess.Popen(cursor_exec, shell=True)
                
            logging.info("已发送Cursor启动命令")
            return True
        else:
            logging.warning("找不到Cursor可执行文件，无法自动重启")
            return False
    except Exception as e:
        logging.error(f"重启Cursor时出错: {e}")
        return False


def open_default_browser(url):
    """使用系统默认浏览器打开指定URL
    
    Args:
        url: 要打开的URL
        
    Returns:
        bool: 是否成功打开
    """
    try:
        # 使用Python标准库打开默认浏览器
        logging.info(f"正在使用系统默认浏览器打开: {url}")
        webbrowser.open(url)
        return True
    except Exception as e:
        logging.error(f"打开默认浏览器失败: {e}")
        return False


def verify_cursor_login(email):
    """
    验证Cursor是否成功登录指定账号
    
    Args:
        email: 期望登录的邮箱账号
        
    Returns:
        bool: 是否成功登录
    """
    try:
        # 获取Cursor认证数据库路径
        auth_manager = CursorAuthManager()
        
        # 连接数据库并查询登录状态
        conn = sqlite3.connect(auth_manager.db_path)
        cursor = conn.cursor()
        
        # 查询登录邮箱
        cursor.execute("SELECT value FROM itemTable WHERE key = ?", ("cursorAuth/cachedEmail",))
        result = cursor.fetchone()
        
        if result:
            logged_email = result[0]
            
            # 查询认证状态
            cursor.execute("SELECT value FROM itemTable WHERE key = ?", ("cursorAuth/cachedSignUpType",))
            auth_status = cursor.fetchone()
            
            conn.close()
            
            if logged_email == email and auth_status and auth_status[0] == "Auth_0":
                logging.info(f"Cursor成功登录账号: {logged_email}")
                return True
            else:
                if logged_email != email:
                    logging.warning(f"Cursor登录的账号与期望不符: 当前={logged_email}, 期望={email}")
                elif not auth_status or auth_status[0] != "Auth_0":
                    logging.warning("Cursor未处于已登录状态")
                return False
        else:
            logging.warning("未找到Cursor登录信息")
            return False
    except Exception as e:
        logging.error(f"验证Cursor登录状态时出错: {e}")
        return False


def show_main_menu():
    """显示主菜单选项"""
    print("\n请选择操作模式:")
    print("0. 退出程序")
    print("1. 仅重置机器码")
    print("2. 传统注册流程（直接修改数据库）")
    
    while True:
        try:
            choice = input("请输入选项 (0-2): ").strip()
            if choice in ["0", "1", "2"]:
                return int(choice)
            else:
                print("无效的选项，请重新输入")
        except ValueError:
            print("请输入有效的数字")


def reset_machine_id_only(greater_than_0_45):
    """仅执行重置机器码操作"""
    logging.info("开始重置机器码...")
    reset_machine_id_func(greater_than_0_45)
    logging.info("机器码重置完成")
    print_end_message()
    print("\n机器码重置操作完成，按任意键返回主菜单...")
    input()
    return True


def full_registration_process(greater_than_0_45, browser_manager=None):
    """执行完整注册流程（传统方式，直接修改数据库）"""
    try:
        # 是否需要关闭浏览器
        need_close_browser = False
        
        # 如果没有提供browser_manager，创建一个新的
        if browser_manager is None:
            browser_manager = BrowserManager()
            need_close_browser = True
        
        # 选择配置模式
        use_official = select_config_mode()
        
        # 加载配置
        configInstance = Config(use_official=use_official)
        configInstance.print_config()

        if not browser_manager.browser:
            logging.info("正在初始化浏览器...")
            # 获取user_agent
            user_agent = get_user_agent()
            if not user_agent:
                logging.error("获取user agent失败，使用默认值")
                user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

            # 剔除user_agent中的"HeadlessChrome"
            user_agent = user_agent.replace("HeadlessChrome", "Chrome")
            browser = browser_manager.init_browser(user_agent)
        else:
            browser = browser_manager.browser

        # 获取并打印浏览器的user-agent
        user_agent = browser.latest_tab.run_js("return navigator.userAgent")

        logging.info(
            "请前往开源项目查看更多信息：https://github.com/xiaoxinkeji/cursor-auto"
        )
        logging.info("\n=== 配置信息 ===")
        login_url = "https://authenticator.cursor.sh"
        sign_up_url = "https://authenticator.cursor.sh/sign-up"
        settings_url = "https://www.cursor.com/settings"

        logging.info("正在生成随机账号信息...")

        try:
            # 确保使用全局配置实例而不是创建新的配置实例
            email_generator = EmailGenerator(use_official=use_official)
            first_name = email_generator.default_first_name
            last_name = email_generator.default_last_name
            account = email_generator.generate_email()
            password = email_generator.default_password

            logging.info(f"生成的邮箱账号: {account}")

            logging.info("正在初始化邮箱验证模块...")
            email_handler = EmailVerificationHandler(account, use_official=use_official)
        except Exception as e:
            logging.error(f"初始化账号生成器或邮箱验证模块失败: {e}")
            logging.error("可能是配置问题，请确保您的环境配置正确")
            # 尝试继续执行，使用官方配置重试
            logging.info("尝试使用官方配置重试...")
            use_official = True
            configInstance = Config(use_official=True)  # 强制使用官方配置
            email_generator = EmailGenerator(use_official=True)
            first_name = email_generator.default_first_name
            last_name = email_generator.default_last_name
            account = email_generator.generate_email()
            password = email_generator.default_password
            logging.info(f"使用官方配置重新生成的邮箱账号: {account}")
            email_handler = EmailVerificationHandler(account, use_official=True)

        auto_update_cursor_auth = True

        tab = browser.latest_tab

        tab.run_js("try { turnstile.reset() } catch(e) { }")

        logging.info("\n=== 开始注册流程 ===")
        logging.info(f"正在访问登录页面: {login_url}")
        tab.get(login_url)

        if sign_up_account(browser, tab, sign_up_url, first_name, last_name, account, password, email_handler, settings_url):
            logging.info("正在获取会话令牌...")
            token = get_cursor_session_token(tab)
            if token:
                # 使用简化的认证流程
                logging.info("开始执行认证流程...")
                auth_result = update_auth_and_restart(account, token, reset_machine_id=True)
                
                if auth_result:
                    logging.info("认证流程成功！")
                else:
                    logging.warning("认证流程可能未完全成功，请检查Cursor登录状态")
                
                logging.info(
                    "请前往开源项目查看更多信息：https://github.com/xiaoxinkeji/cursor-auto"
                )
                logging.info("所有操作已完成")
                print_end_message()
                
                # 提示用户检查登录状态
                print("\n" + "="*50)
                print("重要提示：")
                print("1. 如果Cursor没有自动重启，请手动启动Cursor")
                print("2. 如果Cursor未显示已登录状态，请重启Cursor")
                print("3. 如果多次尝试后仍无法登录，请手动登录")
                print("="*50 + "\n")
            else:
                logging.error("获取会话令牌失败，注册流程未完成")
        
        # 提示返回主菜单
        print("\n传统注册流程已完成，按任意键返回主菜单...")
        input()
        
        # 如果是新创建的browser_manager，需要关闭
        if need_close_browser:
            browser_manager.quit()
            
        return True
    except Exception as e:
        logging.error(f"注册流程执行出现错误: {str(e)}")
        import traceback
        logging.error(traceback.format_exc())
        
        print("\n注册流程执行出错，请查看日志，按任意键返回主菜单...")
        input()
        return False


def update_auth_and_restart(email, token, reset_machine_id=True):
    """
    简化的认证流程，只执行数据库更新和重启Cursor
    
    Args:
        email: 账号邮箱
        token: 会话令牌
        reset_machine_id: 是否重置机器码
        
    Returns:
        bool: 登录是否成功
    """
    logging.info("开始执行认证流程...")
    
    # 1. 更新数据库
    logging.info("正在更新认证数据库...")
    update_result = update_cursor_auth(email=email, access_token=token, refresh_token=token)
    if not update_result:
        logging.error("更新认证数据库失败")
        return False
    
    # 2. 可选：重置机器码
    if reset_machine_id:
        logging.info("正在重置机器码...")
        greater_than_0_45 = check_cursor_version()
        reset_machine_id_func(greater_than_0_45)
    
    # 3. 重启Cursor
    logging.info("正在重启Cursor...")
    restart_result = restart_cursor()
    if not restart_result:
        logging.error("重启Cursor失败")
        return False
    
    # 4. 等待一段时间让Cursor启动
    wait_time = 10  # 给Cursor一些启动时间
    logging.info(f"等待Cursor启动 ({wait_time} 秒)...")
    time.sleep(wait_time)
    
    # 5. 验证登录状态
    logging.info("正在验证Cursor登录状态...")
    login_success = verify_cursor_login(email)
    
    if login_success:
        logging.info(f"成功验证Cursor登录状态! 账号: {email}")
        return True
    else:
        logging.warning("Cursor登录状态验证失败，可能需要手动检查")
        return False


if __name__ == "__main__":
    print_logo()
    
    # 检查管理员权限并尝试提升权限
    if not is_admin():
        logging.warning("检测到程序未以管理员权限运行，尝试提升权限...")
        if run_as_admin():
            # 如果成功提升权限，新进程已启动，当前进程退出
            sys.exit(0)
        else:
            logging.warning("无法提升至管理员权限，某些功能可能无法正常工作")
    
    greater_than_0_45 = check_cursor_version()
    browser_manager = None
    
    # 检查是否在CI环境中
    is_ci_environment = os.environ.get('CI') == 'true' or os.environ.get('GITHUB_ACTIONS') == 'true'
    
    try:
        logging.info("\n=== 初始化程序 ===")
        ExitCursor()
        
        # 在CI环境中不需要用户交互
        if is_ci_environment:
            logging.info("CI环境：跳过用户交互，仅进行编译")
            sys.exit(0)
            
        # 创建共享的浏览器管理器实例
        browser_manager = BrowserManager()
        
        # 主程序循环
        while True:
            # 显示主菜单并获取用户选择
            choice = show_main_menu()
            
            if choice == 0:
                # 退出程序
                logging.info("用户选择退出程序")
                break
            elif choice == 1:
                # 仅执行重置机器码
                reset_machine_id_only(greater_than_0_45)
            elif choice == 2:
                # 执行传统注册流程，共享浏览器管理器实例
                full_registration_process(greater_than_0_45, browser_manager)
    
    except Exception as e:
        logging.error(f"程序执行出现错误: {str(e)}")
        import traceback
        logging.error(traceback.format_exc())
    finally:
        # 确保退出前关闭浏览器
        if browser_manager:
            browser_manager.quit()
        logging.info("程序已退出")
        print("\n程序已退出，感谢使用！按回车键关闭窗口...")
        input()
