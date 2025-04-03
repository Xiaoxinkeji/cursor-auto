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
    重启Cursor以确保新的认证信息生效
    """
    try:
        logging.info("正在准备重启Cursor...")
        
        # 获取Cursor可执行文件路径
        cursor_exec = None
        if platform.system() == "Windows":
            cursor_path = os.path.join(os.getenv("LOCALAPPDATA", ""), "Programs", "Cursor", "Cursor.exe")
            if os.path.exists(cursor_path):
                cursor_exec = cursor_path
        elif platform.system() == "Darwin":  # macOS
            cursor_path = "/Applications/Cursor.app"
            if os.path.exists(cursor_path):
                cursor_exec = "open -a Cursor"
        elif platform.system() == "Linux":
            # 在Linux上尝试几种可能的路径
            possible_paths = ["/usr/bin/cursor", "/opt/Cursor/cursor"]
            for path in possible_paths:
                if os.path.exists(path):
                    cursor_exec = path
                    break
                    
        if cursor_exec:
            # 先确保Cursor已经关闭
            ExitCursor()
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


def diagnose_login_issues(email, auth_manager=None):
    """
    诊断Cursor登录问题并提供解决方案
    
    Args:
        email: 尝试登录的邮箱账号
        auth_manager: 可选的CursorAuthManager实例
        
    Returns:
        dict: 诊断结果，包含问题和解决方案
    """
    if auth_manager is None:
        auth_manager = CursorAuthManager()
    
    logging.info("开始诊断Cursor登录问题...")
    diagnosis = {
        "problems": [],
        "solutions": [],
        "severity": "未知"  # 可能的值: 低, 中, 高, 严重
    }
    
    try:
        # 检查1: Cursor进程是否正在运行
        cursor_running = False
        try:
            import psutil
            for proc in psutil.process_iter(['name']):
                # 在不同OS上检查进程名
                if platform.system() == "Windows" and "Cursor.exe" in proc.info['name']:
                    cursor_running = True
                    break
                elif platform.system() == "Darwin" and "Cursor" in proc.info['name']:
                    cursor_running = True
                    break
                elif platform.system() == "Linux" and "cursor" in proc.info['name']:
                    cursor_running = True
                    break
        except ImportError:
            logging.warning("无法导入psutil模块，跳过进程检查")
            # 简单检查是否有游标进程
            if platform.system() == "Windows":
                cursor_running = "Cursor.exe" in os.popen("tasklist").read()
            else:
                cursor_running = "cursor" in os.popen("ps -ax").read().lower()
        
        if not cursor_running:
            diagnosis["problems"].append("Cursor进程未运行")
            diagnosis["solutions"].append("请手动启动Cursor应用")
            diagnosis["severity"] = "高"
        
        # 检查2: 认证数据库是否存在且可访问
        db_exists = os.path.exists(auth_manager.db_path)
        if not db_exists:
            diagnosis["problems"].append("Cursor认证数据库不存在")
            diagnosis["solutions"].append("请确保Cursor已正确安装，并至少运行过一次")
            diagnosis["severity"] = "严重"
        else:
            # 检查3: 尝试连接认证数据库
            try:
                conn = sqlite3.connect(auth_manager.db_path)
                cursor = conn.cursor()
                
                # 检查表是否存在
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='itemTable'")
                table_exists = cursor.fetchone() is not None
                
                if not table_exists:
                    diagnosis["problems"].append("Cursor认证数据库结构异常")
                    diagnosis["solutions"].append("Cursor数据库可能已损坏，请重新安装Cursor")
                    diagnosis["severity"] = "严重"
                else:
                    # 检查4: 数据库中是否有登录信息
                    cursor.execute("SELECT value FROM itemTable WHERE key = ?", ("cursorAuth/cachedEmail",))
                    email_result = cursor.fetchone()
                    
                    cursor.execute("SELECT value FROM itemTable WHERE key = ?", ("cursorAuth/cachedSignUpType",))
                    auth_type = cursor.fetchone()
                    
                    if not email_result:
                        diagnosis["problems"].append("Cursor认证数据库中没有邮箱信息")
                        diagnosis["solutions"].append("认证信息未保存，请尝试手动登录")
                        diagnosis["severity"] = "高"
                    else:
                        stored_email = email_result[0]
                        if stored_email != email:
                            diagnosis["problems"].append(f"Cursor认证数据库中的邮箱与期望不符")
                            diagnosis["solutions"].append(f"数据库中存储的是 {stored_email}，而不是 {email}")
                            diagnosis["severity"] = "中"
                        
                        if not auth_type or auth_type[0] != "Auth_0":
                            diagnosis["problems"].append("Cursor认证状态异常")
                            diagnosis["solutions"].append("认证类型不正确，请尝试手动登录")
                            diagnosis["severity"] = "高"
                
                conn.close()
            except sqlite3.Error as e:
                diagnosis["problems"].append(f"无法访问Cursor认证数据库: {e}")
                diagnosis["solutions"].append("Cursor数据库可能已损坏或被锁定，请重启电脑后重试")
                diagnosis["severity"] = "严重"
        
        # 检查5: Cursor数据目录权限
        cursor_dir = os.path.dirname(auth_manager.db_path)
        try:
            # 尝试创建临时文件来检查写入权限
            test_file = os.path.join(cursor_dir, "permission_test.tmp")
            with open(test_file, "w") as f:
                f.write("test")
            os.remove(test_file)
        except (PermissionError, IOError):
            diagnosis["problems"].append("Cursor数据目录权限不足")
            diagnosis["solutions"].append("请以管理员权限运行或修复Cursor数据目录的权限")
            diagnosis["severity"] = "高"
        
        # 如果没有发现任何问题，但登录仍然失败
        if not diagnosis["problems"]:
            diagnosis["problems"].append("未检测到明显问题，但登录验证仍然失败")
            diagnosis["solutions"].append("请尝试重启电脑，或完全重新安装Cursor")
            diagnosis["severity"] = "中"
    except Exception as e:
        logging.error(f"诊断过程中发生错误: {e}")
        diagnosis["problems"].append(f"诊断过程出错: {e}")
        diagnosis["solutions"].append("诊断失败，请尝试重启电脑后重试")
        diagnosis["severity"] = "未知"
    
    return diagnosis


def attempt_auto_repair(diagnosis, email, auth_manager=None):
    """
    尝试自动修复常见的Cursor登录问题
    
    Args:
        diagnosis: 诊断结果字典
        email: 用户邮箱
        auth_manager: 可选的CursorAuthManager实例
        
    Returns:
        bool: 是否成功修复
    """
    if auth_manager is None:
        auth_manager = CursorAuthManager()
    
    # 如果没有问题，不需要修复
    if not diagnosis.get("problems", []):
        return True
    
    print(f"\n{Fore.YELLOW}尝试自动修复...{Style.RESET_ALL}")
    logging.info("开始尝试自动修复登录问题...")
    
    fix_attempted = False
    fixes_applied = []
    
    # 根据诊断结果尝试修复
    for problem in diagnosis.get("problems", []):
        if "进程未运行" in problem:
            # 尝试启动Cursor
            print(f"{Fore.CYAN}• 尝试启动Cursor...{Style.RESET_ALL}")
            if restart_cursor():
                fixes_applied.append("成功启动Cursor")
                fix_attempted = True
            else:
                fixes_applied.append("无法自动启动Cursor，请手动启动")
        
        elif "认证数据库中的邮箱与期望不符" in problem:
            # 尝试更新认证信息
            print(f"{Fore.CYAN}• 尝试更新认证信息...{Style.RESET_ALL}")
            try:
                # 获取当前的access_token和refresh_token
                conn = sqlite3.connect(auth_manager.db_path)
                cursor = conn.cursor()
                
                cursor.execute("SELECT value FROM itemTable WHERE key = ?", ("cursorAuth/accessToken",))
                access_token = cursor.fetchone()
                
                cursor.execute("SELECT value FROM itemTable WHERE key = ?", ("cursorAuth/refreshToken",))
                refresh_token = cursor.fetchone()
                
                conn.close()
                
                if access_token and refresh_token:
                    # 使用现有token更新为新邮箱
                    auth_manager.update_auth_info(
                        email=email,
                        access_token=access_token[0],
                        refresh_token=refresh_token[0]
                    )
                    fixes_applied.append("已更新认证信息中的邮箱")
                    fix_attempted = True
                else:
                    fixes_applied.append("无法获取现有token，无法更新认证信息")
            except Exception as e:
                logging.error(f"更新认证信息时出错: {e}")
                fixes_applied.append(f"更新认证信息失败: {str(e)}")
        
        elif "认证状态异常" in problem:
            # 尝试重置认证状态
            print(f"{Fore.CYAN}• 尝试重置认证状态...{Style.RESET_ALL}")
            try:
                # 重置认证类型为Auth_0
                conn = sqlite3.connect(auth_manager.db_path)
                cursor = conn.cursor()
                
                cursor.execute("UPDATE itemTable SET value = ? WHERE key = ?", 
                               ("Auth_0", "cursorAuth/cachedSignUpType"))
                conn.commit()
                conn.close()
                
                fixes_applied.append("已重置认证状态为Auth_0")
                fix_attempted = True
            except Exception as e:
                logging.error(f"重置认证状态时出错: {e}")
                fixes_applied.append(f"重置认证状态失败: {str(e)}")
        
        elif "权限不足" in problem:
            # 权限问题需要用户手动处理
            fixes_applied.append("权限问题需要以管理员身份重新运行，无法自动修复")
            # 可以提示用户
            if not is_admin():
                print(f"{Fore.YELLOW}• 检测到权限问题，请以管理员身份重新运行{Style.RESET_ALL}")
                fixes_applied.append("请以管理员身份重新运行程序")
        
        elif "数据库不存在" in problem or "数据库结构异常" in problem:
            # 数据库问题通常需要重新运行Cursor
            print(f"{Fore.CYAN}• 尝试重新创建认证数据库...{Style.RESET_ALL}")
            if not os.path.exists(os.path.dirname(auth_manager.db_path)):
                try:
                    os.makedirs(os.path.dirname(auth_manager.db_path), exist_ok=True)
                    fixes_applied.append("已创建数据库目录")
                    fix_attempted = True
                except Exception as e:
                    fixes_applied.append(f"创建数据库目录失败: {str(e)}")
            
            # 尝试启动Cursor以重建数据库
            print(f"{Fore.CYAN}• 尝试启动Cursor以重建数据库...{Style.RESET_ALL}")
            if restart_cursor():
                fixes_applied.append("已启动Cursor，请等待数据库重建")
                fix_attempted = True
            else:
                fixes_applied.append("无法自动启动Cursor，请手动启动")
    
    # 显示修复结果
    if fix_attempted:
        print("\n" + "="*60)
        print(f"{Fore.CYAN}自动修复尝试结果{Style.RESET_ALL}")
        print("-"*60)
        
        for i, fix in enumerate(fixes_applied, 1):
            if "失败" in fix or "无法" in fix:
                print(f"{Fore.RED}{i}. {fix}{Style.RESET_ALL}")
            else:
                print(f"{Fore.GREEN}{i}. {fix}{Style.RESET_ALL}")
        
        print("\n建议在修复后等待几分钟，然后再次运行验证")
        print("="*60 + "\n")
        
        # 如果进行了修复，再次检查
        print(f"{Fore.YELLOW}等待修复生效 (10秒)...{Style.RESET_ALL}")
        time.sleep(10)
        
        print(f"{Fore.CYAN}正在验证修复结果...{Style.RESET_ALL}")
        if verify_cursor_login(email):
            print(f"{Fore.GREEN}✓ 修复成功! Cursor现在已登录到账号: {email}{Style.RESET_ALL}")
            return True
        else:
            print(f"{Fore.RED}✗ 修复后验证仍然失败{Style.RESET_ALL}")
            return False
    else:
        print(f"{Fore.YELLOW}• 没有找到可自动修复的问题{Style.RESET_ALL}")
        return False


def display_diagnosis_results(diagnosis):
    """
    显示诊断结果
    
    Args:
        diagnosis: 诊断结果字典
    """
    severity_colors = {
        "低": Fore.BLUE,
        "中": Fore.YELLOW,
        "高": Fore.MAGENTA,
        "严重": Fore.RED,
        "未知": Fore.WHITE
    }
    
    print("\n" + "="*60)
    print(f"{Fore.CYAN}Cursor登录问题诊断结果{Style.RESET_ALL}")
    print("-"*60)
    
    severity = diagnosis.get("severity", "未知")
    color = severity_colors.get(severity, Fore.WHITE)
    print(f"问题严重性: {color}{severity}{Style.RESET_ALL}")
    
    print("\n发现的问题:")
    for i, problem in enumerate(diagnosis.get("problems", []), 1):
        print(f"{Fore.RED}{i}. {problem}{Style.RESET_ALL}")
    
    print("\n解决方案:")
    for i, solution in enumerate(diagnosis.get("solutions", []), 1):
        print(f"{Fore.GREEN}{i}. {solution}{Style.RESET_ALL}")
    
    print("\n其他建议:")
    print(f"• 确保您的网络连接正常")
    print(f"• 检查Cursor官方服务器状态")
    print(f"• 如果问题持续，可以尝试联系Cursor官方支持或访问社区论坛")
    
    print("="*60 + "\n")
    
    return diagnosis


def monitor_cursor_login_status(email, max_attempts=5, check_interval=5, timeout=60):
    """
    在Cursor重启后监控其登录状态，确保成功加载新账号
    
    Args:
        email: 期望登录的邮箱账号
        max_attempts: 最大检查次数
        check_interval: 检查间隔时间（秒）
        timeout: 总超时时间（秒）
        
    Returns:
        bool: 是否成功验证登录状态
    """
    logging.info(f"开始监控Cursor登录状态，期望账号: {email}")
    print(f"\n{Fore.CYAN}正在监控Cursor登录状态...{Style.RESET_ALL}")
    
    start_time = time.time()
    attempts = 0
    last_error = None
    
    # 计算实际可能的最大尝试次数（基于超时时间和检查间隔）
    max_possible_attempts = min(max_attempts, int(timeout / check_interval) + 1)
    
    # 定义监控阶段和状态
    stages = [
        "检测Cursor进程",
        "等待Cursor完全启动",
        "检查认证数据库",
        "验证登录状态"
    ]
    stage_status = {stage: f"{Fore.YELLOW}等待中{Style.RESET_ALL}" for stage in stages}
    
    # 显示初始状态
    print("\n" + "="*60)
    print(f"{Fore.CYAN}Cursor启动监控{Style.RESET_ALL}")
    for stage in stages:
        print(f"  {stage}: {stage_status[stage]}")
    print("="*60)
    
    # 先等待一段时间，让Cursor有足够时间启动
    initial_wait = min(10, check_interval)
    logging.info(f"等待Cursor启动 ({initial_wait}秒)...")
    
    # 更新第一阶段状态
    stage_status[stages[0]] = f"{Fore.CYAN}进行中{Style.RESET_ALL}"
    _update_monitor_display(stages, stage_status)
    
    time.sleep(initial_wait)
    
    # 第一阶段完成
    stage_status[stages[0]] = f"{Fore.GREEN}已完成{Style.RESET_ALL}"
    _update_monitor_display(stages, stage_status)
    
    while attempts < max_possible_attempts and (time.time() - start_time) < timeout:
        attempts += 1
        
        # 显示进度
        remaining = max_possible_attempts - attempts
        time_elapsed = time.time() - start_time
        time_remaining = max(0, timeout - time_elapsed)
        
        # 更新当前阶段
        current_stage = min(attempts // 2 + 1, len(stages) - 1)
        for i in range(1, current_stage + 1):
            if stage_status[stages[i]] == f"{Fore.YELLOW}等待中{Style.RESET_ALL}":
                stage_status[stages[i]] = f"{Fore.CYAN}进行中{Style.RESET_ALL}"
        
        _update_monitor_display(stages, stage_status, 
                              progress=f"{attempts}/{max_possible_attempts}", 
                              remaining=f"{int(time_remaining)}秒")
        
        try:
            # 尝试验证登录状态
            if verify_cursor_login(email):
                # 所有阶段标记为成功
                for stage in stages:
                    stage_status[stage] = f"{Fore.GREEN}已完成{Style.RESET_ALL}"
                
                _update_monitor_display(stages, stage_status, 
                                      progress=f"{attempts}/{max_possible_attempts}", 
                                      remaining="完成")
                
                print("\n" + "="*60)
                print(f"{Fore.GREEN}✓ 成功验证Cursor登录状态!{Style.RESET_ALL}")
                print(f"  账号: {email}")
                print("="*60 + "\n")
                
                logging.info(f"成功验证Cursor登录状态! 账号: {email}")
                return True
            
            # 如果验证失败但Cursor可能还在启动中，等待下一次检查
            if attempts < max_possible_attempts:
                time.sleep(check_interval)
        except Exception as e:
            last_error = str(e)
            logging.error(f"验证登录状态时出错: {e}")
            
            # 更新当前阶段为错误
            stage_status[stages[current_stage]] = f"{Fore.RED}错误{Style.RESET_ALL}"
            _update_monitor_display(stages, stage_status, 
                                  progress=f"{attempts}/{max_possible_attempts}", 
                                  remaining=f"{int(time_remaining)}秒")
            
            if attempts < max_possible_attempts:
                time.sleep(check_interval)
    
    # 所有尝试都失败，打印详细错误和建议
    # 标记未完成的阶段为失败
    for stage in stages:
        if stage_status[stage] != f"{Fore.GREEN}已完成{Style.RESET_ALL}":
            stage_status[stage] = f"{Fore.RED}失败{Style.RESET_ALL}"
    
    _update_monitor_display(stages, stage_status, 
                          progress=f"{attempts}/{max_possible_attempts}", 
                          remaining="超时")
    
    logging.warning(f"在{attempts}次尝试后仍未能验证Cursor登录状态")
    
    if last_error:
        logging.error(f"最后一次错误: {last_error}")
    
    # 执行深度诊断
    print(f"\n{Fore.YELLOW}正在进行深度诊断...{Style.RESET_ALL}")
    try:
        diagnosis = diagnose_login_issues(email)
        display_diagnosis_results(diagnosis)
        
        # 尝试自动修复
        print(f"\n{Fore.YELLOW}是否尝试自动修复问题? (y/n){Style.RESET_ALL}")
        choice = input().strip().lower()
        if choice == 'y':
            if attempt_auto_repair(diagnosis, email):
                print(f"{Fore.GREEN}✓ 问题已成功修复!{Style.RESET_ALL}")
                return True
            else:
                print(f"{Fore.RED}✗ 自动修复未能解决问题{Style.RESET_ALL}")
    except Exception as e:
        logging.error(f"执行诊断时出错: {e}")
        print(f"{Fore.RED}诊断过程出错，无法提供详细问题报告{Style.RESET_ALL}")
    
    # 提供故障排除建议
    print("\n" + "="*60)
    print(f"{Fore.RED}✗ 登录状态验证失败{Style.RESET_ALL}，请尝试以下步骤:")
    print("1. 确保Cursor已完全启动")
    print("2. 重启Cursor并等待几分钟")
    print("3. 如果问题仍然存在，请手动登录以下账号:")
    print(f"   邮箱: {email}")
    print(f"   密码: *已隐藏，请参考前面的账号信息*")
    print("4. 如果手动登录也失败，请尝试使用机器码重置工具")
    print("="*60 + "\n")
    
    return False


def _update_monitor_display(stages, stage_status, progress=None, remaining=None):
    """
    更新监控显示界面
    """
    # 清空之前的显示（仅上移到之前的位置）
    print(f"\033[{len(stages) + 4}A", end="")
    
    # 重新显示标题和所有阶段
    print("\r" + "="*60 + " "*20)
    print(f"\r{Fore.CYAN}Cursor启动监控{Style.RESET_ALL}" + " "*40)
    
    for stage in stages:
        print(f"\r  {stage}: {stage_status[stage]}" + " "*40)
    
    # 显示进度信息
    progress_info = ""
    if progress:
        progress_info += f"进度: {progress} "
    if remaining:
        progress_info += f"剩余时间: {remaining}"
    
    print(f"\r  {progress_info}" + " "*40)
    print("\r" + "="*60 + " "*20)


def show_main_menu():
    """显示主菜单选项"""
    print("\n请选择操作模式:")
    print("0. 退出程序")
    print("1. 仅重置机器码")
    print("2. 传统注册流程（直接修改数据库）")
    print("3. 混合认证注册流程（尝试两种方式）")
    print("4. 启动登录状态监控")
    
    while True:
        try:
            choice = input("请输入选项 (0-4): ").strip()
            if choice in ["0", "1", "2", "3", "4"]:
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
        use_official_config = select_config_mode()
        
        # 加载配置
        configInstance = Config(use_official=use_official_config)
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
            email_generator = EmailGenerator(use_official=use_official_config)
            first_name = email_generator.default_first_name
            last_name = email_generator.default_last_name
            account = email_generator.generate_email()
            password = email_generator.default_password

            logging.info(f"生成的邮箱账号: {account}")

            logging.info("正在初始化邮箱验证模块...")
            email_handler = EmailVerificationHandler(account, use_official=use_official_config)
        except Exception as e:
            logging.error(f"初始化账号生成器或邮箱验证模块失败: {e}")
            logging.error("可能是配置问题，请确保您的环境配置正确")
            # 尝试继续执行，使用官方配置重试
            logging.info("尝试使用官方配置重试...")
            use_official_config = True
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
                # 使用增强的认证流程
                logging.info("开始执行增强认证流程...")
                auth_result = enhanced_auth_process(account, password, token, reset_machine_id=True)
                
                if auth_result:
                    logging.info("增强认证流程成功！")
                else:
                    logging.warning("增强认证流程可能未完全成功，请检查Cursor登录状态")
                
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


def enhanced_auth_process(email, password, token, reset_machine_id=True):
    """
    增强的认证处理流程，整合数据库直接更新和保持浏览器登录两种方式
    
    这个函数执行以下步骤：
    1. 直接更新 SQLite 数据库中的认证信息（传统方式）
    2. 确保浏览器处于登录状态（支持可能存在的浏览器认证机制）
    3. 重启 Cursor 应用
    4. 保持浏览器一段时间后关闭
    5. 监控登录状态
    
    Args:
        email: 账号邮箱
        password: 账号密码，用于保持浏览器登录状态
        token: 会话令牌
        reset_machine_id: 是否重置机器码
        
    Returns:
        bool: 登录是否成功
    """
    logging.info("开始执行增强认证流程...")
    
    # 1. 先直接更新数据库（传统方式）
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
    
    # 3. 在重启Cursor前，确保浏览器处于登录状态
    logging.info("准备浏览器环境，保持登录状态...")
    browser_manager = BrowserManager()
    try:
        browser = browser_manager.init_browser()
        tab = browser.latest_tab
        
        # 访问登录页面并确保登录
        login_url = "https://authenticator.cursor.sh"
        tab.get(login_url)
        
        # 检查是否需要登录
        if tab.ele("@name=email", timeout=5):
            logging.info("浏览器未登录，执行登录流程...")
            # 输入邮箱
            tab.ele("@name=email").input(email)
            time.sleep(random.uniform(1, 2))
            
            # 点击下一步按钮
            tab.ele("@type=submit").click()
            time.sleep(3)
            
            # 处理Turnstile验证
            handle_turnstile(tab)
            
            # 输入密码
            if tab.ele("@name=password", timeout=10):
                tab.ele("@name=password").input(password)
                time.sleep(random.uniform(1, 2))
                
                # 提交密码
                tab.ele("@type=submit").click()
                time.sleep(3)
                
                # 处理Turnstile验证
                handle_turnstile(tab)
                
                # 检查是否登录成功
                login_success = False
                if tab.ele("Account Settings", timeout=10) or tab.ele("User Profile", timeout=2):
                    login_success = True
                    logging.info("浏览器已成功登录")
                elif "dashboard" in tab.url or "cursors" in tab.url:
                    login_success = True
                    logging.info("浏览器已成功登录")
                
                if not login_success:
                    logging.warning("浏览器登录可能失败，但将继续尝试")
            else:
                logging.warning("无法输入密码，浏览器可能已登录或存在问题")
        else:
            logging.info("浏览器可能已处于登录状态")
            
        # 访问授权页面以保持登录状态明显
        tab.get("https://www.cursor.com/settings")
        time.sleep(2)
        
        # 4. 重启Cursor
        logging.info("浏览器已准备就绪，现在重启Cursor...")
        restart_result = restart_cursor()
        if not restart_result:
            logging.error("重启Cursor失败")
            return False
        
        # 5. 在Cursor启动后，保持浏览器一段时间，再关闭
        wait_time = 30  # 给Cursor足够时间启动并可能访问浏览器
        logging.info(f"保持浏览器打开 {wait_time} 秒，让Cursor有机会访问...")
        
        for i in range(wait_time):
            if i % 5 == 0:  # 每5秒输出一次日志
                logging.info(f"浏览器将保持打开，还剩 {wait_time - i} 秒...")
            time.sleep(1)
            
    except Exception as e:
        logging.error(f"浏览器操作过程出错: {e}")
        import traceback
        logging.error(traceback.format_exc())
    finally:
        # 关闭浏览器
        logging.info("正在关闭浏览器...")
        browser_manager.quit()
    
    # 6. 监控登录状态
    logging.info("开始监控Cursor登录状态...")
    return monitor_cursor_login_status(email)


def hybrid_registration_process(greater_than_0_45, browser_manager=None):
    """
    混合认证方式的注册流程，同时尝试数据库直接更新和浏览器认证
    
    Args:
        greater_than_0_45: Cursor版本是否大于0.45
        browser_manager: 可选的浏览器管理器实例
        
    Returns:
        bool: 是否成功
    """
    try:
        # 是否需要关闭浏览器
        need_close_browser = False
        
        # 如果没有提供browser_manager，创建一个新的
        if browser_manager is None:
            browser_manager = BrowserManager()
            need_close_browser = True
        
        # 选择配置模式
        use_official_config = select_config_mode()
        
        # 加载配置
        configInstance = Config(use_official=use_official_config)
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
            email_generator = EmailGenerator(use_official=use_official_config)
            first_name = email_generator.default_first_name
            last_name = email_generator.default_last_name
            account = email_generator.generate_email()
            password = email_generator.default_password

            logging.info(f"生成的邮箱账号: {account}")

            logging.info("正在初始化邮箱验证模块...")
            email_handler = EmailVerificationHandler(account, use_official=use_official_config)
        except Exception as e:
            logging.error(f"初始化账号生成器或邮箱验证模块失败: {e}")
            logging.error("可能是配置问题，请确保您的环境配置正确")
            # 尝试继续执行，使用官方配置重试
            logging.info("尝试使用官方配置重试...")
            use_official_config = True
            configInstance = Config(use_official=True)  # 强制使用官方配置
            email_generator = EmailGenerator(use_official=True)
            first_name = email_generator.default_first_name
            last_name = email_generator.default_last_name
            account = email_generator.generate_email()
            password = email_generator.default_password
            logging.info(f"使用官方配置重新生成的邮箱账号: {account}")
            email_handler = EmailVerificationHandler(account, use_official=True)

        tab = browser.latest_tab
        tab.run_js("try { turnstile.reset() } catch(e) { }")

        logging.info("\n=== 开始注册流程 ===")
        logging.info(f"正在访问登录页面: {login_url}")
        tab.get(login_url)

        if sign_up_account(browser, tab, sign_up_url, first_name, last_name, account, password, email_handler, settings_url):
            logging.info("正在获取会话令牌...")
            token = get_cursor_session_token(tab)
            if token:
                # 使用增强的认证流程
                logging.info("开始执行增强认证流程...")
                auth_result = enhanced_auth_process(account, password, token, reset_machine_id=True)
                
                if auth_result:
                    logging.info("增强认证流程成功！")
                else:
                    logging.warning("增强认证流程可能未完全成功，请检查Cursor登录状态")
                
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
        print("\n混合认证注册流程已完成，按任意键返回主菜单...")
        input()
        
        # 如果是新创建的browser_manager，需要关闭
        if need_close_browser:
            browser_manager.quit()
            
        return True
    except Exception as e:
        logging.error(f"混合认证注册流程执行出现错误: {str(e)}")
        import traceback
        logging.error(traceback.format_exc())
        
        print("\n注册流程执行出错，请查看日志，按任意键返回主菜单...")
        input()
        return False


class CursorLoginMonitor:
    """Cursor登录状态监控器，定期检查登录状态并自动重新登录"""
    
    def __init__(self, email, password, check_interval=30*60, retry_interval=5*60, reset_machine_id=True):
        """
        初始化监控器
        
        Args:
            email: 账号邮箱
            password: 账号密码
            check_interval: 检查间隔时间（秒），默认30分钟
            retry_interval: 重试间隔时间（秒），默认5分钟
            reset_machine_id: 是否在重新登录时重置机器码
        """
        self.email = email
        self.password = password
        self.check_interval = check_interval
        self.retry_interval = retry_interval
        self.reset_machine_id = reset_machine_id
        self.running = False
        self.thread = None
        self.last_check_time = 0
        self.login_attempts = 0
        self.successful_logins = 0
        
    def start_monitoring(self):
        """启动监控线程"""
        if self.thread and self.thread.is_alive():
            logging.warning("监控已在运行中")
            return False
            
        self.running = True
        self.thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.thread.start()
        logging.info(f"已启动Cursor登录状态监控，检查间隔: {self.check_interval/60} 分钟")
        return True
        
    def stop_monitoring(self):
        """停止监控线程"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        logging.info("Cursor登录状态监控已停止")
        return True
        
    def _monitoring_loop(self):
        """监控主循环"""
        # 首次立即检查
        self._check_login_status()
        
        while self.running:
            try:
                # 等待下一次检查
                time.sleep(self.check_interval)
                if not self.running:
                    break
                
                # 检查登录状态
                self._check_login_status()
            except Exception as e:
                logging.error(f"监控过程出错: {e}")
                # 如果发生错误，等待一段时间后继续
                time.sleep(self.retry_interval)
    
    def _check_login_status(self):
        """检查登录状态并在必要时重新登录"""
        try:
            # 更新最后检查时间
            self.last_check_time = time.time()
            
            # 检查当前是否登录
            if not verify_cursor_login(self.email):
                logging.warning(f"检测到账号 {self.email} 已登出，尝试重新登录")
                self._attempt_relogin()
            else:
                logging.info(f"账号 {self.email} 登录状态正常，JWT 有效")
        except Exception as e:
            logging.error(f"检查登录状态时出错: {e}")
                
    def _attempt_relogin(self):
        """尝试重新登录"""
        try:
            self.login_attempts += 1
            logging.info(f"开始第 {self.login_attempts} 次重新登录尝试")
            
            # 调用自动重新登录函数
            if auto_relogin(self.email, self.password, self.reset_machine_id):
                self.successful_logins += 1
                logging.info(f"重新登录成功 (成功次数: {self.successful_logins})")
            else:
                logging.error("重新登录失败")
                # 如果失败，等待一段时间再重试
                time.sleep(self.retry_interval)
        except Exception as e:
            logging.error(f"重新登录过程出错: {e}")
            time.sleep(self.retry_interval)
    
    def get_status(self):
        """获取监控状态信息"""
        return {
            "running": self.running,
            "email": self.email,
            "last_check": self.last_check_time,
            "login_attempts": self.login_attempts,
            "successful_logins": self.successful_logins,
            "check_interval_minutes": self.check_interval / 60
        }


def auto_relogin(email, password, reset_machine_id=True):
    """
    自动重新登录Cursor
    
    Args:
        email: 账号邮箱
        password: 账号密码
        reset_machine_id: 是否重置机器码
        
    Returns:
        bool: 是否成功登录
    """
    browser_manager = None
    try:
        # 初始化浏览器
        browser_manager = BrowserManager()
        browser = browser_manager.init_browser()
        tab = browser.latest_tab
        
        # 访问登录页面
        login_url = "https://authenticator.cursor.sh"
        tab.get(login_url)
        
        # 等待登录表单加载
        if tab.ele("@name=email", timeout=10):
            # 输入邮箱
            tab.ele("@name=email").input(email)
            time.sleep(random.uniform(1, 2))
            
            # 点击下一步按钮
            tab.ele("@type=submit").click()
            time.sleep(3)
            
            # 处理Turnstile验证
            handle_turnstile(tab)
            
            # 输入密码
            if tab.ele("@name=password", timeout=10):
                tab.ele("@name=password").input(password)
                time.sleep(random.uniform(1, 2))
                
                # 提交密码
                tab.ele("@type=submit").click()
                time.sleep(3)
                
                # 处理Turnstile验证
                handle_turnstile(tab)
                
                # 检查是否登录成功 - 尝试多种验证方式
                login_success = False
                
                # 方式1: 检查是否跳转到账户设置页面
                if tab.ele("Account Settings", timeout=10) or tab.ele("User Profile", timeout=2):
                    login_success = True
                    logging.info("已检测到账户设置页面，登录成功")
                
                # 方式2: 检查URL是否包含dashboard
                elif "dashboard" in tab.url or "cursors" in tab.url:
                    login_success = True
                    logging.info("已检测到仪表盘页面，登录成功")
                
                if login_success:
                    # 获取新的会话令牌
                    token = get_cursor_session_token(tab)
                    if token:
                        # 是否需要重置机器码
                        if reset_machine_id:
                            logging.info("正在重置机器码...")
                            greater_than_0_45 = check_cursor_version()
                            reset_machine_id_func(greater_than_0_45)
                        
                        # 更新认证信息
                        if update_cursor_auth(email=email, access_token=token, refresh_token=token):
                            logging.info("成功更新Cursor认证信息")
                            # 重启Cursor以应用新的认证信息
                            restart_cursor()
                            return True
                        else:
                            logging.error("更新认证信息失败")
                    else:
                        logging.error("获取会话令牌失败")
                else:
                    logging.error("登录验证失败，未检测到成功登录标志")
            else:
                logging.error("未找到密码输入框")
        else:
            logging.error("未找到邮箱输入框")
        
        return False
    except Exception as e:
        logging.error(f"自动登录过程出错: {e}")
        import traceback
        logging.error(traceback.format_exc())
        return False
    finally:
        # 确保关闭浏览器
        if browser_manager:
            browser_manager.quit()


def start_login_monitor():
    """启动Cursor登录状态监控服务"""
    # 获取认证信息
    auth_manager = CursorAuthManager()
    try:
        conn = sqlite3.connect(auth_manager.db_path)
        cursor = conn.cursor()
        
        # 获取当前登录的邮箱
        cursor.execute("SELECT value FROM itemTable WHERE key = ?", ("cursorAuth/cachedEmail",))
        result = cursor.fetchone()
        
        if not result:
            logging.error("未找到已登录的邮箱，请先完成注册流程")
            print(f"\n{Fore.RED}错误: 未找到已登录的账号，请先完成注册流程{Style.RESET_ALL}")
            return False
            
        email = result[0]
        
        # 提示用户输入密码
        print(f"\n请为账号 {email} 输入密码以启动监控服务:")
        password = input("密码: ").strip()
        
        if not password:
            logging.error("密码不能为空")
            print(f"\n{Fore.RED}错误: 密码不能为空{Style.RESET_ALL}")
            return False
        
        # 让用户设置自定义的检查间隔
        check_interval = 30  # 默认30分钟
        print("\n设置检查间隔时间 (分钟):")
        print("JWT令牌有效期约为2小时，建议设置为30-60分钟")
        try:
            interval_input = input(f"请输入检查间隔 (直接回车使用默认值 {check_interval} 分钟): ").strip()
            if interval_input:
                check_interval = max(5, min(120, int(interval_input)))  # 限制在5-120分钟范围内
        except ValueError:
            logging.warning(f"无效的间隔时间，使用默认值 {check_interval} 分钟")
        
        # 让用户设置是否在登出时自动重置机器码
        should_reset_machine_id = True
        print("\n是否在检测到登出时自动重置机器码? (y/n):")
        print("重置机器码可以解决某些登录问题，但可能需要管理员权限")
        reset_input = input("请选择 (默认是): ").strip().lower()
        if reset_input and reset_input == 'n':
            should_reset_machine_id = False
        
        # 创建并启动监控器
        monitor = CursorLoginMonitor(email, password, check_interval=check_interval*60, reset_machine_id=should_reset_machine_id)
        if monitor.start_monitoring():
            logging.info(f"已启动对账号 {email} 的监控服务，检查间隔: {check_interval} 分钟")
            print(f"\n{Fore.GREEN}监控服务已在后台启动!{Style.RESET_ALL}")
            print("程序将继续在后台检查登录状态，并在必要时自动重新登录。")
            print(f"检查间隔: {check_interval} 分钟")
            print("\n按 Ctrl+C 停止监控服务")
            
            # 开始运行监控主循环
            try:
                # 显示监控状态
                while monitor.running:
                    time.sleep(60)  # 每分钟更新一次状态
                    status = monitor.get_status()
                    elapsed = time.time() - status["last_check"]
                    next_check = max(0, monitor.check_interval - elapsed)
                    
                    # 清除上一次的状态显示
                    print("\033[4A", end="")
                    print("\r" + " "*80)
                    print("\r" + " "*80)
                    print("\r" + " "*80)
                    print("\r" + " "*80)
                    
                    # 显示新的状态
                    print(f"\r当前监控账号: {status['email']}")
                    print(f"\r检查间隔: {status['check_interval_minutes']:.1f} 分钟")
                    print(f"\r登录尝试次数: {status['login_attempts']} | 成功次数: {status['successful_logins']}")
                    print(f"\r下次检查: {next_check/60:.1f} 分钟后")
            except KeyboardInterrupt:
                monitor.stop_monitoring()
                print("\n监控服务已停止")
            
            return True
        else:
            logging.error("启动监控服务失败")
            return False
    except Exception as e:
        logging.error(f"启动监控服务时出错: {e}")
        import traceback
        logging.error(traceback.format_exc())
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
            elif choice == 3:
                # 执行混合认证注册流程，共享浏览器管理器实例
                hybrid_registration_process(greater_than_0_45, browser_manager)
            elif choice == 4:
                # 启动登录状态监控
                start_login_monitor()
    
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
