import os
import platform
import sqlite3
import json
import time
import shutil
import logging
import subprocess
from typing import Dict, List, Any, Optional, Tuple
from colorama import Fore, Style

from cursor_auth_manager import CursorAuthManager

class CursorRecoveryManager:
    """
    Cursor故障恢复管理器
    
    负责诊断和修复Cursor相关的各种问题，包括：
    1. 系统环境问题
    2. Cursor安装问题
    3. 网络连接问题
    4. 认证数据库问题
    5. 配置问题
    """
    
    def __init__(self, auth_manager=None):
        """
        初始化恢复管理器
        
        Args:
            auth_manager: 可选的CursorAuthManager实例
        """
        self.auth_manager = auth_manager or CursorAuthManager()
        self.recovery_log = []
        self.last_diagnosis = None
        self.system = platform.system()
        self.backup_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), "recovery_backups")
        
        # 确保备份文件夹存在
        if not os.path.exists(self.backup_folder):
            try:
                os.makedirs(self.backup_folder, exist_ok=True)
            except Exception as e:
                logging.error(f"创建备份文件夹失败: {e}")
    
    def check_system_requirements(self) -> Dict[str, Any]:
        """
        检查系统环境是否满足运行Cursor的要求
        
        检查项目包括：
        1. 操作系统兼容性
        2. 管理员/root权限
        3. 必要的系统依赖
        4. 磁盘空间
        5. 目录权限
        
        Returns:
            Dict: 包含检查结果的字典
        """
        results = {
            "status": "passed",  # 可能的值: passed, warning, failed
            "issues": [],
            "details": {}
        }
        
        # 检查1: 操作系统兼容性
        os_check = self._check_os_compatibility()
        results["details"]["os_compatibility"] = os_check
        if not os_check["compatible"]:
            results["status"] = "failed"
            results["issues"].append(f"不兼容的操作系统: {os_check['os_name']}")
        
        # 检查2: 管理员/root权限
        admin_check = self._check_admin_privileges()
        results["details"]["admin_privileges"] = admin_check
        if not admin_check["has_admin"]:
            if admin_check["required"]:
                results["status"] = "failed"
                results["issues"].append("缺少必要的管理员权限")
            else:
                if results["status"] != "failed":
                    results["status"] = "warning"
                results["issues"].append("建议使用管理员权限运行")
        
        # 检查3: 必要的系统依赖
        dependency_check = self._check_system_dependencies()
        results["details"]["dependencies"] = dependency_check
        if dependency_check["missing_dependencies"]:
            if results["status"] != "failed":
                results["status"] = "warning"
            deps_str = ", ".join(dependency_check["missing_dependencies"])
            results["issues"].append(f"缺少系统依赖: {deps_str}")
        
        # 检查4: 磁盘空间
        disk_check = self._check_disk_space()
        results["details"]["disk_space"] = disk_check
        if not disk_check["sufficient"]:
            if disk_check["critical"]:
                results["status"] = "failed"
                results["issues"].append(f"磁盘空间严重不足: 仅剩 {disk_check['available_mb']}MB")
            else:
                if results["status"] != "failed":
                    results["status"] = "warning"
                results["issues"].append(f"磁盘空间不足: 仅剩 {disk_check['available_mb']}MB")
        
        # 检查5: 目录权限
        permission_check = self._check_directory_permissions()
        results["details"]["directory_permissions"] = permission_check
        if permission_check["permission_issues"]:
            if results["status"] != "failed":
                results["status"] = "warning"
            issues_str = ", ".join([f"{dir}: {issue}" for dir, issue in permission_check["permission_issues"].items()])
            results["issues"].append(f"目录权限问题: {issues_str}")
        
        # 记录检查结果
        action = "系统环境检查"
        success = results["status"] != "failed"
        details = f"结果: {results['status']}, 发现问题: {len(results['issues'])}"
        self._log_recovery_action(action, success, details)
        
        return results
    
    def _check_os_compatibility(self) -> Dict[str, Any]:
        """检查操作系统兼容性"""
        os_name = platform.system()
        os_version = platform.version()
        os_release = platform.release()
        
        result = {
            "os_name": os_name,
            "os_version": os_version,
            "os_release": os_release,
            "compatible": True,
            "details": ""
        }
        
        # Cursor支持的操作系统
        if os_name == "Windows":
            # Windows 7及以上版本
            try:
                major_version = int(platform.version().split('.')[0])
                if major_version < 6:  # Windows 7是6.1
                    result["compatible"] = False
                    result["details"] = "Cursor需要Windows 7或更高版本"
            except Exception:
                # 如果版本解析失败，假设兼容
                result["details"] = "无法确定Windows版本，假设兼容"
        elif os_name == "Darwin":  # macOS
            try:
                # macOS版本格式通常是10.xx.xx或11.xx.xx
                major_version = int(platform.mac_ver()[0].split('.')[0])
                minor_version = int(platform.mac_ver()[0].split('.')[1])
                
                if major_version < 10 or (major_version == 10 and minor_version < 15):
                    # Cursor可能需要macOS 10.15 (Catalina)或更高版本
                    result["compatible"] = False
                    result["details"] = "Cursor需要macOS 10.15 (Catalina)或更高版本"
            except Exception:
                result["details"] = "无法确定macOS版本，假设兼容"
        elif os_name == "Linux":
            # 对于Linux，检查常见的发行版
            try:
                import distro
                distro_name = distro.name()
                distro_version = distro.version()
                result["distro_name"] = distro_name
                result["distro_version"] = distro_version
                
                # 目前假设大多数现代Linux发行版都兼容
                result["details"] = f"检测到Linux发行版: {distro_name} {distro_version}"
            except ImportError:
                result["details"] = "无法确定Linux发行版，假设兼容"
        else:
            result["compatible"] = False
            result["details"] = f"不支持的操作系统: {os_name}"
        
        return result
    
    def _check_admin_privileges(self) -> Dict[str, bool]:
        """检查是否具有管理员/root权限"""
        result = {
            "has_admin": False,
            "required": True  # 大多数情况下Cursor操作需要管理员权限
        }
        
        try:
            if self.system == "Windows":
                import ctypes
                result["has_admin"] = ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:  # macOS和Linux
                result["has_admin"] = os.geteuid() == 0
        except Exception:
            # 如果检查失败，假设没有管理员权限
            pass
        
        return result
    
    def _check_system_dependencies(self) -> Dict[str, Any]:
        """检查必要的系统依赖"""
        result = {
            "dependencies_checked": [],
            "missing_dependencies": []
        }
        
        # 根据不同操作系统检查特定依赖
        if self.system == "Windows":
            # Windows通常依赖VC++运行库等
            dependencies = ["vcruntime140.dll"]
            for dep in dependencies:
                result["dependencies_checked"].append(dep)
                # 简单检查，实际应该更复杂
                if not self._check_windows_dll_exists(dep):
                    result["missing_dependencies"].append(dep)
        
        elif self.system == "Darwin":  # macOS
            # macOS可能需要检查特定框架
            pass
        
        elif self.system == "Linux":
            # Linux检查常见库
            dependencies = ["libssl.so", "libcrypto.so"]
            for dep in dependencies:
                result["dependencies_checked"].append(dep)
                if not self._check_linux_lib_exists(dep):
                    result["missing_dependencies"].append(dep)
        
        return result
    
    def _check_windows_dll_exists(self, dll_name: str) -> bool:
        """检查Windows DLL是否存在"""
        # 这是简化版，实际应该检查系统路径
        return True  # 简化实现，假设存在
    
    def _check_linux_lib_exists(self, lib_name: str) -> bool:
        """检查Linux库是否存在"""
        try:
            output = subprocess.check_output(["ldconfig", "-p"], universal_newlines=True)
            return lib_name in output
        except Exception:
            return True  # 如果检查失败，假设存在
    
    def _check_disk_space(self) -> Dict[str, Any]:
        """检查磁盘空间"""
        cursor_dir = os.path.dirname(self.auth_manager.db_path)
        
        result = {
            "path": cursor_dir,
            "available_mb": 0,
            "required_mb": 100,  # 假设需要100MB
            "sufficient": True,
            "critical": False
        }
        
        try:
            if os.path.exists(cursor_dir):
                if self.system == "Windows":
                    # Windows特定的空间检查
                    free_bytes = ctypes.c_ulonglong(0)
                    ctypes.windll.kernel32.GetDiskFreeSpaceExW(
                        ctypes.c_wchar_p(cursor_dir), None, None, 
                        ctypes.pointer(free_bytes)
                    )
                    result["available_mb"] = free_bytes.value // (1024 * 1024)
                else:
                    # Unix系统使用os.statvfs
                    stats = os.statvfs(cursor_dir)
                    result["available_mb"] = (stats.f_bavail * stats.f_frsize) // (1024 * 1024)
                
                # 检查空间是否足够
                result["sufficient"] = result["available_mb"] >= result["required_mb"]
                result["critical"] = result["available_mb"] < (result["required_mb"] // 2)
        except Exception as e:
            logging.error(f"检查磁盘空间失败: {e}")
            # 如果检查失败，假设空间足够
            result["available_mb"] = "未知"
            result["sufficient"] = True
            result["critical"] = False
            result["error"] = str(e)
        
        return result
    
    def _check_directory_permissions(self) -> Dict[str, Any]:
        """检查目录权限"""
        cursor_dirs = [
            os.path.dirname(self.auth_manager.db_path),  # 认证数据库目录
            os.path.expanduser("~/.cursor")  # 假设的配置目录
        ]
        
        result = {
            "directories_checked": cursor_dirs,
            "permission_issues": {}
        }
        
        for directory in cursor_dirs:
            if os.path.exists(directory):
                # 测试写入权限
                test_file = os.path.join(directory, "permission_test.tmp")
                try:
                    with open(test_file, "w") as f:
                        f.write("test")
                    os.remove(test_file)
                except Exception as e:
                    result["permission_issues"][directory] = str(e)
        
        return result
    
    def check_cursor_installation(self) -> Dict[str, Any]:
        """
        验证Cursor安装是否完整
        
        检查项目包括：
        1. Cursor可执行文件存在性
        2. 关键文件/目录完整性
        3. 版本信息
        4. 安装路径正确性
        
        Returns:
            Dict: 包含验证结果的字典
        """
        results = {
            "status": "passed",  # 可能的值: passed, warning, failed
            "issues": [],
            "details": {}
        }
        
        # 检查1: Cursor可执行文件
        executable_check = self._check_cursor_executable()
        results["details"]["executable"] = executable_check
        if not executable_check["exists"]:
            results["status"] = "failed"
            results["issues"].append("找不到Cursor可执行文件")
        
        # 检查2: 关键文件和目录
        files_check = self._check_cursor_files()
        results["details"]["files"] = files_check
        if files_check["missing_files"]:
            if results["status"] != "failed":
                results["status"] = "warning"
            missing_files_str = ", ".join(files_check["missing_files"])
            results["issues"].append(f"缺少关键文件: {missing_files_str}")
        
        # 检查3: 版本信息
        version_check = self._check_cursor_version()
        results["details"]["version"] = version_check
        if version_check["outdated"]:
            if results["status"] != "failed":
                results["status"] = "warning"
            results["issues"].append(f"Cursor版本过旧: {version_check['version']}, 建议: {version_check['recommended']}")
        
        # 检查4: 安装路径
        path_check = self._check_installation_path()
        results["details"]["installation_path"] = path_check
        if not path_check["valid"]:
            if results["status"] != "failed":
                results["status"] = "warning"
            results["issues"].append(f"安装路径异常: {path_check['path']}")
        
        # 记录检查结果
        action = "Cursor安装检查"
        success = results["status"] != "failed"
        details = f"结果: {results['status']}, 发现问题: {len(results['issues'])}"
        self._log_recovery_action(action, success, details)
        
        return results
    
    def _check_cursor_executable(self) -> Dict[str, Any]:
        """检查Cursor可执行文件"""
        result = {
            "exists": False,
            "path": None,
            "readable": False,
            "executable": False
        }
        
        # 根据不同操作系统查找可执行文件
        if self.system == "Windows":
            cursor_path = os.path.join(os.getenv("LOCALAPPDATA", ""), "Programs", "Cursor", "Cursor.exe")
            result["path"] = cursor_path
        elif self.system == "Darwin":  # macOS
            cursor_path = "/Applications/Cursor.app"
            result["path"] = cursor_path
        elif self.system == "Linux":
            # 在Linux上尝试几种可能的路径
            possible_paths = ["/usr/bin/cursor", "/opt/Cursor/cursor"]
            for path in possible_paths:
                if os.path.exists(path):
                    cursor_path = path
                    result["path"] = cursor_path
                    break
        
        # 检查文件存在性和权限
        if result["path"] and os.path.exists(result["path"]):
            result["exists"] = True
            result["readable"] = os.access(result["path"], os.R_OK)
            result["executable"] = os.access(result["path"], os.X_OK)
        
        return result
    
    def _check_cursor_files(self) -> Dict[str, Any]:
        """检查Cursor关键文件和目录"""
        result = {
            "required_files": [],
            "missing_files": [],
            "corrupted_files": []
        }
        
        # 根据不同操作系统检查不同的文件
        if self.system == "Windows":
            cursor_dir = os.path.join(os.getenv("LOCALAPPDATA", ""), "Programs", "Cursor")
            required_files = ["Cursor.exe", "resources.pak"]
        elif self.system == "Darwin":
            cursor_dir = "/Applications/Cursor.app"
            required_files = ["Contents/MacOS/Cursor", "Contents/Info.plist"]
        elif self.system == "Linux":
            cursor_dir = "/opt/Cursor"
            required_files = ["cursor", "resources.pak"]
        else:
            return result
        
        # 记录需要检查的文件
        result["required_files"] = [os.path.join(cursor_dir, f) for f in required_files]
        
        # 检查文件是否存在
        for file_path in result["required_files"]:
            if not os.path.exists(file_path):
                result["missing_files"].append(file_path)
        
        return result
    
    def _check_cursor_version(self) -> Dict[str, Any]:
        """检查Cursor版本信息"""
        result = {
            "version": "未知",
            "recommended": "0.45.0",  # 假设的推荐版本
            "outdated": False
        }
        
        try:
            # 尝试从package.json获取版本信息
            from patch_cursor_get_machine_id import get_cursor_paths
            pkg_path, _ = get_cursor_paths()
            
            if os.path.exists(pkg_path):
                with open(pkg_path, "r", encoding="utf-8") as f:
                    version = json.load(f).get("version", "未知")
                    result["version"] = version
                    
                    # 检查版本是否过旧
                    from patch_cursor_get_machine_id import version_check
                    result["outdated"] = not version_check(version, min_version=result["recommended"])
        except Exception as e:
            logging.error(f"检查Cursor版本失败: {e}")
            result["error"] = str(e)
        
        return result
    
    def _check_installation_path(self) -> Dict[str, Any]:
        """检查安装路径是否正确"""
        result = {
            "path": "未知",
            "valid": True,
            "issues": []
        }
        
        # 获取安装路径
        if self.system == "Windows":
            cursor_path = os.path.join(os.getenv("LOCALAPPDATA", ""), "Programs", "Cursor")
        elif self.system == "Darwin":
            cursor_path = "/Applications/Cursor.app"
        elif self.system == "Linux":
            cursor_path = "/opt/Cursor"
        else:
            result["valid"] = False
            result["issues"].append("不支持的操作系统")
            return result
        
        result["path"] = cursor_path
        
        # 检查路径是否存在
        if not os.path.exists(cursor_path):
            result["valid"] = False
            result["issues"].append("安装目录不存在")
            return result
        
        # 检查路径中是否有特殊字符或空格
        if " " in cursor_path and self.system != "Darwin":  # macOS上空格是正常的
            result["issues"].append("路径包含空格，可能导致问题")
        
        # 检查路径是否过长
        if len(cursor_path) > 260 and self.system == "Windows":
            result["issues"].append("路径过长，Windows上可能导致问题")
        
        # 如果有任何问题，标记为无效
        if result["issues"]:
            result["valid"] = False
        
        return result
    
    def check_network_connectivity(self) -> Dict[str, Any]:
        """
        检查网络连接状态
        
        检查项目包括：
        1. 基本网络连接
        2. Cursor服务器连接
        3. 代理设置
        4. DNS解析
        5. 网络延迟
        
        Returns:
            Dict: 包含网络状态的字典
        """
        results = {
            "status": "passed",  # 可能的值: passed, warning, failed
            "issues": [],
            "details": {}
        }
        
        # 检查1: 基本网络连接
        basic_check = self._check_basic_connectivity()
        results["details"]["basic_connectivity"] = basic_check
        if not basic_check["connected"]:
            results["status"] = "failed"
            results["issues"].append("无法连接到互联网")
        
        # 检查2: Cursor服务器连接
        server_check = self._check_cursor_servers()
        results["details"]["cursor_servers"] = server_check
        if not server_check["all_accessible"]:
            if server_check["critical_accessible"]:
                if results["status"] != "failed":
                    results["status"] = "warning"
                results["issues"].append("部分Cursor服务器无法访问")
            else:
                results["status"] = "failed"
                results["issues"].append("无法访问关键Cursor服务器")
        
        # 检查3: 代理设置
        proxy_check = self._check_proxy_settings()
        results["details"]["proxy_settings"] = proxy_check
        if proxy_check["issues"]:
            if results["status"] != "failed":
                results["status"] = "warning"
            issues_str = ", ".join(proxy_check["issues"])
            results["issues"].append(f"代理配置问题: {issues_str}")
        
        # 检查4: DNS解析
        dns_check = self._check_dns_resolution()
        results["details"]["dns_resolution"] = dns_check
        if not dns_check["all_resolved"]:
            if dns_check["critical_resolved"]:
                if results["status"] != "failed":
                    results["status"] = "warning"
                results["issues"].append("部分域名解析失败")
            else:
                results["status"] = "failed"
                results["issues"].append("无法解析关键域名")
        
        # 检查5: 网络延迟
        latency_check = self._check_network_latency()
        results["details"]["network_latency"] = latency_check
        if latency_check["high_latency"]:
            if results["status"] != "failed":
                results["status"] = "warning"
            results["issues"].append(f"网络延迟较高: {latency_check['average_ms']}ms")
        
        # 记录检查结果
        action = "网络连接检查"
        success = results["status"] != "failed"
        details = f"结果: {results['status']}, 发现问题: {len(results['issues'])}"
        self._log_recovery_action(action, success, details)
        
        return results
    
    def _check_basic_connectivity(self) -> Dict[str, Any]:
        """检查基本网络连接"""
        result = {
            "connected": False,
            "details": ""
        }
        
        # 测试连接到常用站点
        test_urls = ["https://www.google.com", "https://www.baidu.com", "https://www.microsoft.com"]
        connected_count = 0
        
        for url in test_urls:
            try:
                import urllib.request
                urllib.request.urlopen(url, timeout=5)
                connected_count += 1
            except Exception:
                pass
        
        # 如果能连接到至少一个站点，则认为基本连接正常
        result["connected"] = connected_count > 0
        result["connected_sites"] = connected_count
        result["total_sites"] = len(test_urls)
        
        if result["connected"]:
            result["details"] = f"能够连接到 {connected_count}/{len(test_urls)} 个测试站点"
        else:
            result["details"] = "无法连接到任何测试站点，请检查网络连接"
        
        return result
    
    def _check_cursor_servers(self) -> Dict[str, Any]:
        """检查Cursor服务器连接"""
        result = {
            "all_accessible": True,
            "critical_accessible": True,
            "details": "",
            "server_status": {}
        }
        
        # Cursor相关服务器
        servers = {
            "authenticator": {
                "url": "https://authenticator.cursor.sh",
                "critical": True
            },
            "api": {
                "url": "https://api.cursor.sh",
                "critical": True
            },
            "www": {
                "url": "https://www.cursor.com",
                "critical": False
            }
        }
        
        accessible_count = 0
        critical_failure = False
        
        for name, info in servers.items():
            url = info["url"]
            critical = info["critical"]
            try:
                import urllib.request
                response = urllib.request.urlopen(url, timeout=10)
                status_code = response.getcode()
                result["server_status"][name] = {
                    "accessible": status_code == 200,
                    "status_code": status_code
                }
                
                if status_code == 200:
                    accessible_count += 1
                elif critical:
                    critical_failure = True
            except Exception as e:
                result["server_status"][name] = {
                    "accessible": False,
                    "error": str(e)
                }
                if critical:
                    critical_failure = True
        
        # 更新总体状态
        result["all_accessible"] = accessible_count == len(servers)
        result["critical_accessible"] = not critical_failure
        
        if result["all_accessible"]:
            result["details"] = "所有Cursor服务器均可访问"
        elif result["critical_accessible"]:
            result["details"] = "部分非关键Cursor服务器无法访问"
        else:
            result["details"] = "无法访问关键Cursor服务器，这可能会影响应用功能"
        
        return result
    
    def _check_proxy_settings(self) -> Dict[str, Any]:
        """检查代理设置"""
        result = {
            "proxy_enabled": False,
            "proxy_url": "",
            "issues": []
        }
        
        # 检查环境变量中的代理设置
        http_proxy = os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")
        https_proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
        
        if http_proxy or https_proxy:
            result["proxy_enabled"] = True
            result["proxy_url"] = https_proxy or http_proxy
            
            # 简单验证代理格式
            try:
                import urllib.parse
                proxy_parts = urllib.parse.urlparse(result["proxy_url"])
                if not proxy_parts.netloc:
                    result["issues"].append("代理URL格式可能不正确")
            except Exception:
                result["issues"].append("无法解析代理URL")
        
        # 检查系统代理设置
        if self.system == "Windows":
            try:
                import winreg
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, 
                                   r"Software\Microsoft\Windows\CurrentVersion\Internet Settings") as key:
                    proxy_enable, _ = winreg.QueryValueEx(key, "ProxyEnable")
                    if proxy_enable:
                        result["proxy_enabled"] = True
                        proxy_server, _ = winreg.QueryValueEx(key, "ProxyServer")
                        result["proxy_url"] = proxy_server
            except Exception:
                pass
        
        # 检查代理可用性
        if result["proxy_enabled"] and result["proxy_url"]:
            try:
                # 简单测试，实际应该用代理设置请求URL
                import urllib.request
                test_url = "https://www.google.com"
                proxy_handler = urllib.request.ProxyHandler({
                    "http": result["proxy_url"],
                    "https": result["proxy_url"]
                })
                opener = urllib.request.build_opener(proxy_handler)
                response = opener.open(test_url, timeout=10)
                if response.getcode() != 200:
                    result["issues"].append("代理服务器可能不工作")
            except Exception:
                result["issues"].append("通过代理连接失败")
        
        return result
    
    def _check_dns_resolution(self) -> Dict[str, Any]:
        """检查DNS解析"""
        result = {
            "all_resolved": True,
            "critical_resolved": True,
            "details": "",
            "domain_status": {}
        }
        
        # 重要域名
        domains = {
            "authenticator.cursor.sh": True,  # 关键域名
            "api.cursor.sh": True,
            "www.cursor.com": False,
            "github.com": False
        }
        
        resolved_count = 0
        critical_failure = False
        
        for domain, critical in domains.items():
            try:
                import socket
                ip_address = socket.gethostbyname(domain)
                result["domain_status"][domain] = {
                    "resolved": True,
                    "ip_address": ip_address
                }
                resolved_count += 1
            except Exception as e:
                result["domain_status"][domain] = {
                    "resolved": False,
                    "error": str(e)
                }
                if critical:
                    critical_failure = True
        
        # 更新总体状态
        result["all_resolved"] = resolved_count == len(domains)
        result["critical_resolved"] = not critical_failure
        
        if result["all_resolved"]:
            result["details"] = "所有域名均可解析"
        elif result["critical_resolved"]:
            result["details"] = "部分非关键域名无法解析"
        else:
            result["details"] = "无法解析关键域名，这可能会影响应用功能"
        
        return result
    
    def _check_network_latency(self) -> Dict[str, Any]:
        """检查网络延迟"""
        result = {
            "average_ms": 0,
            "high_latency": False,
            "details": ""
        }
        
        # 测试站点
        test_sites = ["authenticator.cursor.sh", "api.cursor.sh"]
        total_latency = 0
        successful_pings = 0
        
        for site in test_sites:
            try:
                # 使用简单的HTTP请求测量延迟
                import time
                import urllib.request
                
                start_time = time.time()
                urllib.request.urlopen(f"https://{site}", timeout=10)
                end_time = time.time()
                
                latency_ms = (end_time - start_time) * 1000
                total_latency += latency_ms
                successful_pings += 1
            except Exception:
                pass
        
        # 计算平均延迟
        if successful_pings > 0:
            result["average_ms"] = int(total_latency / successful_pings)
            result["high_latency"] = result["average_ms"] > 500  # 延迟超过500ms视为高延迟
            
            if result["high_latency"]:
                result["details"] = f"网络延迟较高 ({result['average_ms']}ms)，可能影响应用体验"
            else:
                result["details"] = f"网络延迟正常 ({result['average_ms']}ms)"
        else:
            result["details"] = "无法测量网络延迟，可能网络连接异常"
            result["high_latency"] = True
        
        return result
    
    def recover_corrupted_auth_db(self) -> bool:
        """
        尝试恢复损坏的认证数据库
        
        修复策略包括：
        1. 备份当前数据库
        2. 尝试重建损坏的表
        3. 导入备份的关键数据
        4. 重置损坏的认证信息
        
        Returns:
            bool: 是否成功恢复
        """
        # 记录开始恢复操作
        action = "恢复认证数据库"
        self._log_recovery_action(action, True, "开始恢复操作")
        
        db_path = self.auth_manager.db_path
        
        # 1. 检查数据库是否存在
        if not os.path.exists(db_path):
            self._log_recovery_action(action, False, "认证数据库不存在")
            return self._create_new_auth_db()
        
        # 2. 备份当前数据库
        backup_path = self._create_backup(db_path)
        if not backup_path:
            self._log_recovery_action(action, False, "无法创建数据库备份")
            # 即使没有备份，也尝试修复
        else:
            self._log_recovery_action(action, True, f"创建备份: {backup_path}")
        
        # 3. 尝试连接并检查数据库结构
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # 检查itemTable是否存在
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='itemTable'")
            table_exists = cursor.fetchone() is not None
            
            if not table_exists:
                # 如果表不存在，创建表
                self._log_recovery_action(action, True, "itemTable不存在，尝试创建")
                self._create_item_table(cursor)
            else:
                # 如果表存在，验证结构
                try:
                    cursor.execute("SELECT key, value FROM itemTable LIMIT 1")
                    # 表结构正常
                    self._log_recovery_action(action, True, "数据库表结构正常")
                except sqlite3.Error:
                    # 表结构异常，尝试重建
                    self._log_recovery_action(action, True, "数据库表结构异常，尝试重建")
                    cursor.execute("DROP TABLE IF EXISTS itemTable")
                    self._create_item_table(cursor)
            
            # 4. 验证关键认证数据
            self._verify_auth_data(cursor)
            
            # 5. 提交更改并关闭连接
            conn.commit()
            conn.close()
            
            self._log_recovery_action(action, True, "认证数据库恢复完成")
            return True
        
        except sqlite3.Error as e:
            error_msg = str(e)
            self._log_recovery_action(action, False, f"数据库操作失败: {error_msg}")
            
            # 如果是严重错误，尝试完全重建数据库
            if "database disk image is malformed" in error_msg or "database is locked" in error_msg:
                return self._rebuild_auth_db(db_path, backup_path)
            
            return False
        
        except Exception as e:
            self._log_recovery_action(action, False, f"恢复过程出错: {e}")
            return False
    
    def _create_item_table(self, cursor) -> None:
        """创建itemTable表"""
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS itemTable (
            key TEXT PRIMARY KEY,
            value TEXT
        )
        """)
    
    def _verify_auth_data(self, cursor) -> None:
        """验证并修复认证数据"""
        # 检查关键认证项是否存在
        auth_keys = [
            "cursorAuth/cachedEmail",
            "cursorAuth/cachedSignUpType",
            "cursorAuth/accessToken",
            "cursorAuth/refreshToken"
        ]
        
        for key in auth_keys:
            cursor.execute("SELECT value FROM itemTable WHERE key = ?", (key,))
            result = cursor.fetchone()
            
            if not result:
                # 如果关键项不存在，记录但不修复（需要用户重新登录）
                self._log_recovery_action("验证认证数据", False, f"缺少关键认证信息: {key}")
            elif key == "cursorAuth/cachedSignUpType" and result[0] != "Auth_0":
                # 修复认证类型
                cursor.execute("UPDATE itemTable SET value = ? WHERE key = ?", 
                              ("Auth_0", key))
                self._log_recovery_action("验证认证数据", True, f"修复认证类型: {key}")
    
    def _create_new_auth_db(self) -> bool:
        """创建新的认证数据库"""
        db_path = self.auth_manager.db_path
        
        try:
            # 确保目录存在
            os.makedirs(os.path.dirname(db_path), exist_ok=True)
            
            # 创建数据库和表
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            self._create_item_table(cursor)
            conn.commit()
            conn.close()
            
            self._log_recovery_action("创建新数据库", True, f"创建新的认证数据库: {db_path}")
            return True
        except Exception as e:
            self._log_recovery_action("创建新数据库", False, f"创建失败: {e}")
            return False
    
    def _rebuild_auth_db(self, db_path: str, backup_path: str) -> bool:
        """完全重建认证数据库"""
        try:
            # 尝试从备份提取关键数据
            auth_data = {}
            
            if backup_path and os.path.exists(backup_path):
                try:
                    backup_conn = sqlite3.connect(backup_path)
                    backup_cursor = backup_conn.cursor()
                    
                    # 提取关键认证数据
                    auth_keys = [
                        "cursorAuth/cachedEmail",
                        "cursorAuth/cachedSignUpType",
                        "cursorAuth/accessToken",
                        "cursorAuth/refreshToken"
                    ]
                    
                    for key in auth_keys:
                        backup_cursor.execute("SELECT value FROM itemTable WHERE key = ?", (key,))
                        result = backup_cursor.fetchone()
                        if result:
                            auth_data[key] = result[0]
                    
                    backup_conn.close()
                except Exception as e:
                    self._log_recovery_action("提取备份数据", False, f"从备份提取数据失败: {e}")
            
            # 删除损坏的数据库
            if os.path.exists(db_path):
                os.remove(db_path)
                self._log_recovery_action("重建数据库", True, "删除损坏的数据库")
            
            # 创建新数据库
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            self._create_item_table(cursor)
            
            # 恢复备份的关键数据
            for key, value in auth_data.items():
                cursor.execute("INSERT INTO itemTable (key, value) VALUES (?, ?)", 
                              (key, value))
            
            conn.commit()
            conn.close()
            
            self._log_recovery_action("重建数据库", True, "完成数据库重建")
            return True
        
        except Exception as e:
            self._log_recovery_action("重建数据库", False, f"重建失败: {e}")
            return False
    
    def reset_cursor_settings(self) -> bool:
        """
        重置Cursor设置到默认状态
        
        重置内容包括：
        1. 认证信息
        2. 用户首选项
        3. 缓存文件
        4. 插件设置
        
        Returns:
            bool: 是否成功重置
        """
        action = "重置Cursor设置"
        self._log_recovery_action(action, True, "开始重置操作")
        
        success = True
        reset_items = []
        
        # 1. 备份当前设置
        backup_created = self._backup_cursor_settings()
        if backup_created:
            self._log_recovery_action(action, True, "已创建设置备份")
        
        # 2. 重置认证信息
        if self._reset_auth_info():
            reset_items.append("认证信息")
        else:
            success = False
        
        # 3. 重置用户首选项
        if self._reset_user_preferences():
            reset_items.append("用户首选项")
        else:
            success = False
        
        # 4. 清理缓存文件
        if self._clean_cursor_cache():
            reset_items.append("缓存文件")
        else:
            success = False
        
        # 5. 重置插件设置
        if self._reset_plugin_settings():
            reset_items.append("插件设置")
        else:
            success = False
        
        # 记录重置结果
        if success:
            reset_items_str = ", ".join(reset_items)
            self._log_recovery_action(action, True, f"成功重置: {reset_items_str}")
        else:
            self._log_recovery_action(action, False, "部分重置操作失败，请查看详细日志")
        
        return success
    
    def _backup_cursor_settings(self) -> bool:
        """备份Cursor设置"""
        try:
            # 获取所有需要备份的文件和目录
            backup_items = [
                self.auth_manager.db_path,  # 认证数据库
            ]
            
            # 根据操作系统添加其他设置文件
            if self.system == "Windows":
                cursor_config_dir = os.path.join(os.getenv("APPDATA", ""), "Cursor")
                if os.path.exists(cursor_config_dir):
                    backup_items.append(cursor_config_dir)
            elif self.system == "Darwin":  # macOS
                cursor_config_dir = os.path.expanduser("~/Library/Application Support/Cursor")
                if os.path.exists(cursor_config_dir):
                    backup_items.append(cursor_config_dir)
            elif self.system == "Linux":
                cursor_config_dir = os.path.expanduser("~/.config/Cursor")
                if os.path.exists(cursor_config_dir):
                    backup_items.append(cursor_config_dir)
            
            # 创建备份时间戳目录
            timestamp = time.strftime("%Y%m%d%H%M%S")
            settings_backup_dir = os.path.join(self.backup_folder, f"settings_backup_{timestamp}")
            os.makedirs(settings_backup_dir, exist_ok=True)
            
            # 备份每个项目
            for item in backup_items:
                if os.path.exists(item):
                    item_name = os.path.basename(item)
                    backup_path = os.path.join(settings_backup_dir, item_name)
                    
                    if os.path.isfile(item):
                        # 如果是文件，直接复制
                        shutil.copy2(item, backup_path)
                    elif os.path.isdir(item):
                        # 如果是目录，递归复制
                        shutil.copytree(item, backup_path, dirs_exist_ok=True)
            
            return True
        except Exception as e:
            logging.error(f"备份Cursor设置失败: {e}")
            return False
    
    def _reset_auth_info(self) -> bool:
        """重置认证信息"""
        try:
            # 重置认证数据库
            db_path = self.auth_manager.db_path
            
            if os.path.exists(db_path):
                try:
                    conn = sqlite3.connect(db_path)
                    cursor = conn.cursor()
                    
                    # 获取当前所有键
                    cursor.execute("SELECT key FROM itemTable")
                    keys = [row[0] for row in cursor.fetchall()]
                    
                    # 删除所有认证相关的键
                    auth_prefixes = ["cursorAuth/", "authData/"]
                    for key in keys:
                        for prefix in auth_prefixes:
                            if key.startswith(prefix):
                                cursor.execute("DELETE FROM itemTable WHERE key = ?", (key,))
                    
                    conn.commit()
                    conn.close()
                    return True
                except Exception as e:
                    logging.error(f"重置认证信息失败: {e}")
                    return False
            else:
                # 如果数据库不存在，创建一个新的
                return self._create_new_auth_db()
        except Exception as e:
            logging.error(f"重置认证信息过程出错: {e}")
            return False
    
    def _reset_user_preferences(self) -> bool:
        """重置用户首选项"""
        try:
            # 根据不同操作系统找到首选项文件
            prefs_file = None
            
            if self.system == "Windows":
                prefs_file = os.path.join(os.getenv("APPDATA", ""), "Cursor", "User", "settings.json")
            elif self.system == "Darwin":
                prefs_file = os.path.expanduser("~/Library/Application Support/Cursor/User/settings.json")
            elif self.system == "Linux":
                prefs_file = os.path.expanduser("~/.config/Cursor/User/settings.json")
            
            if prefs_file and os.path.exists(prefs_file):
                # 备份原始设置
                self._create_backup(prefs_file)
                
                # 创建默认设置文件
                with open(prefs_file, "w", encoding="utf-8") as f:
                    f.write("{}")
                
                return True
            
            return True  # 如果文件不存在，视为成功
        except Exception as e:
            logging.error(f"重置用户首选项失败: {e}")
            return False
    
    def _clean_cursor_cache(self) -> bool:
        """清理Cursor缓存文件"""
        try:
            cache_dirs = []
            
            # 根据不同操作系统找到缓存目录
            if self.system == "Windows":
                cache_dir = os.path.join(os.getenv("APPDATA", ""), "Cursor", "Cache")
                cache_dirs.append(cache_dir)
                cache_dirs.append(os.path.join(os.getenv("APPDATA", ""), "Cursor", "Code Cache"))
            elif self.system == "Darwin":
                cache_dir = os.path.expanduser("~/Library/Application Support/Cursor/Cache")
                cache_dirs.append(cache_dir)
                cache_dirs.append(os.path.expanduser("~/Library/Application Support/Cursor/Code Cache"))
            elif self.system == "Linux":
                cache_dir = os.path.expanduser("~/.config/Cursor/Cache")
                cache_dirs.append(cache_dir)
                cache_dirs.append(os.path.expanduser("~/.config/Cursor/Code Cache"))
            
            # 清理每个缓存目录
            for dir_path in cache_dirs:
                if os.path.exists(dir_path):
                    # 删除目录内容但保留目录本身
                    for item in os.listdir(dir_path):
                        item_path = os.path.join(dir_path, item)
                        try:
                            if os.path.isfile(item_path):
                                os.unlink(item_path)
                            elif os.path.isdir(item_path):
                                shutil.rmtree(item_path)
                        except Exception as e:
                            logging.warning(f"无法删除缓存项 {item_path}: {e}")
            
            return True
        except Exception as e:
            logging.error(f"清理缓存文件失败: {e}")
            return False
    
    def _reset_plugin_settings(self) -> bool:
        """重置插件设置"""
        try:
            extensions_dirs = []
            
            # 根据不同操作系统找到插件目录
            if self.system == "Windows":
                extensions_dirs.append(os.path.join(os.getenv("APPDATA", ""), "Cursor", "User", "globalStorage"))
            elif self.system == "Darwin":
                extensions_dirs.append(os.path.expanduser("~/Library/Application Support/Cursor/User/globalStorage"))
            elif self.system == "Linux":
                extensions_dirs.append(os.path.expanduser("~/.config/Cursor/User/globalStorage"))
            
            # 清理每个插件目录
            for dir_path in extensions_dirs:
                if os.path.exists(dir_path):
                    # 备份目录
                    backup_path = self._create_backup(dir_path)
                    if backup_path:
                        # 删除目录内容但保留目录本身
                        for item in os.listdir(dir_path):
                            item_path = os.path.join(dir_path, item)
                            try:
                                if os.path.isfile(item_path):
                                    os.unlink(item_path)
                                elif os.path.isdir(item_path):
                                    shutil.rmtree(item_path)
                            except Exception as e:
                                logging.warning(f"无法重置插件 {item_path}: {e}")
            
            return True
        except Exception as e:
            logging.error(f"重置插件设置失败: {e}")
            return False
    
    def interactive_recovery(self) -> bool:
        """
        交互式恢复模式，引导用户解决问题
        
        交互式恢复过程：
        1. 诊断阶段 - 收集系统和Cursor状态信息
        2. 问题识别 - 分析诊断结果，识别关键问题
        3. 解决方案 - 为每个问题提供详细的解决步骤
        4. 用户交互 - 引导用户执行解决步骤，提供实时反馈
        5. 验证修复 - 验证问题是否已解决
        
        Returns:
            bool: 是否成功恢复
        """
        action = "交互式恢复"
        self._log_recovery_action(action, True, "开始交互式恢复流程")
        
        print("\n" + "="*60)
        print(f"{Fore.CYAN}Cursor 交互式恢复向导{Style.RESET_ALL}")
        print("-"*60)
        print("本向导将帮助您诊断和解决Cursor的常见问题。")
        print("整个过程将引导您完成以下步骤:")
        print("1. 诊断系统和Cursor状态")
        print("2. 识别可能的问题")
        print("3. 提供解决方案并引导您执行")
        print("4. 验证问题是否已解决")
        print("="*60 + "\n")
        
        # 1. 诊断阶段
        print(f"{Fore.CYAN}正在收集诊断信息...{Style.RESET_ALL}")
        diagnosis_results = {}
        
        # 1.1 系统环境检查
        print("检查系统环境...")
        sys_check = self.check_system_requirements()
        diagnosis_results["system"] = sys_check
        
        # 1.2 Cursor安装检查
        print("验证Cursor安装...")
        install_check = self.check_cursor_installation()
        diagnosis_results["installation"] = install_check
        
        # 1.3 网络连接检查
        print("测试网络连接...")
        network_check = self.check_network_connectivity()
        diagnosis_results["network"] = network_check
        
        # 1.4 数据库状态检查
        print("检查认证数据库状态...")
        db_path = self.auth_manager.db_path
        db_check = {"status": "passed", "issues": []}
        
        if not os.path.exists(db_path):
            db_check["status"] = "failed"
            db_check["issues"].append("认证数据库文件不存在")
        else:
            try:
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                
                # 检查表结构
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='itemTable'")
                if cursor.fetchone() is None:
                    db_check["status"] = "failed"
                    db_check["issues"].append("认证数据库缺少必要表结构")
                else:
                    # 检查是否有认证信息
                    cursor.execute("SELECT key FROM itemTable WHERE key LIKE 'cursorAuth/%'")
                    if not cursor.fetchone():
                        db_check["status"] = "warning"
                        db_check["issues"].append("未找到认证信息，可能需要重新登录")
                
                conn.close()
            except sqlite3.Error:
                db_check["status"] = "failed"
                db_check["issues"].append("认证数据库已损坏")
        
        diagnosis_results["database"] = db_check
        
        # 2. 问题识别和分类
        print(f"\n{Fore.CYAN}诊断完成，分析结果...{Style.RESET_ALL}")
        problems = self._identify_problems(diagnosis_results)
        
        if not problems:
            print(f"{Fore.GREEN}未发现明显问题!{Style.RESET_ALL}")
            print("您的Cursor环境看起来运行正常。如果仍然遇到问题，可能是其他未检测到的因素导致的。")
            self._log_recovery_action(action, True, "诊断未发现明显问题")
            return True
        
        # 3. 解决方案和用户交互
        print(f"\n{Fore.CYAN}发现以下问题:{Style.RESET_ALL}")
        for i, problem in enumerate(problems, 1):
            severity_color = Fore.RED if problem["severity"] == "critical" else Fore.YELLOW if problem["severity"] == "warning" else Fore.WHITE
            print(f"{i}. {severity_color}{problem['description']}{Style.RESET_ALL}")
        
        # 按优先级排序问题
        problems.sort(key=lambda p: 0 if p["severity"] == "critical" else 1 if p["severity"] == "warning" else 2)
        
        # 逐个解决问题
        solved_problems = []
        for problem in problems:
            print(f"\n{Fore.CYAN}正在解决: {problem['description']}{Style.RESET_ALL}")
            
            # 显示解决步骤
            print("建议的解决步骤:")
            for i, solution in enumerate(problem["solutions"], 1):
                print(f"{i}. {solution}")
            
            # 确认是否尝试解决
            if not self._confirm_continue("是否尝试解决此问题?"):
                print(f"{Fore.YELLOW}跳过此问题{Style.RESET_ALL}")
                continue
            
            # 尝试自动解决或引导用户手动解决
            if problem["can_auto_fix"]:
                print(f"{Fore.CYAN}正在自动修复...{Style.RESET_ALL}")
                fix_success = self._auto_fix_problem(problem["type"])
                
                if fix_success:
                    print(f"{Fore.GREEN}问题已修复!{Style.RESET_ALL}")
                    solved_problems.append(problem)
                else:
                    print(f"{Fore.RED}自动修复失败，请尝试手动解决{Style.RESET_ALL}")
                    self._guide_manual_fix(problem["type"])
            else:
                print(f"{Fore.YELLOW}此问题需要手动解决{Style.RESET_ALL}")
                self._guide_manual_fix(problem["type"])
                
                # 让用户确认是否已解决
                if self._confirm_continue("您已完成上述步骤并解决了问题吗?"):
                    print(f"{Fore.GREEN}问题已标记为已解决{Style.RESET_ALL}")
                    solved_problems.append(problem)
        
        # 4. 验证修复
        print(f"\n{Fore.CYAN}正在验证修复结果...{Style.RESET_ALL}")
        
        # 再次运行诊断，检查问题是否已解决
        verification_passed = self._verify_fixes(problems, solved_problems)
        
        if verification_passed:
            print(f"\n{Fore.GREEN}所有问题已成功解决!{Style.RESET_ALL}")
            self._log_recovery_action(action, True, f"成功解决了 {len(solved_problems)}/{len(problems)} 个问题")
            return True
        else:
            print(f"\n{Fore.YELLOW}部分问题可能仍未解决{Style.RESET_ALL}")
            print("建议您重启计算机，然后重新尝试登录Cursor。")
            print("如果问题仍然存在，请考虑重新安装Cursor或联系Cursor支持团队。")
            
            # 记录恢复结果
            self._log_recovery_action(action, False, f"仅解决了 {len(solved_problems)}/{len(problems)} 个问题")
            return False
    
    def _identify_problems(self, diagnosis_results) -> List[Dict[str, Any]]:
        """
        从诊断结果中识别问题
        
        Args:
            diagnosis_results: 诊断结果字典
            
        Returns:
            List[Dict]: 问题列表，每个问题包含描述、严重性、解决方案等
        """
        problems = []
        
        # 系统环境问题
        if diagnosis_results["system"]["status"] in ["warning", "failed"]:
            for issue in diagnosis_results["system"]["issues"]:
                problem = {
                    "type": "system",
                    "description": f"系统环境问题: {issue}",
                    "severity": "critical" if diagnosis_results["system"]["status"] == "failed" else "warning",
                    "solutions": [],
                    "can_auto_fix": False
                }
                
                # 根据具体问题添加解决方案
                if "管理员权限" in issue:
                    problem["solutions"] = [
                        "以管理员身份重新运行程序",
                        "右键点击程序图标，选择\"以管理员身份运行\"",
                        "在Windows上，您可能需要修改程序属性，勾选\"以管理员身份运行此程序\""
                    ]
                elif "磁盘空间" in issue:
                    problem["solutions"] = [
                        "清理磁盘空间，删除不必要的文件",
                        "使用磁盘清理工具",
                        "将Cursor移动到其他有足够空间的分区"
                    ]
                elif "目录权限" in issue:
                    problem["solutions"] = [
                        "检查并修复文件夹权限",
                        "确保您的用户账户对Cursor目录有完全控制权限"
                    ]
                else:
                    problem["solutions"] = ["联系系统管理员解决此系统环境问题"]
                
                problems.append(problem)
        
        # 安装问题
        if diagnosis_results["installation"]["status"] in ["warning", "failed"]:
            for issue in diagnosis_results["installation"]["issues"]:
                problem = {
                    "type": "installation",
                    "description": f"Cursor安装问题: {issue}",
                    "severity": "critical" if diagnosis_results["installation"]["status"] == "failed" else "warning",
                    "solutions": [],
                    "can_auto_fix": False
                }
                
                if "找不到Cursor可执行文件" in issue:
                    problem["solutions"] = [
                        "重新安装Cursor",
                        "从官方网站下载最新版本的Cursor",
                        "确保安装过程完成且没有错误"
                    ]
                elif "缺少关键文件" in issue:
                    problem["solutions"] = [
                        "修复Cursor安装",
                        "重新安装Cursor",
                        "确保安装过程没有被防病毒软件中断"
                    ]
                elif "版本过旧" in issue:
                    problem["solutions"] = [
                        "更新Cursor到最新版本",
                        "从官方网站下载最新版本"
                    ]
                else:
                    problem["solutions"] = ["重新安装Cursor以解决安装问题"]
                
                problems.append(problem)
        
        # 网络问题
        if diagnosis_results["network"]["status"] in ["warning", "failed"]:
            for issue in diagnosis_results["network"]["issues"]:
                problem = {
                    "type": "network",
                    "description": f"网络连接问题: {issue}",
                    "severity": "critical" if diagnosis_results["network"]["status"] == "failed" else "warning",
                    "solutions": [],
                    "can_auto_fix": False
                }
                
                if "无法连接到互联网" in issue:
                    problem["solutions"] = [
                        "检查您的网络连接",
                        "重新连接WiFi或网络",
                        "重启路由器",
                        "联系网络管理员"
                    ]
                elif "无法访问关键Cursor服务器" in issue:
                    problem["solutions"] = [
                        "检查防火墙设置，确保Cursor可以访问互联网",
                        "如果使用公司网络，咨询IT部门是否限制了对Cursor服务器的访问",
                        "尝试使用其他网络连接"
                    ]
                elif "代理配置问题" in issue:
                    problem["solutions"] = [
                        "检查系统代理设置",
                        "在Cursor设置中配置正确的代理",
                        "暂时禁用代理，看问题是否解决"
                    ]
                elif "网络延迟较高" in issue:
                    problem["solutions"] = [
                        "检查您的网络连接速度",
                        "关闭可能占用带宽的其他应用",
                        "使用更稳定的网络连接"
                    ]
                else:
                    problem["solutions"] = ["排查网络连接问题"]
                
                problems.append(problem)
        
        # 数据库问题
        if diagnosis_results["database"]["status"] in ["warning", "failed"]:
            for issue in diagnosis_results["database"]["issues"]:
                problem = {
                    "type": "database",
                    "description": f"认证数据库问题: {issue}",
                    "severity": "critical" if diagnosis_results["database"]["status"] == "failed" else "warning",
                    "solutions": [],
                    "can_auto_fix": True
                }
                
                if "数据库文件不存在" in issue:
                    problem["solutions"] = [
                        "创建新的认证数据库",
                        "重新登录Cursor",
                        "重新安装Cursor"
                    ]
                elif "数据库已损坏" in issue:
                    problem["solutions"] = [
                        "修复损坏的数据库",
                        "重置认证数据库",
                        "重新登录Cursor"
                    ]
                elif "未找到认证信息" in issue:
                    problem["solutions"] = [
                        "重新登录Cursor",
                        "确保登录过程完成"
                    ]
                else:
                    problem["solutions"] = ["修复认证数据库问题"]
                
                problems.append(problem)
        
        return problems
    
    def _auto_fix_problem(self, problem_type: str) -> bool:
        """
        尝试自动修复问题
        
        Args:
            problem_type: 问题类型
            
        Returns:
            bool: 是否修复成功
        """
        if problem_type == "database":
            print("尝试修复认证数据库...")
            return self.recover_corrupted_auth_db()
        # 其他问题类型的自动修复可以在这里添加
        
        return False
    
    def _guide_manual_fix(self, problem_type: str) -> None:
        """
        引导用户手动修复问题
        
        Args:
            problem_type: 问题类型
        """
        if problem_type == "system":
            print("\n手动修复步骤:")
            print("1. 确保您有管理员权限")
            print("2. 检查磁盘空间是否充足")
            print("3. 确保Cursor目录的权限正确")
        elif problem_type == "installation":
            print("\n手动修复步骤:")
            print("1. 备份您的Cursor数据（如果需要）")
            print("2. 卸载当前的Cursor")
            print("3. 从官方网站下载最新版本")
            print("4. 重新安装Cursor")
        elif problem_type == "network":
            print("\n手动修复步骤:")
            print("1. 检查您的网络连接是否正常")
            print("2. 尝试访问 https://cursor.sh 确认是否可以访问")
            print("3. 如果使用代理，请检查代理设置")
            print("4. 尝试重启路由器或切换到其他网络")
        elif problem_type == "database":
            print("\n手动修复步骤:")
            print("1. 退出Cursor")
            print("2. 删除损坏的数据库文件（如果知道位置）")
            print("3. 重新启动Cursor并登录")
            print(f"4. 数据库位置: {self.auth_manager.db_path}")
        else:
            print("无法提供特定问题类型的手动修复指南")
    
    def _verify_fixes(self, original_problems, solved_problems) -> bool:
        """
        验证问题是否已解决
        
        Args:
            original_problems: 原始问题列表
            solved_problems: 已解决问题列表
            
        Returns:
            bool: 是否所有关键问题都已解决
        """
        # 检查所有严重问题是否都已解决
        critical_problems = [p for p in original_problems if p["severity"] == "critical"]
        solved_critical = [p for p in solved_problems if p["severity"] == "critical"]
        
        # 如果所有严重问题都已解决，或者没有严重问题，则认为验证通过
        return len(solved_critical) == len(critical_problems)
    
    def generate_recovery_report(self) -> str:
        """
        生成详细的恢复报告
        
        报告内容包括：
        1. 系统环境信息
        2. Cursor安装状态
        3. 诊断结果摘要
        4. 执行的恢复操作
        5. 恢复结果
        6. 建议的后续步骤
        
        Returns:
            str: 恢复报告文本
        """
        # 创建报告时间戳
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        
        # 生成报告内容
        report = []
        report.append("="*80)
        report.append(f"Cursor 恢复报告 - 生成时间: {timestamp}")
        report.append("="*80)
        
        # 1. 系统环境信息
        report.append("\n系统环境信息:")
        report.append("-"*40)
        report.append(f"操作系统: {self.system}")
        report.append(f"版本: {platform.version()}")
        report.append(f"架构: {platform.machine()}")
        report.append(f"管理员权限: {'是' if self._check_admin_privileges()['has_admin'] else '否'}")
        
        # 2. Cursor安装状态
        report.append("\nCursor安装状态:")
        report.append("-"*40)
        executable_info = self._check_cursor_executable()
        version_info = self._check_cursor_version()
        
        report.append(f"安装路径: {executable_info.get('path', '未知')}")
        report.append(f"可执行状态: {'正常' if executable_info.get('exists', False) else '未找到'}")
        report.append(f"版本: {version_info.get('version', '未知')}")
        report.append(f"版本状态: {'最新' if not version_info.get('outdated', True) else '过旧'}")
        
        # 3. 诊断结果摘要
        report.append("\n诊断结果摘要:")
        report.append("-"*40)
        
        # 收集最近的诊断结果
        diagnosis_summary = {}
        for log_entry in self.recovery_log:
            if "检查" in log_entry["action"]:
                component = log_entry["action"].replace("检查", "").strip()
                status = "通过" if log_entry["success"] else "失败"
                diagnosis_summary[component] = {
                    "status": status,
                    "details": log_entry["details"]
                }
        
        # 显示诊断结果
        for component, info in diagnosis_summary.items():
            report.append(f"{component}: {info['status']}")
            report.append(f"  详情: {info['details']}")
        
        # 4. 执行的恢复操作
        report.append("\n执行的恢复操作:")
        report.append("-"*40)
        
        recovery_actions = []
        for log_entry in self.recovery_log:
            if "恢复" in log_entry["action"] or "重置" in log_entry["action"] or "修复" in log_entry["action"]:
                timestamp = log_entry["timestamp"]
                action = log_entry["action"]
                result = "成功" if log_entry["success"] else "失败"
                details = log_entry["details"]
                
                recovery_actions.append((timestamp, action, result, details))
        
        if recovery_actions:
            for timestamp, action, result, details in recovery_actions:
                report.append(f"[{timestamp}] {action}: {result}")
                report.append(f"  详情: {details}")
        else:
            report.append("未执行恢复操作")
        
        # 5. 恢复结果
        report.append("\n恢复结果:")
        report.append("-"*40)
        
        # 检查最后一个恢复操作的结果
        last_recovery = None
        for log_entry in reversed(self.recovery_log):
            if "恢复流程" in log_entry["action"]:
                last_recovery = log_entry
                break
        
        if last_recovery:
            overall_result = "成功" if last_recovery["success"] else "部分成功" if "部分" in last_recovery["details"] else "失败"
            report.append(f"整体恢复状态: {overall_result}")
            report.append(f"详情: {last_recovery['details']}")
        else:
            report.append("未找到恢复结果记录")
        
        # 6. 建议的后续步骤
        report.append("\n建议的后续步骤:")
        report.append("-"*40)
        
        # 根据恢复结果提供建议
        if last_recovery and last_recovery["success"]:
            report.append("1. 重启Cursor并验证问题是否已解决")
            report.append("2. 如果问题仍然存在，可以尝试重启计算机")
            report.append("3. 定期更新Cursor以获取最新功能和修复")
        else:
            report.append("1. 尝试重启计算机")
            report.append("2. 重新安装Cursor")
            report.append("3. 如果问题仍然存在，建议联系Cursor支持团队")
            report.append("4. 确保您使用的是最新版本的Cursor")
        
        # 7. 额外信息
        report.append("\n额外信息:")
        report.append("-"*40)
        report.append(f"恢复工具版本: 1.0.0")
        report.append(f"报告ID: {timestamp.replace(' ', '').replace(':', '').replace('-', '')}")
        report.append("="*80)
        
        # 将报告保存到文件
        report_text = "\n".join(report)
        report_filename = f"cursor_recovery_report_{timestamp.replace(' ', '_').replace(':', '-')}.txt"
        report_path = os.path.join(self.backup_folder, report_filename)
        
        try:
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(report_text)
            print(f"恢复报告已保存到: {report_path}")
        except Exception as e:
            print(f"保存恢复报告失败: {e}")
        
        return report_text
    
    def _log_recovery_action(self, action: str, success: bool, details: str = "") -> None:
        """
        记录恢复操作
        
        Args:
            action: 执行的操作
            success: 是否成功
            details: 操作详情
        """
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        self.recovery_log.append({
            "timestamp": timestamp,
            "action": action,
            "success": success,
            "details": details
        })
        
        # 同时写入应用日志
        status = "成功" if success else "失败"
        log_message = f"恢复操作 [{status}]: {action}"
        if details:
            log_message += f" - {details}"
            
        if success:
            logging.info(log_message)
        else:
            logging.error(log_message)
    
    def _create_backup(self, file_path: str) -> Optional[str]:
        """
        创建文件备份
        
        Args:
            file_path: 要备份的文件路径
            
        Returns:
            Optional[str]: 备份文件路径，如果备份失败则返回None
        """
        if not os.path.exists(file_path):
            return None
            
        try:
            # 生成备份文件名
            file_name = os.path.basename(file_path)
            timestamp = time.strftime("%Y%m%d%H%M%S")
            backup_path = os.path.join(self.backup_folder, f"{file_name}.{timestamp}.bak")
            
            # 创建备份
            shutil.copy2(file_path, backup_path)
            logging.info(f"已创建备份: {backup_path}")
            return backup_path
        except Exception as e:
            logging.error(f"创建备份失败: {e}")
            return None
    
    def _restore_backup(self, backup_path: str, target_path: str) -> bool:
        """
        从备份恢复文件
        
        Args:
            backup_path: 备份文件路径
            target_path: 目标恢复路径
            
        Returns:
            bool: 是否成功恢复
        """
        if not os.path.exists(backup_path):
            logging.error(f"备份文件不存在: {backup_path}")
            return False
            
        try:
            # 如果目标文件存在，先删除
            if os.path.exists(target_path):
                os.remove(target_path)
                
            # 恢复备份
            shutil.copy2(backup_path, target_path)
            logging.info(f"已从备份恢复: {target_path}")
            return True
        except Exception as e:
            logging.error(f"从备份恢复失败: {e}")
            return False 
    
    def _confirm_continue(self, prompt: str) -> bool:
        """
        用户确认是否继续
        
        Args:
            prompt: 提示信息
            
        Returns:
            bool: 用户是否选择继续
        """
        while True:
            response = input(f"{prompt} (y/n): ").strip().lower()
            if response == 'y':
                return True
            elif response == 'n':
                return False
            else:
                print("请输入 'y' 或 'n'")
    
    def perform_full_recovery(self, interactive=True) -> bool:
        """
        执行完整的恢复流程
        
        恢复步骤包括：
        1. 系统环境检查
        2. Cursor安装验证
        3. 网络连接测试
        4. 认证数据库恢复
        5. 重置Cursor设置
        
        Args:
            interactive: 是否启用交互式恢复模式
        
        Returns:
            bool: 是否成功恢复
        """
        action = "完整恢复流程"
        self._log_recovery_action(action, True, "开始完整恢复流程")
        
        recovery_results = {}
        overall_success = True
        
        # 1. 系统环境检查
        print(f"{Fore.CYAN}[1/5] 检查系统环境...{Style.RESET_ALL}")
        sys_check = self.check_system_requirements()
        recovery_results["system_check"] = sys_check["status"]
        
        if sys_check["status"] == "failed":
            print(f"{Fore.RED}系统环境检查失败，可能无法继续恢复{Style.RESET_ALL}")
            if interactive:
                if not self._confirm_continue("是否继续恢复流程?"):
                    self._log_recovery_action(action, False, "用户在系统环境检查失败后取消了恢复")
                    return False
            else:
                # 非交互模式下，系统环境检查失败就不继续
                self._log_recovery_action(action, False, "系统环境检查失败，自动终止恢复")
                return False
        
        # 2. Cursor安装验证
        print(f"{Fore.CYAN}[2/5] 验证Cursor安装...{Style.RESET_ALL}")
        install_check = self.check_cursor_installation()
        recovery_results["install_check"] = install_check["status"]
        
        if install_check["status"] == "failed":
            print(f"{Fore.RED}Cursor安装验证失败，无法继续恢复{Style.RESET_ALL}")
            self._log_recovery_action(action, False, "Cursor安装验证失败，终止恢复")
            return False
        
        # 3. 网络连接测试
        print(f"{Fore.CYAN}[3/5] 测试网络连接...{Style.RESET_ALL}")
        network_check = self.check_network_connectivity()
        recovery_results["network_check"] = network_check["status"]
        
        if network_check["status"] == "failed":
            print(f"{Fore.RED}网络连接测试失败，部分恢复功能可能受限{Style.RESET_ALL}")
            if interactive:
                if not self._confirm_continue("是否继续恢复流程?"):
                    self._log_recovery_action(action, False, "用户在网络连接测试失败后取消了恢复")
                    return False
        
        # 4. 认证数据库恢复
        print(f"{Fore.CYAN}[4/5] 恢复认证数据库...{Style.RESET_ALL}")
        db_recovery = self.recover_corrupted_auth_db()
        recovery_results["db_recovery"] = "success" if db_recovery else "failed"
        
        if not db_recovery:
            print(f"{Fore.RED}认证数据库恢复失败，Cursor可能无法正常登录{Style.RESET_ALL}")
            overall_success = False
        
        # 5. 重置Cursor设置
        print(f"{Fore.CYAN}[5/5] 重置Cursor设置...{Style.RESET_ALL}")
        if interactive:
            if self._confirm_continue("是否重置Cursor设置到默认状态?"):
                settings_reset = self.reset_cursor_settings()
                recovery_results["settings_reset"] = "success" if settings_reset else "failed"
                
                if not settings_reset:
                    print(f"{Fore.RED}Cursor设置重置失败{Style.RESET_ALL}")
                    overall_success = False
            else:
                print(f"{Fore.YELLOW}跳过Cursor设置重置{Style.RESET_ALL}")
                recovery_results["settings_reset"] = "skipped"
        else:
            # 非交互模式下，默认重置设置
            settings_reset = self.reset_cursor_settings()
            recovery_results["settings_reset"] = "success" if settings_reset else "failed"
            
            if not settings_reset:
                print(f"{Fore.RED}Cursor设置重置失败{Style.RESET_ALL}")
                overall_success = False
        
        # 生成恢复报告
        report = self.generate_recovery_report()
        
        # 显示恢复结果
        print("\n" + "="*60)
        print(f"{Fore.CYAN}恢复流程完成!{Style.RESET_ALL}")
        print("-"*60)
        
        for step, status in recovery_results.items():
            color = Fore.GREEN if status == "success" or status == "passed" else Fore.YELLOW if status == "warning" or status == "skipped" else Fore.RED
            print(f"{step}: {color}{status}{Style.RESET_ALL}")
        
        print("\n如果恢复未解决所有问题，请尝试:")
        print("1. 重启计算机")
        print("2. 重新安装Cursor")
        print("3. 手动登录Cursor账号")
        print("="*60)
        
        # 记录恢复结果
        result_str = ", ".join([f"{k}: {v}" for k, v in recovery_results.items()])
        self._log_recovery_action(action, overall_success, f"恢复流程结果: {result_str}")
        
        return overall_success