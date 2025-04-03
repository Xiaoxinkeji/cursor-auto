#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
GitHub Secrets 配置准备工具

本脚本用于将JSON配置文件编码为base64格式，以便在GitHub Actions中使用。
使用方法：
    python prepare_github_secret.py <config_file>

如果未指定配置文件，则默认使用 'official_config.json'
"""

import base64
import json
import sys
import os
from colorama import Fore, Style, init

# 初始化colorama
init()

def encode_config_file(file_path: str) -> None:
    """
    将JSON配置文件编码为base64格式
    
    Args:
        file_path: JSON配置文件路径
    """
    try:
        # 检查文件是否存在
        if not os.path.exists(file_path):
            print(f"{Fore.RED}错误: 文件不存在 {file_path}{Style.RESET_ALL}")
            return
            
        # 读取并验证JSON文件
        with open(file_path, 'r', encoding='utf-8') as f:
            config_data = json.load(f)
            
        # 将JSON转换为字符串并编码为base64
        json_str = json.dumps(config_data)
        encoded = base64.b64encode(json_str.encode('utf-8')).decode('utf-8')
        
        # 验证生成的base64是否有效
        try:
            decoded = base64.b64decode(encoded).decode('utf-8')
            json.loads(decoded)  # 验证解码后的内容是否是有效的JSON
            is_valid = True
        except Exception as e:
            print(f"{Fore.RED}警告: 生成的base64字符串无法正确解码: {str(e)}{Style.RESET_ALL}")
            is_valid = False
            
        # 打印结果
        print(f"\n{Fore.GREEN}=== JSON配置已成功编码为base64格式 ==={Style.RESET_ALL}")
        print(f"\n{Fore.CYAN}原始JSON内容:{Style.RESET_ALL}")
        print(json.dumps(config_data, indent=2, ensure_ascii=False))
        
        print(f"\n{Fore.CYAN}base64编码结果:{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{encoded}{Style.RESET_ALL}")
        
        # 提供验证和使用提示
        print(f"\n{Fore.GREEN}请将上面的base64编码内容添加到GitHub Secrets中，名称为 'OFFICIAL_CONFIG'{Style.RESET_ALL}")
        print(f"\n{Fore.CYAN}注意: GitHub Actions现在使用Python解码base64内容，不再依赖系统命令，提高了跨平台兼容性。{Style.RESET_ALL}")
        
        # 添加验证方法提示
        print(f"\n{Fore.CYAN}您可以使用以下命令验证base64字符串:{Style.RESET_ALL}")
        print(f"python decode_github_secret.py {encoded}")
        
        # 如果需要，也可以添加直接使用JSON的提示
        print(f"\n{Fore.CYAN}或者也可以直接将原始JSON添加到GitHub Secrets中:{Style.RESET_ALL}")
        print(f"新版本的工作流也支持直接使用JSON格式的配置，无需base64编码。")
        
    except json.JSONDecodeError as e:
        print(f"{Fore.RED}错误: JSON格式无效 - {str(e)}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}错误: {str(e)}{Style.RESET_ALL}")

if __name__ == "__main__":
    # 获取配置文件路径
    if len(sys.argv) > 1:
        config_file = sys.argv[1]
    else:
        config_file = "official_config.json"
        # 如果默认文件不存在但示例文件存在，则提示复制
        if not os.path.exists(config_file) and os.path.exists(config_file + ".example"):
            print(f"{Fore.YELLOW}提示: 配置文件 {config_file} 不存在，但找到了示例文件。{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}请先复制示例文件并进行配置:{Style.RESET_ALL}")
            print(f"cp {config_file}.example {config_file}")
            sys.exit(1)
            
    print(f"{Fore.CYAN}正在处理配置文件: {config_file}{Style.RESET_ALL}")
    encode_config_file(config_file) 