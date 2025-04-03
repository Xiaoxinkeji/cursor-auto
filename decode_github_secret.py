#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
GitHub Secrets 配置解码工具

本脚本用于将base64格式的配置解码回JSON格式，用于调试GitHub Actions配置。
使用方法：
    python decode_github_secret.py <base64_string>

如果未指定base64字符串，将提示用户输入。
"""

import base64
import json
import sys
from colorama import Fore, Style, init

# 初始化colorama
init()

def decode_base64_to_json(base64_str: str) -> None:
    """
    将base64编码的字符串解码为JSON
    
    Args:
        base64_str: base64编码的字符串
    """
    try:
        # 尝试修复不规范的base64字符串
        original_str = base64_str
        
        # 检查并修复填充
        padding = len(base64_str) % 4
        if padding:
            print(f"{Fore.YELLOW}注意: 输入的base64字符串长度不是4的倍数，自动添加填充...{Style.RESET_ALL}")
            base64_str += '=' * (4 - padding)
        
        # 尝试解码base64
        try:
            # 解码base64
            decoded_bytes = base64.b64decode(base64_str)
            json_str = decoded_bytes.decode('utf-8')
            
            # 解析JSON
            json_data = json.loads(json_str)
            
            # 打印结果
            print(f"\n{Fore.GREEN}=== base64已成功解码为JSON ==={Style.RESET_ALL}")
            print(f"\n{Fore.CYAN}解码后的JSON内容:{Style.RESET_ALL}")
            print(json.dumps(json_data, indent=2, ensure_ascii=False))
            
            # 验证必要的字段
            required_fields = ["DOMAIN", "IMAP_SERVER", "IMAP_PORT", "IMAP_USER", "IMAP_PASS"]
            missing_fields = [field for field in required_fields if field not in json_data]
            
            if missing_fields:
                print(f"\n{Fore.YELLOW}警告: 配置中缺少以下必要字段:{Style.RESET_ALL}")
                for field in missing_fields:
                    print(f" - {field}")
            else:
                print(f"\n{Fore.GREEN}配置有效: 包含所有必要字段{Style.RESET_ALL}")
        except:
            # 如果base64解码后无法解析为JSON，尝试直接解析原始字符串
            try:
                print(f"{Fore.YELLOW}base64解码失败，尝试直接解析为JSON...{Style.RESET_ALL}")
                json_data = json.loads(original_str)
                print(f"\n{Fore.GREEN}=== 输入已直接解析为JSON (非base64编码) ==={Style.RESET_ALL}")
                print(f"\n{Fore.CYAN}JSON内容:{Style.RESET_ALL}")
                print(json.dumps(json_data, indent=2, ensure_ascii=False))
                
                # 验证必要的字段
                required_fields = ["DOMAIN", "IMAP_SERVER", "IMAP_PORT", "IMAP_USER", "IMAP_PASS"]
                missing_fields = [field for field in required_fields if field not in json_data]
                
                if missing_fields:
                    print(f"\n{Fore.YELLOW}警告: 配置中缺少以下必要字段:{Style.RESET_ALL}")
                    for field in missing_fields:
                        print(f" - {field}")
                else:
                    print(f"\n{Fore.GREEN}配置有效: 包含所有必要字段{Style.RESET_ALL}")
            except:
                print(f"{Fore.RED}错误: 输入既不是有效的base64编码，也不是有效的JSON格式{Style.RESET_ALL}")
                raise Exception("无法解析输入")
            
        print(f"\n{Fore.CYAN}提示: GitHub Actions现在使用Python进行base64解码，不再依赖系统命令，提高了跨平台兼容性。{Style.RESET_ALL}")
        print(f"\n{Fore.CYAN}最新版本的工作流支持直接使用JSON格式和base64编码的配置。{Style.RESET_ALL}")
        
    except base64.binascii.Error as e:
        print(f"{Fore.RED}错误: base64解码失败 - {str(e)}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}提示: 请确保输入的是有效的base64字符串。base64字符串长度应为4的倍数，或末尾有适当的'='填充。{Style.RESET_ALL}")
    except json.JSONDecodeError as e:
        print(f"{Fore.RED}错误: JSON解析失败 - {str(e)}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}解码后的原始内容:{Style.RESET_ALL}")
        print(json_str)
    except Exception as e:
        print(f"{Fore.RED}错误: {str(e)}{Style.RESET_ALL}")

if __name__ == "__main__":
    # 获取base64字符串
    if len(sys.argv) > 1:
        base64_string = sys.argv[1]
    else:
        print(f"{Fore.CYAN}请输入base64编码的配置字符串:{Style.RESET_ALL}")
        base64_string = input().strip()
        
    if not base64_string:
        print(f"{Fore.RED}错误: 未提供base64字符串{Style.RESET_ALL}")
        sys.exit(1)
        
    decode_base64_to_json(base64_string) 