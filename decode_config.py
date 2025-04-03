#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
配置处理工具

此脚本用于处理GitHub Actions中的配置数据。
它会尝试将配置解析为JSON，并生成有效的配置文件。
"""

import base64
import json
import os
import sys


def decode_config():
    """
    处理配置数据
    
    从环境变量OFFICIAL_CONFIG获取配置数据，
    尝试解析为JSON，并生成有效的配置文件。
    """
    # 获取配置
    config_data = os.environ.get('OFFICIAL_CONFIG', '')

    # 处理配置
    try:
        if not config_data:
            # 空配置，使用空JSON对象
            config_json = '{}'
            print("警告: 未提供配置数据，使用空配置。")
        else:
            # 首先尝试直接作为JSON解析
            try:
                json.loads(config_data)  # 验证JSON有效性
                config_json = config_data
                print("成功: 配置已作为JSON处理。")
            except json.JSONDecodeError:
                # 如果JSON解析失败，尝试作为base64解码
                try:
                    # 修复base64填充
                    padding = len(config_data) % 4
                    if padding:
                        config_data += '=' * (4 - padding)
                    
                    # 解码
                    config_json = base64.b64decode(config_data).decode('utf-8')
                    
                    # 验证JSON有效性
                    json.loads(config_json)
                    print("成功: 配置已解码处理。")
                except Exception as e:
                    print(f"警告: 提供的数据不是有效的JSON格式。使用空配置。")
                    print(f"原始错误: {str(e)}")
                    config_json = '{}'
        
        # 写入配置文件
        with open('official_config.json', 'w') as f:
            f.write(config_json)
        
        # 验证结果
        with open('official_config.json', 'r') as f:
            content = json.load(f)
        
        if content:
            print('配置验证成功')
            # 输出配置字段但隐藏敏感值
            safe_content = {k: '***' if k in ['IMAP_PASS'] else v for k, v in content.items()}
            print(f"配置内容: {json.dumps(safe_content, ensure_ascii=False)}")
        else:
            print('配置为空')
        
    except Exception as e:
        print(f'处理配置时出错: {str(e)}')
        # 确保至少有一个有效的配置文件
        with open('official_config.json', 'w') as f:
            f.write('{}')


if __name__ == "__main__":
    decode_config() 