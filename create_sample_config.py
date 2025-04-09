import json
import os
import sys

def create_sample_config():
    """创建示例官方配置文件，仅供开发测试使用"""
    sample_config = {
        "DOMAIN": "xiao89.site",
        "IMAP_SERVER": "imap.qq.com",
        "IMAP_PORT": "993",
        "IMAP_USER": "<请在此处填写您的QQ邮箱>",
        "IMAP_PASS": "<请在此处填写您的QQ邮箱授权码>",
        "IMAP_DIR": "inbox",
        "IMAP_PROTOCOL": "IMAP"
    }
    
    config_path = "official_config.json"
    
    try:
        with open(config_path, 'w', encoding='utf-8') as f:
            json.dump(sample_config, f, indent=2)
        print(f"已生成示例配置文件：{config_path}")
        print("注意：这是仅供开发测试的示例配置，请勿用于生产环境")
        
        # 生成适用于GitHub Secrets的单行JSON
        one_line_json = json.dumps(sample_config)
        print("\n适用于GitHub Secrets的格式：")
        print(one_line_json)
    except Exception as e:
        print(f"生成配置文件失败：{str(e)}")
        return False
    
    return True

if __name__ == "__main__":
    print("=== 创建示例官方配置文件 ===")
    print("警告：此脚本仅供开发测试使用，生成的配置文件包含示例数据")
    
    confirm = input("是否继续？(y/n): ").strip().lower()
    if confirm == 'y':
        create_sample_config()
    else:
        print("操作已取消") 