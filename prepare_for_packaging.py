import os
import shutil
import argparse
import json

def prepare_for_packaging():
    """准备打包前的配置文件"""
    # 创建备份目录
    if not os.path.exists('backup_configs'):
        os.makedirs('backup_configs')
    
    # 备份现有的敏感配置文件（如果存在）
    if os.path.exists('official_config.json'):
        shutil.copy('official_config.json', 'backup_configs/official_config.json.bak')
        print("已备份官方配置文件")
    
    if os.path.exists('.env'):
        shutil.copy('.env', 'backup_configs/.env.bak')
        print("已备份环境配置文件")
    
    # 如果不存在官方配置，则检查是否存在示例配置
    if not os.path.exists('official_config.json'):
        if os.path.exists('official_config.example.json'):
            shutil.copy('official_config.example.json', 'official_config.json')
            print("已从示例文件创建临时官方配置")
        else:
            # 两个文件都不存在，创建默认配置
            default_config = {
                "DOMAIN": "xiao89.site",
                "IMAP_SERVER": "imap.qq.com",
                "IMAP_PORT": "993",
                "IMAP_USER": "BASE64:MzI2NDkxMzUyM0BxcS5jb20=",
                "IMAP_PASS": "BASE64:YXZ2dHRnZWJmbWxvZGJmYw==",
                "IMAP_DIR": "inbox",
                "IMAP_PROTOCOL": "IMAP"
            }
            with open('official_config.json', 'w', encoding='utf-8') as f:
                json.dump(default_config, f, indent=2, ensure_ascii=False)
            print("已创建默认官方配置文件")
    
    print("打包准备工作完成！")
    return True

def restore_after_packaging():
    """打包后恢复配置文件"""
    # 删除临时创建的配置文件
    if os.path.exists('official_config.json') and os.path.exists('backup_configs/official_config.json.bak'):
        os.remove('official_config.json')
        print("已删除临时官方配置文件")
    
    # 从备份恢复配置文件
    if os.path.exists('backup_configs/official_config.json.bak'):
        shutil.copy('backup_configs/official_config.json.bak', 'official_config.json')
        print("已从备份恢复官方配置文件")
    
    if os.path.exists('backup_configs/.env.bak'):
        shutil.copy('backup_configs/.env.bak', '.env')
        print("已从备份恢复环境配置文件")
    
    print("配置恢复工作完成！")
    return True

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="配置文件准备和恢复工具")
    parser.add_argument('action', choices=['prepare', 'restore'], help="prepare: 准备打包环境; restore: 恢复配置文件")
    
    args = parser.parse_args()
    
    if args.action == 'prepare':
        prepare_for_packaging()
    elif args.action == 'restore':
        restore_after_packaging() 