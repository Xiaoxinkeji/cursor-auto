# -*- mode: python ; coding: utf-8 -*-
import os

a = Analysis(
    ['cursor_pro_keep_alive.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('turnstilePatch', 'turnstilePatch'),
        ('cursor_auth_manager.py', '.'),
        ('.env.example', '.'),
    ],
    hiddenimports=[
        'cursor_auth_manager'
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)

# 如果存在官方配置文件，添加到数据文件中
official_config_exists = os.path.exists('official_config.json')
example_config_exists = os.path.exists('official_config.example.json')

if official_config_exists:
    # 使用已有的官方配置
    a.datas += [('official_config.json', 'official_config.json', 'DATA')]
elif example_config_exists:
    # 不存在官方配置但存在示例配置，复制示例文件为临时官方配置
    import shutil
    temp_config = 'official_config.json.tmp'
    shutil.copy('official_config.example.json', temp_config)
    a.datas += [('official_config.json', temp_config, 'DATA')]
    
    # 添加清理步骤
    import atexit
    def cleanup():
        if os.path.exists(temp_config):
            os.remove(temp_config)
    atexit.register(cleanup)
else:
    # 两个配置文件都不存在，创建一个默认配置
    import json
    temp_config = 'official_config.json.tmp'
    default_config = {
        "DOMAIN": "bsmail.xyz",
        "IMAP_SERVER": "imap.qq.com",
        "IMAP_PORT": "993",
        "IMAP_USER": "3264913523@qq.com",
        "IMAP_PASS": "avvttgebfmlodbfc",
        "IMAP_DIR": "inbox",
        "IMAP_PROTOCOL": "IMAP"
    }
    with open(temp_config, 'w', encoding='utf-8') as f:
        json.dump(default_config, f, indent=2, ensure_ascii=False)
    a.datas += [('official_config.json', temp_config, 'DATA')]
    
    # 添加清理步骤
    import atexit
    def cleanup():
        if os.path.exists(temp_config):
            os.remove(temp_config)
    atexit.register(cleanup)
    print("注意: 未找到官方配置文件或示例配置文件，已创建默认配置。")

pyz = PYZ(a.pure)

target_arch = os.environ.get('TARGET_ARCH', None)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='CursorPro',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=True,  # 对非Mac平台无影响
    target_arch=target_arch,  # 仅在需要时通过环境变量指定
    codesign_identity=None,
    entitlements_file=None,
    icon=None
)