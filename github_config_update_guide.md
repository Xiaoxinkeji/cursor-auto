# GitHub密钥配置更新指南

为了更改GitHub Actions中使用的官方配置，您需要更新仓库的`OFFICIAL_CONFIG`密钥。以下是详细步骤：

## 1. 准备新的配置JSON

创建一个包含QQ邮箱配置的JSON文件：

```json
{
  "DOMAIN": "xiao89.site",
  "IMAP_SERVER": "imap.qq.com",
  "IMAP_PORT": "993",
  "IMAP_USER": "3264913523@qq.com",
  "IMAP_PASS": "avvttgebfmlodbfc",
  "IMAP_DIR": "inbox",
  "IMAP_PROTOCOL": "IMAP"
}
```

## 2. 更新GitHub仓库密钥

1. 登录GitHub并导航到您的仓库
2. 点击仓库页面上的"Settings"选项卡
3. 在左侧菜单中找到"Secrets and variables"，然后选择"Actions"
4. 在"Repository secrets"部分，找到`OFFICIAL_CONFIG`密钥
5. 点击"Update"更新这个密钥
6. 将准备好的JSON配置复制到密钥值中
7. 点击"Update secret"保存更改

## 3. 测试配置更新

配置更新后，您可以通过以下方式测试是否生效：

1. 手动触发GitHub Actions工作流：
   - 导航到您仓库的"Actions"选项卡
   - 选择"Build Executables"工作流
   - 点击"Run workflow"
   - 选择一个分支（通常是main或master）并运行

2. 或者创建一个新的发布标签：
   - 创建一个新的Git标签，如`v1.0.1`
   - 推送标签到GitHub仓库
   - 这将自动触发构建工作流

## 4. 确认配置已应用

检查构建日志：
1. 打开触发的工作流运行
2. 查看任何一个构建任务的日志
3. 找到`decode_config.py`脚本的输出
4. 确认配置内容中显示了`"IMAP_SERVER": "imap.qq.com"`

## 注意事项

- GitHub Actions密钥是加密存储的，因此它们在日志中不会完整显示
- 如果遇到构建问题，可以检查`decode_config.py`脚本的输出以确认配置是否正确处理
- 确保JSON格式有效，不包含任何语法错误 