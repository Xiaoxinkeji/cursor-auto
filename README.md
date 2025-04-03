# Cursor Pro 自动化工具使用说明

## 新功能：官方配置
现在，您可以选择使用官方预配置的邮箱或自定义配置：

- **官方配置**：使用我们预先配置好的QQ邮箱服务，开箱即用，无需自行配置
- **自定义配置**：使用您自己的邮箱服务，通过.env文件配置

启动程序后，只需按照提示选择配置模式即可：
```
请选择配置模式:
1. 官方配置 (使用预配置的QQ邮箱，开箱即用)
2. 自定义配置 (使用您自己的邮箱配置)
```

## 开发者配置说明
如果您是开发者并希望在本地测试：

1. 复制 `.env.example` 为 `.env` 并填写您自己的邮箱配置
2. 或者复制 `official_config.example.json` 为 `official_config.json` 并填写配置

注意：出于安全考虑，包含敏感信息的配置文件 `.env` 和 `official_config.json` 已被添加到 `.gitignore` 中，不会被提交到仓库。

## GitHub Actions 配置说明
如果您需要使用 GitHub Actions 自动构建此项目，需要配置 GitHub Secrets：

1. 复制 `official_config.example.json` 为 `official_config.json` 并填写配置
2. 在 GitHub 仓库中创建一个名为 `OFFICIAL_CONFIG` 的 Secret，直接将JSON配置复制粘贴为值，格式如下：
   ```json
   {
     "DOMAIN": "your-domain.com",
     "IMAP_SERVER": "imap.your-mail.com",
     "IMAP_PORT": "993",
     "IMAP_USER": "your-email@example.com",
     "IMAP_PASS": "your-password-or-app-code",
     "IMAP_DIR": "inbox",
     "IMAP_PROTOCOL": "IMAP"
   }
   ```
3. 创建名为 `TOKEN` 的 Secret，值为您的 GitHub Personal Access Token（需要有repo权限）

配置完成后，每次创建新的 tag（格式如 `v1.0.0`）时，GitHub Actions 将自动构建并发布新的版本。

### GitHub Actions 问题排除

如果在 GitHub Actions 中遇到配置相关的错误：

1. 确保 `OFFICIAL_CONFIG` Secret 包含有效的JSON格式
2. 检查JSON格式是否正确，尤其是确保所有引号都是英文引号，没有多余的逗号或缺少大括号
3. 注意在GitHub界面粘贴JSON时不要引入额外的空格或换行
4. 您可以使用在线JSON验证工具（如 jsonlint.com）验证您的JSON格式是否正确

### 安全提示

请注意保护您的邮箱授权码和其他敏感信息：

1. 永远不要在公开的地方分享您的授权码
2. 如果您不小心泄露了授权码，请立即更改
3. 建议定期更换授权码，增强安全性

## 许可证声明
本项目采用 [CC BY-NC-ND 4.0](https://creativecommons.org/licenses/by-nc-nd/4.0/) 许可证。
这意味着您可以：
- 分享 — 在任何媒介以任何形式复制、发行本作品
但必须遵守以下条件：
- 非商业性使用 — 您不得将本作品用于商业目的

## 声明
- 本项目仅供学习交流使用，请勿用于商业用途。
- 本项目不承担任何法律责任，使用本项目造成的任何后果，由使用者自行承担。

## 骗子
海豚

## 感谢 linuxDo 这个开源社区(一个真正的技术社区)
https://linux.do/

## 特别鸣谢
本项目的开发过程中得到了众多开源项目和社区成员的支持与帮助，在此特别感谢：

### 开源项目
- [go-cursor-help](https://github.com/yuaotian/go-cursor-help) - 一个优秀的 Cursor 机器码重置工具，本项目的机器码重置功能使用该项目实现。该项目目前已获得 9.1k Stars，是最受欢迎的 Cursor 辅助工具之一。



