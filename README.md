# QuickSSH


一个简单的SSH工具，主要用户公司内部就固定几个密码的场景，挨个尝试认证后自动添加秘钥，以及可通过命令行快速在 ssh config 中添加主机及别名。 

## 使用场景

### 场景1：企业内部服务器管理
在公司环境中，通常服务器使用有限几个标准密码。IT管理员可以：
- 保存常用密码，一键尝试所有可能的密码组合
- 批量添加公钥到新服务器，避免重复密码认证
- 无需记忆大量密码，系统自动尝试

### 场景2：自动化运维
- 自动尝试多个密码登录新服务器
- 自动复制SSH密钥到目标主机
- 避免每次输入"yes"确认主机密钥问题

### 场景3：管理大量服务器
- 复用现有~/.ssh/config配置
- 快速添加新主机配置
- 使用别名快速连接主机

### 场景4：临时访问不熟悉的环境
- 一次尝试多个常见密码（如root/admin/password等）
- 登录成功后自动配置免密登录
- 直观的错误提示和调试信息

## 功能特点

- 尝试多个密码进行SSH登录
- 保存和管理常用密码
- 自动添加公钥到远程主机
- 管理SSH主机配置
- 跨平台支持(Windows, Linux, macOS)
- 使用标准SSH配置文件，兼容现有SSH工具
- 自动绕过SSH主机密钥确认

## 安装

```bash
git clone https://github.com/你的用户名/quickssh.git
cd quickssh
go build -o quickssh
```

### 设置终端别名

为了更便捷地使用QuickSSH，您可以在终端设置别名`qssh`指向本工具。

#### Linux/macOS (Bash)
在`~/.bashrc`或`~/.bash_profile`中添加：
```bash
alias qssh='/path/to/quickssh'
```
然后执行`source ~/.bashrc`（或`source ~/.bash_profile`）使修改生效。

#### Linux/macOS (Zsh)
在`~/.zshrc`中添加：
```bash
alias qssh='/path/to/quickssh'
```
然后执行`source ~/.zshrc`使修改生效。

#### Windows (PowerShell)
在PowerShell配置文件中添加：
```powershell
function qssh { & 'D:\path\to\quickssh.exe' $args }
```
或者直接在当前会话中设置（临时）：
```powershell
Set-Alias -Name qssh -Value "D:\path\to\quickssh.exe"
```

## 使用方法

### 直接SSH登录（最常用）

```bash
# 使用别名直接调用
qssh 192.168.1.100

# 直接尝试已保存的所有密码登录
quickssh 192.168.1.100

# 指定密码尝试登录
quickssh 10.0.0.1 password1 password2

# 支持非标准端口
quickssh 192.168.1.100:2222
```

### 密码管理

对于企业内部常用的几个密码，可以保存起来以便快速尝试：

```bash
qssh password add Passw0rd@2023    # 添加公司标准密码
qssh password add admin@123        # 添加常用管理员密码
qssh password list                 # 列出所有密码
qssh password delete mypassword123 # 删除不再使用的密码
```

### 主机配置管理

与标准SSH配置文件(~/.ssh/config)集成：

```bash
# 添加带有别名的新服务器
qssh host add 192.168.1.100 alias=webserver user=admin port=2222

# 查看所有配置的主机
qssh host list

# 删除旧主机配置
qssh host delete webserver
```

### 使用优势

- **无需交互确认**：自动接受主机密钥，避免首次连接时的交互
- **智能错误处理**：连接失败时提供具体原因和建议
- **一键配置免密登录**：成功登录后自动复制公钥到远程主机
- **兼容性**：使用标准SSH配置，与其他SSH工具无缝协作

## 实际使用示例

**场景：新服务器批量部署**

1. 保存公司常用密码：
   ```bash
   qssh password add Password123!
   qssh password add Admin@2023
   ```

2. 尝试登录新服务器：
   ```bash
   qssh 192.168.50.10
   ```
   
3. 工具自动尝试所有密码，登录成功后自动设置免密登录

4. 添加到主机配置：
   ```bash
   qssh host add 192.168.50.10 alias=app-server-1 user=admin
   ```

5. 后续可直接使用别名登录：
   ```bash
   ssh app-server-1
   ```

## 帮助信息

```bash
qssh --help
qssh password --help
qssh host add --help
```

## 许可证

MIT License
