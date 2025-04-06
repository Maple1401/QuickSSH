package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

var (
	sshConfigPath string
	passwordsPath string
)

// 获取用户主目录路径的辅助函数
func getUserHomeDir() string {
	if home := os.Getenv("HOME"); home != "" {
		return home
	}
	if runtime.GOOS == "windows" {
		home := os.Getenv("USERPROFILE")
		if home != "" {
			return home
		}
		return os.Getenv("HOMEDRIVE") + os.Getenv("HOMEPATH")
	}
	return ""
}

// 扩展路径中的波浪线(~)，使其在各系统上都能正常工作
func expandPath(path string) string {
	if !strings.HasPrefix(path, "~") {
		return path
	}

	home := getUserHomeDir()
	if home == "" {
		// 无法获取主目录，返回原路径
		return path
	}

	if len(path) > 1 && (path[1] == '/' || path[1] == '\\') {
		// ~/path
		return filepath.Join(home, path[2:])
	}

	// 仅 ~
	return home
}

// 初始化配置路径
func init() {
	// 动态设置SSH配置文件路径
	if runtime.GOOS == "windows" {
		// Windows 上默认在用户主目录下的 .ssh 文件夹中
		sshConfigPath = filepath.Join(getUserHomeDir(), ".ssh", "config")
		passwordsPath = filepath.Join(getUserHomeDir(), ".ssh", "passwords.txt")
	} else {
		// Linux 和 macOS 默认使用 ~/.ssh/config
		sshConfigPath = "~/.ssh/config"
		passwordsPath = "~/.ssh/passwords.txt"
	}
}

func main() {
	if len(os.Args) < 2 {
		showHelp("")
		return
	}

	// 处理全局帮助参数
	for i := 1; i < len(os.Args); i++ {
		arg := os.Args[i]
		if arg == "help" || arg == "--help" || arg == "-h" {
			// 如果帮助标志不是第一个参数，则获取第一个参数作为主题
			if i > 1 {
				helpTopic := strings.Join(os.Args[1:i], " ")
				showHelp(helpTopic)
			} else if i+1 < len(os.Args) {
				// 如果帮助标志是第一个参数，获取下一个参数作为主题
				showHelp(os.Args[i+1])
			} else {
				// 仅帮助标志
				showHelp("")
			}
			return
		}
	}

	command := os.Args[1]
	switch command {
	case "ssh":
		if len(os.Args) < 3 {
			showHelp("ssh")
			return
		}
		host := os.Args[2]
		if len(os.Args) > 3 {
			passwords := os.Args[3:]
			sshLogin(host, passwords)
		} else {
			passwords, err := readPasswords()
			if err != nil || len(passwords) == 0 {
				fmt.Println("No saved passwords found and none provided")
				return
			}
			sshLogin(host, passwords)
		}
	case "host":
		if len(os.Args) < 3 {
			showHelp("host")
			return
		}
		action := os.Args[2]
		switch action {
		case "list":
			listHosts()
		case "add":
			if len(os.Args) < 4 {
				showHelp("host add")
				return
			}
			// 检查主机参数是否是帮助请求
			if os.Args[3] == "--help" || os.Args[3] == "-h" || os.Args[3] == "help" {
				showHelp("host add")
				return
			}
			hostArgs := os.Args[3:]
			hostInfo := parseHostArgs(hostArgs)
			addHostWithInfo(hostInfo)
		case "delete":
			if len(os.Args) < 4 {
				showHelp("host delete")
				return
			}
			host := os.Args[3]
			// 检查主机参数是否是帮助请求
			if host == "--help" || host == "-h" || host == "help" {
				showHelp("host delete")
				return
			}
			deleteHost(host)
		case "change":
			if len(os.Args) < 4 {
				showHelp("host change")
				return
			}
			host := os.Args[3]
			// 检查主机参数是否是帮助请求
			if host == "--help" || host == "-h" || host == "help" {
				showHelp("host change")
				return
			}
			changeHost(host)
		default:
			showHelp("host")
		}
	case "password":
		if len(os.Args) < 3 {
			showHelp("password")
			return
		}
		action := os.Args[2]
		switch action {
		case "add":
			if len(os.Args) < 4 {
				showHelp("password add")
				return
			}
			password := os.Args[3]
			// 检查密码参数是否是帮助请求
			if password == "--help" || password == "-h" || password == "help" {
				showHelp("password add")
				return
			}
			addPassword(password)
		case "delete":
			if len(os.Args) < 4 {
				showHelp("password delete")
				return
			}
			password := os.Args[3]
			// 检查密码参数是否是帮助请求
			if password == "--help" || password == "-h" || password == "help" {
				showHelp("password delete")
				return
			}
			deletePassword(password)
		case "list":
			listPasswords()
		default:
			showHelp("password")
		}
	default:
		// 检查是否是帮助请求
		if command == "--help" || command == "-h" || command == "help" {
			showHelp("")
			return
		}

		// 检查是否是IP地址或主机名 - 尝试直接SSH登录
		host := command
		if len(os.Args) > 2 {
			passwords := os.Args[2:]
			fmt.Printf("正在尝试使用提供的密码登录到 %s...\n", host)
			sshLogin(host, passwords)
		} else {
			passwords, err := readPasswords()
			if err != nil || len(passwords) == 0 {
				fmt.Printf("没有保存的密码且未提供密码，尝试无密码登录到 %s...\n", host)
				// 尝试无密码登录（可能配置了公钥认证）
				sshLoginWithoutPassword(host)
			} else {
				fmt.Printf("正在尝试使用已保存的密码登录到 %s...\n", host)
				sshLogin(host, passwords)
			}
		}
	}
}

// 显示帮助信息
func showHelp(topic string) {
	switch topic {
	case "":
		fmt.Println("QuickSSH使用指南:")
		fmt.Println("  quickssh [命令/主机] [参数]")
		fmt.Println("\n可用命令:")
		fmt.Println("  <主机地址> - 直接SSH登录到指定主机，自动尝试所有密码")
		fmt.Println("  ssh       - (不推荐)SSH登录到远程主机")
		fmt.Println("  host      - 主机配置管理")
		fmt.Println("  password  - 密码管理")
		fmt.Println("  help      - 显示帮助信息")
		fmt.Println("\n使用 'quickssh help [命令]' 获取具体命令的详细帮助")
		fmt.Println("\n快速SSH登录示例 (推荐):")
		fmt.Println("  quickssh 192.168.1.100                 # 使用已保存密码")
		fmt.Println("  quickssh 10.0.0.1 password1 password2  # 使用指定密码")
	case "ssh":
		fmt.Println("用法: quickssh ssh <主机地址> [密码1 密码2 ...]")
		fmt.Println("  尝试使用提供的密码列表登录到指定主机")
		fmt.Println("  如果未提供密码，将尝试使用已保存的密码")
		fmt.Println("\n推荐使用简化用法: quickssh <主机地址> [密码1 密码2 ...]")
		fmt.Println("  直接输入主机地址作为第一个参数可以实现相同功能")
		fmt.Println("\n示例:")
		fmt.Println("  quickssh 192.168.1.100                 # 推荐")
		fmt.Println("  quickssh 192.168.1.100 password123     # 推荐")
		fmt.Println("  quickssh ssh 192.168.1.100             # 不推荐")
	case "host":
		fmt.Println("用法: quickssh host <操作> [参数]")
		fmt.Println("\n可用操作:")
		fmt.Println("  list    - 列出所有已配置的主机")
		fmt.Println("  add     - 添加主机配置")
		fmt.Println("  delete  - 删除主机配置")
		fmt.Println("  change  - 修改主机配置")
		fmt.Println("\n使用 'quickssh help host <操作>' 获取具体操作的详细帮助")
	case "host add":
		fmt.Println("用法: quickssh host add <主机地址> [user=用户名] [port=端口] [alias=别名]")
		fmt.Println("  将主机添加到SSH配置文件")
		fmt.Println("  默认用户名为root，端口为22，别名与主机地址相同")
		fmt.Println("\n参数:")
		fmt.Println("  主机地址   - 必需，主机名或IP地址")
		fmt.Println("  user=用户名 - 可选，SSH连接的用户名，默认为root")
		fmt.Println("  port=端口   - 可选，SSH连接的端口，默认为22")
		fmt.Println("  alias=别名  - 可选，SSH配置中的别名，默认与主机地址相同")
		fmt.Println("\n示例:")
		fmt.Println("  quickssh host add 192.168.1.100")
		fmt.Println("  quickssh host add 192.168.1.100 user=admin port=2222")
		fmt.Println("  quickssh host add server.example.com alias=webserver user=deploy")
	case "host delete":
		fmt.Println("用法: quickssh host delete <主机标识>")
		fmt.Println("  从SSH配置文件中删除指定主机")
		fmt.Println("\n示例:")
		fmt.Println("  quickssh host delete 192.168.1.100")
		fmt.Println("  quickssh host delete server.example.com")
	case "host change":
		fmt.Println("用法: quickssh host change <主机标识>")
		fmt.Println("  修改现有主机的配置")
		fmt.Println("  注意：此功能尚未实现")
	case "password":
		fmt.Println("用法: quickssh password <操作> [参数]")
		fmt.Println("\n可用操作:")
		fmt.Println("  list    - 列出所有已保存的密码")
		fmt.Println("  add     - 添加新密码")
		fmt.Println("  delete  - 删除已保存的密码")
		fmt.Println("\n使用 'quickssh help password <操作>' 获取具体操作的详细帮助")
	case "password add":
		fmt.Println("用法: quickssh password add <密码>")
		fmt.Println("  添加新密码到密码库")
		fmt.Println("\n示例:")
		fmt.Println("  quickssh password add password123")
	case "password delete":
		fmt.Println("用法: quickssh password delete <密码>")
		fmt.Println("  从密码库中删除指定密码")
		fmt.Println("\n示例:")
		fmt.Println("  quickssh password delete password123")
	default:
		fmt.Printf("未找到关于 '%s' 的帮助信息\n", topic)
		showHelp("")
	}
}

func readPasswords() ([]string, error) {
	filePath := expandPath(passwordsPath)

	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		file, err := os.Create(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to create passwords file: %v", err)
		}
		file.Close()
		return []string{}, nil
	}

	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read passwords file: %v", err)
	}

	passwords := []string{}
	for _, line := range strings.Split(string(data), "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			passwords = append(passwords, trimmed)
		}
	}
	return passwords, nil
}

func savePasswords(passwords []string) error {
	filePath := expandPath(passwordsPath)
	content := strings.Join(passwords, "\n")
	err := ioutil.WriteFile(filePath, []byte(content), 0600)
	if err != nil {
		return fmt.Errorf("failed to write passwords file: %v", err)
	}
	return nil
}

func addPassword(password string) {
	passwords, err := readPasswords()
	if err != nil {
		fmt.Println("Error reading passwords:", err)
		return
	}

	for _, p := range passwords {
		if p == password {
			fmt.Println("Password already exists")
			return
		}
	}

	passwords = append(passwords, password)
	if err := savePasswords(passwords); err != nil {
		fmt.Println("Error saving password:", err)
		return
	}
	fmt.Println("Password added successfully")
}

func deletePassword(password string) {
	passwords, err := readPasswords()
	if err != nil {
		fmt.Println("Error reading passwords:", err)
		return
	}

	found := false
	newPasswords := []string{}
	for _, p := range passwords {
		if p != password {
			newPasswords = append(newPasswords, p)
		} else {
			found = true
		}
	}

	if !found {
		fmt.Println("Password not found")
		return
	}

	if err := savePasswords(newPasswords); err != nil {
		fmt.Println("Error saving passwords:", err)
		return
	}
	fmt.Println("Password deleted successfully")
}

func listPasswords() {
	passwords, err := readPasswords()
	if err != nil {
		fmt.Println("Error reading passwords:", err)
		return
	}

	if len(passwords) == 0 {
		fmt.Println("No saved passwords")
		return
	}

	fmt.Println("Saved passwords:")
	for i, password := range passwords {
		fmt.Printf("%d. %s\n", i+1, password)
	}
}

func sshLogin(host string, passwords []string) {
	// 检查是否包含端口号
	hostname := host
	port := "22"
	if strings.Contains(host, ":") {
		parts := strings.Split(host, ":")
		hostname = parts[0]
		if len(parts) > 1 {
			port = parts[1]
		}
	}

	fmt.Printf("调试: 尝试连接到主机 %s 端口 %s\n", hostname, port)

	for i, password := range passwords {
		fmt.Printf("调试: 尝试密码 %d: %s\n", i+1, password)
		client, err := connectWithPassword(hostname, port, password)
		if err == nil {
			fmt.Println("登录成功，使用密码:", password)
			copyPublicKey(client)
			return
		}

		// 输出详细的错误信息
		fmt.Printf("连接失败: %v\n", err)

		// 可能的原因分析
		if strings.Contains(err.Error(), "unable to authenticate") {
			fmt.Println("原因：密码认证失败或拒绝")
		} else if strings.Contains(err.Error(), "connection refused") {
			fmt.Printf("原因：连接被拒绝 - SSH服务可能未运行或端口不是%s\n", port)
		} else if strings.Contains(err.Error(), "timeout") {
			fmt.Println("原因：连接超时 - 检查网络或防火墙设置")
		} else if strings.Contains(err.Error(), "no route") {
			fmt.Println("原因：无法访问主机 - 检查网络或主机名称是否正确")
		}
	}

	fmt.Println("所有密码尝试失败。")
	fmt.Println("\n提示: 尝试使用以下命令查看更多调试信息:")
	fmt.Printf("    ssh -v root@%s\n", host)
}

func sshLoginWithoutPassword(host string) {
	// 检查是否包含端口号
	hostname := host
	port := "22"
	if strings.Contains(host, ":") {
		parts := strings.Split(host, ":")
		hostname = parts[0]
		if len(parts) > 1 {
			port = parts[1]
		}
	}

	fmt.Printf("调试: 尝试无密码连接到 %s:%s\n", hostname, port)
	fmt.Println("尝试使用公钥认证或无密码方式登录...")

	config := &ssh.ClientConfig{
		User: "root",
		Auth: []ssh.AuthMethod{
			// 尝试使用SSH密钥
			tryPublicKeyAuth(),
			// 尝试无密码登录（在某些特殊配置中可能允许）
			ssh.Password(""),
		},
		Timeout:         10 * time.Second,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // 自动接受主机密钥
	}

	addr := fmt.Sprintf("%s:%s", hostname, port)
	fmt.Printf("调试: 完整连接地址 %s\n", addr)

	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		fmt.Printf("无密码登录失败: %v\n", err)
		fmt.Println("\n提示: 尝试使用以下命令查看更多调试信息:")
		fmt.Printf("    ssh -v root@%s\n", host)
		return
	}

	fmt.Println("登录成功！（使用公钥认证或无密码方式）")
	defer client.Close()

	// 如果登录成功，尝试交互式会话
	session, err := client.NewSession()
	if err != nil {
		fmt.Printf("无法创建会话: %v\n", err)
		return
	}
	defer session.Close()

	// 执行一个简单的命令来验证连接
	output, err := session.CombinedOutput("whoami")
	if err != nil {
		fmt.Printf("执行命令失败: %v\n", err)
		return
	}

	fmt.Printf("已连接为用户: %s\n", strings.TrimSpace(string(output)))
}

func connectWithPassword(host, port, password string) (*ssh.Client, error) {
	fmt.Printf("调试: 正在建立连接到 %s:%s...\n", host, port)

	config := &ssh.ClientConfig{
		User: "root",
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		// 增加超时配置
		Timeout: 10 * time.Second,
		// 自动接受主机密钥
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	addr := fmt.Sprintf("%s:%s", host, port)
	fmt.Printf("调试: 完整连接地址 %s\n", addr)

	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return nil, fmt.Errorf("SSH连接错误: %v", err)
	}

	// 尝试创建会话来验证连接是否真的成功
	session, err := client.NewSession()
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("无法创建SSH会话: %v", err)
	}
	session.Close()

	return client, nil
}

// 尝试获取SSH密钥认证方式
func tryPublicKeyAuth() ssh.AuthMethod {
	// 尝试多个可能的私钥位置
	keyFiles := []string{
		filepath.Join(getUserHomeDir(), ".ssh", "id_rsa"),
		filepath.Join(getUserHomeDir(), ".ssh", "id_dsa"),
		filepath.Join(getUserHomeDir(), ".ssh", "id_ed25519"),
		filepath.Join(getUserHomeDir(), ".ssh", "id_ecdsa"),
	}

	for _, keyPath := range keyFiles {
		fmt.Printf("调试: 尝试加载SSH密钥: %s\n", keyPath)
		key, err := ioutil.ReadFile(keyPath)
		if err != nil {
			fmt.Printf("调试: 无法读取密钥 %s: %v\n", keyPath, err)
			continue
		}

		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			fmt.Printf("调试: 无法解析密钥 %s: %v\n", keyPath, err)
			continue
		}

		fmt.Printf("调试: 成功加载SSH密钥: %s\n", keyPath)
		return ssh.PublicKeys(signer)
	}

	fmt.Println("调试: 没有找到可用的SSH密钥")
	return ssh.PublicKeys()
}

func copyPublicKey(client *ssh.Client) {
	pubKeyPath := filepath.Join(getUserHomeDir(), ".ssh", "id_rsa.pub")
	pubKey, err := ioutil.ReadFile(pubKeyPath)
	if err != nil {
		fmt.Println("Failed to read public key:", err)
		return
	}
	session, err := client.NewSession()
	if err != nil {
		fmt.Println("Failed to create session:", err)
		return
	}
	defer session.Close()

	cmd := fmt.Sprintf("echo '%s' >> ~/.ssh/authorized_keys", strings.TrimSpace(string(pubKey)))
	if err := session.Run(cmd); err != nil {
		fmt.Println("Failed to copy public key:", err)
		return
	}
	fmt.Println("Public key copied successfully.")
}

func listHosts() {
	configPath := expandPath(sshConfigPath)

	// 检查配置文件是否存在，如果不存在则创建
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		createEmptySSHConfig()
		fmt.Println("创建了新的SSH配置文件")
		return
	}

	file, err := os.Open(configPath)
	if err != nil {
		fmt.Println("无法打开SSH配置文件:", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fmt.Println(scanner.Text())
	}
}

func addHost(host string) {
	hostInfo := map[string]string{
		"hostname": host,
		"alias":    host,
		"user":     "root",
		"port":     "22",
	}
	addHostWithInfo(hostInfo)
}

func addHostWithInfo(hostInfo map[string]string) {
	configPath := expandPath(sshConfigPath)

	// 检查配置文件是否存在，如果不存在则创建
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		createEmptySSHConfig()
		fmt.Println("创建了新的SSH配置文件")
	}

	file, err := os.OpenFile(configPath, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		fmt.Println("无法打开SSH配置文件:", err)
		return
	}
	defer file.Close()

	entry := fmt.Sprintf("\nHost %s\n\tHostName %s\n\tUser %s\n\tPort %s\n",
		hostInfo["alias"],
		hostInfo["hostname"],
		hostInfo["user"],
		hostInfo["port"])

	if _, err := file.WriteString(entry); err != nil {
		fmt.Println("无法写入SSH配置文件:", err)
	}
	fmt.Println("主机添加成功。")
}

func deleteHost(host string) {
	configPath := expandPath(sshConfigPath)

	// 检查配置文件是否存在，如果不存在则创建
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		createEmptySSHConfig()
		fmt.Println("创建了新的SSH配置文件，但其中没有要删除的主机")
		return
	}

	input, err := ioutil.ReadFile(configPath)
	if err != nil {
		fmt.Println("无法读取SSH配置文件:", err)
		return
	}

	lines := strings.Split(string(input), "\n")
	output := []string{}
	skip := false
	for _, line := range lines {
		if strings.HasPrefix(line, "Host ") && strings.Contains(line, host) {
			skip = true
		} else if skip && strings.TrimSpace(line) == "" {
			skip = false
		} else if !skip {
			output = append(output, line)
		}
	}

	if err := ioutil.WriteFile(configPath, []byte(strings.Join(output, "\n")), 0600); err != nil {
		fmt.Println("无法写入SSH配置文件:", err)
	}
	fmt.Println("主机删除成功。")
}

// 创建空的SSH配置文件
func createEmptySSHConfig() {
	configPath := expandPath(sshConfigPath)

	// 确保~/.ssh目录存在
	sshDir := filepath.Dir(configPath)
	if _, err := os.Stat(sshDir); os.IsNotExist(err) {
		if err := os.MkdirAll(sshDir, 0700); err != nil {
			fmt.Println("无法创建~/.ssh目录:", err)
			return
		}
	}

	// 创建空的配置文件
	file, err := os.Create(configPath)
	if err != nil {
		fmt.Println("无法创建SSH配置文件:", err)
		return
	}
	defer file.Close()

	// 写入一些基本注释
	initialContent := "# SSH配置文件\n" +
		"# 格式: Host [别名]\n" +
		"#       HostName [主机名或IP]\n" +
		"#       User [用户名]\n" +
		"#       Port [端口号]\n\n"

	if _, err := file.WriteString(initialContent); err != nil {
		fmt.Println("无法写入SSH配置文件:", err)
	}

	fmt.Println("创建了新的SSH配置文件:", configPath)
}

func changeHost(host string) {
	fmt.Println("Change host functionality not implemented yet.")
}

// 添加新的函数：解析主机参数
func parseHostArgs(args []string) map[string]string {
	result := map[string]string{
		"hostname": args[0],
		"user":     "root",
		"port":     "22",
		"alias":    args[0],
	}

	for i := 1; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "user=") {
			result["user"] = strings.TrimPrefix(arg, "user=")
		} else if strings.HasPrefix(arg, "port=") {
			result["port"] = strings.TrimPrefix(arg, "port=")
		} else if strings.HasPrefix(arg, "alias=") {
			result["alias"] = strings.TrimPrefix(arg, "alias=")
		}
	}

	return result
}
