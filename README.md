# xdsrun - 西电深澜校园网命令行认证客户端

[![Build Status](https://github.com/NanCunChild/xdsrun-login/actions/workflows/release.yml/badge.svg)](https://github.com/NanCunChild/xdsrun-login/actions/workflows/release.yml)
[![Latest Release](https://img.shields.io/github/v/release/NanCunChild/xdsrun-login)](https://github.com/NanCunChild/xdsrun-login/releases/latest)

> 一个用于西安电子科技大学（西电）深澜校园网的跨平台、轻量级命令行认证客户端。

## 简介

在校园网环境中，特别是对于无图形界面的嵌入式设备（如树莓派）和无头Linux服务器，通过浏览器进行Web认证非常繁琐甚至无法实现。`xdsrun` 旨在解决这一痛点，它将复杂的Web认证流程封装成一个简单的命令行工具，让你可以在任何设备上轻松完成联网认证。

本项目使用 Go 语言编写，天然支持跨平台编译，无需任何额外依赖即可在多种CPU架构上原生运行。

## 功能特性

- **跨平台支持**: 可在 `Windows`, `Linux`, `macOS` 等操作系统及 `x86`, `ARMv7`, `ARMv8 (aarch64)`, `MIPS`, `RISC-V`, `LoongArch` 等多种架构上运行。
- **纯命令行接口**: 简单直观的参数，易于集成到开机自启脚本或自动化流程中。
- **状态查询**: 可随时查询当前网络的在线状态、已用流量、时长和余额等信息。
- **并行请求处理**: 当主认证域名 (`w.xidian.edu.cn`) 与IP地址 (`10.255.44.33`) 同时进行连接，增强稳定性。

## 开发历程与技术挑战

本工具的开发并非简单的表单模拟提交。西安电子科技大学的深澜认证门户采用了一套基于JavaScript的动态加密方案，给逆向分析带来了一定的挑战。

开发过程中遇到的主要难点是 `info` 认证字段的生成。起初分析发现它使用了 XXTEA 加密算法，但使用任何标准的XXTEA库加密得到的结果都会被服务器拒绝，并返回 `auth_info_error`。

最关键的突破在于，在某位逆向大师的帮助下，我们发现其 **`info` 字段的加密并非使用标准的XXTEA算法**。前端JavaScript代码中的 **核心MX混合函数（Mixing Function）被修改了**，它改变了标准算法中不同计算部分的组合方式（将部分异或运算改为了加法运算）。

因此，本项目的核心是**在Go语言中精确地复现了这个魔改版的XXTEA算法**，从而生成了服务器认可的 `info` 字段，最终成功完成了认证。

## 使用方法

### 1. 下载

前往本项目的 [**Releases 页面**](https://github.com/NanCunChild/xdsrun-login/releases) 下载最新版本的程序。

请根据你的操作系统和CPU架构选择对应的文件，例如：

- Windows (64位): `xdsrun_x.x.x_windows_amd64.zip`
- Linux (64位): `xdsrun_x.x.x_linux_amd64.tar.gz`
- 树莓派等arm Linux设备 (ARMv8/aarch64): `xdsrun_x.x.x_linux_arm64.tar.gz`

### 2. 准备运行

- **Windows**: 解压 `zip` 文件，得到 `xdsrun.exe`，直接在 `cmd` 或 `PowerShell` 中使用。
- **Linux / macOS**: 解压 `tar.gz` 文件，得到 `xdsrun`。首先需要赋予它可执行权限：

  ```bash
  chmod +x ./xdsrun
  ```

### 3. 执行命令

#### 登录认证

使用 `-u` 指定账号。未使用 `-p` 时，如果标准输入是可交互终端，程序会以不回显的方式提示输入密码；在定时任务、容器等非交互环境中则会直接报错，避免等待输入。如果密码包含特殊字符，请用单引号将其包围。

```Bash
# 基本用法
./xdsrun -u 你的学号 -p 你的密码

# 密码包含特殊字符的用法
./xdsrun -u 23000000000 -p 'password@!#$'

# 交互式输入密码（输入内容不会回显）
./xdsrun -u 23000000000

# 如果需要指定运营商（例如电信），使用 -d 参数
./xdsrun -u 你的学号 -p 你的密码 -d @dx
```

成功后，程序会提示 `IP "xxx.xxx.xxx.xxx" 已授权！` 。

程序默认同时尝试通过 `w.xidian.edu.cn` 和固定 IP `10.255.44.33` 连接认证服务。固定 IP 通道只绕过 DNS 解析，HTTPS 请求仍使用域名进行证书校验。

如果校园网认证服务存在证书错误，可显式添加 `-k` 或 `--insecure` 忽略证书校验。该选项会降低连接安全性，仅应在确认认证服务可信时使用。

其他学校可尝试通过 `--portal` 覆盖认证地址，并按需用 `--portal-ip` 指定绕过 DNS 的地址：

```bash
./xdsrun -u 你的账号 -p '你的密码' --portal https://portal.example.edu --portal-ip 192.0.2.10
```

此配置仅提供 best-effort 兼容；程序仍固定使用西电当前采用的 `ac_id=8` 和认证协议，不承诺适配其他学校的 Portal 实现。

#### 环境变量

定时任务和容器可通过环境变量配置登录信息。命令行参数的优先级高于对应的环境变量。

| 环境变量 | 对应参数 | 说明 |
| --- | --- | --- |
| `XDSRUN_USERNAME` | `-u` | 校园网账号 |
| `XDSRUN_PASSWORD` | `-p` | 校园网密码 |
| `XDSRUN_DOMAIN` | `-d` | 运营商后缀，如 `@dx` |
| `XDSRUN_PORTAL` | `--portal` | Portal 地址，默认为 `https://w.xidian.edu.cn` |
| `XDSRUN_PORTAL_IP` | `--portal-ip` | 绕过 DNS 直连的 Portal IP |

```bash
XDSRUN_USERNAME=23000000000 \
XDSRUN_PASSWORD='password@!#$' \
./xdsrun
```

环境变量中的密码可能被同一主机上有权限查看进程环境的用户或工具读取。应限制运行账户和配置文件权限，避免将密码提交到镜像、仓库或公开的任务配置中。

#### 查询在线状态

使用 -s 标志。此模式下无需账号密码。

```Bash
./xdsrun -s
```

程序会打印出你当前的账号、已用流量、余额等信息。如果提示未登录，请先执行登录操作。

### ★从源码编译

如果你希望自行编译：

确保你已安装 Go (版本 >= 1.20)。

克隆本仓库：

```Bash
git clone https://github.com/NanCunChild/xdsrun-login.git
cd xdsrun-login
```

执行编译：

```Bash
# 编译当前平台的版本
go build -o xdsrun .

# 交叉编译Linux ARM64版本
GOOS=linux GOARCH=arm64 go build -o xdsrun-linux-arm64 .
```

## 致谢

特别感谢这位逆向的同学，精准地指出了项目中最核心的XXTEA算法变体问题，没有他的帮助，这个项目将难以完成。
同时也感谢一下NCC自己~ 如果喜欢这个项目，那就给NCC打个星星吧~

## 参考

NCC在完成逆向之后才看到目前已经有很多对深澜JS源码的逆向分析了，主要加密点为XETAA的魔改S盒子，还有做过调换的base64 。放置部分文章供参考：

[wust武科大校园网深澜srun认证api分析](https://huhu.ciduid.top/2022/1113/srun-login-analyze/)

[深大 srun 认证流程分析](https://www.caterpie771.cn/archives/364)

[Github-UCAS-Network-Login-for-SRUN](https://github.com/Jon-QQQ/UCAS-Network-Login-for-SRUN)
