# PacketStorm - High-Performance Network Packet Generator


![Qt](https://img.shields.io/badge/Qt-5.15%20%7C%206.x-green.svg)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey.svg)

**PacketStorm** 是一个基于 **Qt (C++)** 和 **WinPcap/Npcap** 开发的高性能网络发包工具。它专为网络调试、压力测试和协议栈验证设计，支持自定义构造 UDP、TCP、ICMP 和 DNS 数据包，并提供微秒级的发送间隔控制。

> **注意**: 本项目仅供学习、网络调试和合法测试使用，请勿用于非法用途。

---

## ✨ 主要功能 (Features)

* **多协议支持**:
    * **UDP**: 自定义源/目的端口、载荷长度。
    * **TCP**: 支持自定义 **Flags** (SYN, ACK, PSH, FIN, RST)，模拟握手或攻击流量。
    * **ICMP**: 发送 Echo Request (Ping) 数据包。
    * **DNS**: 支持自定义查询域名 (Domain Name)。
* **全字段编辑**: 自由配置源/目的 MAC 地址、IP 地址。
* **高精度发包**:
    * 支持微秒 (µs) 级发送间隔设置。
    * 采用 **批量发送 (Batching)** 策略，在高吞吐量下保持 UI 流畅。
* **网卡自动枚举**: 自动识别并列出系统中的网络适配器。
* **现代化 UI**: 基于 Qt Fusion 风格的深色主题界面，交互直观。

## 🛠️ 构建依赖 (Requirements)

在编译本项目之前，请确保您的开发环境满足以下要求：

1.  **Qt 开发环境**:
    * Qt 5.14+ 或 Qt 6.x
    * 编译器: MSVC 2019+ 或 MinGW 64-bit
2.  **Npcap SDK** (核心依赖):
    * 本项目依赖 `pcap.h` 和 `packet.lib`。
    * 请访问 [Npcap 官网](https://npcap.com/#download) 下载 **Npcap SDK**。
3.  **运行环境**:
    * 运行程序的电脑必须安装 [Npcap Installer](https://npcap.com/#download)。
    * **重要**: 安装时必须勾选 **"Install Npcap in WinPcap API-compatible Mode"**。

## 🚀 编译指南 (Build Instructions)

1.  **克隆仓库**:
    ```bash
    git clone [https://github.com/YourUsername/PacketStorm-Sender.git](https://github.com/YourUsername/PacketStorm-Sender.git)
    cd PacketStorm-Sender
    ```

2.  **配置 Npcap SDK**:
    * 将下载的 Npcap SDK 解压到某个目录（例如 `C:/Npcap-SDK`）。
    * 打开 `PacketStorm_Sender.pro` 文件，找到 `INCLUDEPATH` 和 `LIBS` 设置，修改为您本地的 SDK 路径：
        ```qmake
        # 示例 (请根据实际路径修改)
        INCLUDEPATH += C:/Npcap-SDK/Include
        LIBS += -LC:/Npcap-SDK/Lib/x64 -lwpcap -lpacket
        ```

3.  **构建项目**:
    * 使用 Qt Creator 打开 `.pro` 文件。
    * 选择 Release 模式。
    * 点击 **Build (构建)**。

## 📖 使用说明 (Usage)

1.  **选择网卡**: 在 "Interface Selection" 下拉框中选择用于发包的网卡。
2.  **配置地址**: 填写源/目的 MAC 和 IP 地址。
3.  **选择协议**:
    * **TCP**: 勾选需要的标志位 (如 SYN 用于测试连接建立)。
    * **DNS**: 输入需要查询的域名 (如 `www.google.com`)。
    * **UDP**: 设置端口和载荷长度。
4.  **设置参数**:
    * **Interval (µs)**: 设置发包间隔（例如 1000µs = 1ms）。设置为 0 表示全速发送。
5.  **开始发送**: 点击 **START SENDING** 按钮。

## 📂 项目结构 (Project Structure)

* `sender_core.h/cpp`: 底层发包核心逻辑，封装了 WinPcap 发送队列、协议头构造 (Ethernet, IP, UDP, TCP, DNS)。
* `SenderWindow.h/cpp`: Qt GUI 逻辑，负责参数获取、线程控制和 UI 更新。
* `sender.ui`: 界面布局文件。

## ⚠️ 免责声明 (Disclaimer)

本软件仅用于网络测试、性能评估和教育目的。使用者应遵守当地法律法规。对于因使用本软件造成的任何直接或间接损失（包括但不限于网络瘫痪、服务中断），开发者不承担任何责任。

---

**PacketStorm Sender** © 2025 Created by jintianwenwenzaoshuilema.