# NetAttackClassifier
一个基于Snort规则和ATT&CK框架的网络流量分析与威胁分类工具

* 🕵️♂️ 基于Snort的异常流量检测
* 🎯 ATT&CK技战术映射
* 🧬 高细粒度流量分类

## 项目简介
在训练流量分类模型时, 大部分都使用网络上的公开数据集, 但都存在一个共同的缺点, 就是对于流量的分类细粒度不够, 如果能把流量中使用的漏洞编号、漏洞细节都区分出来才是在使用在实战中, 但大部分数据集的构造方式要么是根据已知漏洞方式、恶意软件类型去产生对应的流量(例如`https://github.com/yungshenglu/USTC-TFC2016`、`https://github.com/safest-place/ExploitPcapCollection`), 要么就是大量人工根据搜索引擎、漏洞编号库等方式进行人工分类(我了解到的一些安全公司).
所以写了一个根据 Snort 对流量进行检测, 让大模型对日志进行分析, 使其和ATT&CK技战术进行映射, 从而能让流量进行高细粒度分类

## 项目功能

* pcap 文件检测：使用Snort规则对大量pcap文件进行检测，快速识别出符合规则的可疑数据包及其对应的网络流。
* ATTCK技战术映射：通过调用DeepSeek API，将检测到的可疑数据包所触发的Snort规则与MITRE ATTCK框架中的技战术进行映射，明确攻击者可能采用的攻击手法和阶段。
* 高细粒度多分类：对检测出的可疑pcap流进行进一步的细分和分类，从多个维度（如攻击类型、目标系统、攻击工具等）进行详细标注和归类，为后续的安全分析和响应提供更精准的信息。

## 环境搭建

* 安装 Snort, 配置相应的规则库(`https://www.snort.org/downloads#rules`), 我的搭建配置:

  ### **安装Snort 3依赖**

  ```bash
  # 更新系统
  sudo apt update && sudo apt upgrade -y

  # 安装编译依赖
  sudo apt install -y build-essential autotools-dev libdumbnet-dev \
  libluajit-5.1-dev libpcap-dev libpcre3-dev zlib1g-dev pkg-config \
  libhwloc-dev libcmocka-dev liblzma-dev openssl libssl-dev cpputest \
  libsqlite3-dev uuid-dev libtool git autoconf bison flex libnetfilter-queue-dev \
  libmnl-dev libunwind-dev libfl-dev libsafec-dev

  # 可选：安装Hyperscan（高性能正则表达式库）
  sudo apt install -y libhyperscan-dev

  # 安装CMake（用于构建依赖项）
  sudo apt install -y cmake
  ```

  ### **安装DAQ 3.x依赖**

  ```bash
  # 安装编译DAQ 3.x所需的依赖
  sudo apt install -y libpcap-dev libdumbnet-dev libssl-dev liblzma-dev \
  libcurl4-openssl-dev libhwloc-dev libcmocka-dev libpcre3-dev bison flex
  ```

  ### **下载并编译DAQ 3.x**

  ```bash
  # 下载DAQ 3.x源码
  cd ~/snort3_build
  git clone https://github.com/snort3/libdaq.git
  cd libdaq

  # 配置、编译和安装
  ./bootstrap
  ./configure --prefix=/usr/local
  make -j$(nproc)
  sudo make install

  # 更新动态库链接
  sudo ldconfig
  ```

  ### **下载并编译Snort 3**

  ```bash
  # 创建编译目录
  mkdir ~/snort3_build && cd ~/snort3_build

  # 下载Snort 3源码
  git clone https://github.com/snort3/snort3.git
  cd snort3

  # 配置编译选项
  ./configure_cmake.sh --prefix=/usr/local --enable-tcmalloc
  cd build

  # 编译并安装
  make -j$(nproc) && sudo make install
  ```

  ### **步骤 4：配置环境变量**

  ```bash
  # 添加Snort 3到PATH
  echo 'export PATH=/usr/local/bin:$PATH' >> ~/.bashrc
  source ~/.bashrc

  # 验证安装
  snort -V
  ```

* ```bash
  pip install openai
  ```

## 使用方法

1. 将pcap文件放置在指定的输入目录下。
2. 运行`run_snort.py`, 对pcap进行批量检测, 并对日志内容进行解析, 提取威胁信息到指定 json 文件中。
3. 运行`extract_tcp_streams.py`, 首先使用`SplitCap.exe`(`https://www.netresec.com/?page=SplitCap`)对pcap进行TCP双向流分流操作, 再检索 json 文件中存在告警的包, 计算整条流中每个包的`规则优先级`、`触发频次`、`协议一致性`, 得到同一条流中每个包的`加权平均分数`, 选取得分最高包的告警最为该流的告警, 这是为了让 Snort 的包检测机制与大部分模型的流检测机制对应起来, 从而得到分流后的pcap数据包和与之对应的 json 文件, 例如:

    ```json
    {
      "timestamp": "09/06-01:18:41.206357",
      "gid": 1,
      "sid": 45015,
      "rev": 3,
      "description": "FILE-OTHER Jackson databind deserialization remote code execution attempt",
      "classification": "Attempted User Privilege Gain",
      "priority": 1,
      "protocol": "TCP",
      "src_ip": "192.168.56.1",
      "dst_ip": "192.168.56.11",
      "src_port": 1056,
      "dst_port": 8090,
      "pcap_path": "/Users/lnhsec/Desktop/NetAttackClassifier/extracted_streams/fastjson1224ldap/192.168.56.1_1056_to_192.168.56.11_8090.pcap",
      "weight_score": 0.8031363764158987,
      "priority_score": 1.0,
      "frequency_score": 0.47712125471966244,
      "protocol_score": 0.8,
      "alert_count": 2
    }
    ```

4. 运行`gpt_analysis.py`, 从上面的 json 文件提取重要流量信息, 构造相应提示词, 提交给gpt对其与MITRE ATTCK框架中的技战术进行映射, 得到对应 json 结果, 例如:

    ```json
    {
      "attack_tactics": {
        "TA0006": "T1110"
      },
      "rule_trigger_reason": "An attempted Oracle login with a suspicious username triggered a misparsed login response alert",
      "attack_type": "Credential Brute Force Attempt",
      "behavior_pattern": "Suspicious username used in login attempt to Oracle server via TCP/1521",
      "threat_level": "medium",
      "suggested_action": "1. Investigate source IP 192.168.1.20 for compromise 2. Review Oracle account activity 3. Enforce strong authentication policies",
      "confidence": 0.9,
      "dynamic_behavior": {
        "network": {
          "ip": "192.168.1.20",
          "dns": ""
        }
      },
      "pcap_path": "/Users/lnhsec/Desktop/NetAttackClassifier/extracted_streams/msf_oracle_sid_brute/192.168.1.20_1521_to_192.168.1.14_34055.pcap"
    }

    ```

    提示词如下:

    ```python
    def construct_prompt(key_info):
        prompt = """根据Snort告警进行网络安全事件分析，要求：
            1. 严格遵循MITRE ATT&CK技战术框架分类
            2. attack_tactics字段必须包含相关TA和T编号
            3. 每个TA编号必须对应具体且正确的的T技术编号
        """
        prompt += "根据以下 Snort 告警信息，进行分析并按照 JSON 格式返回：\n"
        for entry in key_info:
            prompt += (
                f"时间: {entry['timestamp']}, 告警ID: {entry['sid']}:{entry['gid']}:{entry['rev']}, "
                f"描述: {entry['description']}, 分类: {entry['classification']}, "
                f"优先级: {entry['priority']}, 协议: {entry['protocol']}, "
                f"源IP: {entry['src_ip']}:{entry['src_port']}, 目的IP: {entry['dst_ip']}:{entry['dst_port']}\n"
            )

        prompt += '''\n请回答以下问题并返回 JSON 格式:
            {
            "attack_tactics": {"TAxxxx": "Txxxx"},
            "rule_trigger_reason": "xxx",
            "attack_type": "xxx",
            "behavior_pattern": "xxx",
            "threat_level": "low/medium/high/critical",
            "suggested_action": "xxx",
            "confidence": 0.9,
            "dynamic_behavior": {
                "network": {"ip": "xxx", "dns": "xxx"}
            }
        }'''
        prompt += "\n请严格返回符合 JSON 格式的内容，不要包含其他说明文字，只返回 JSON 串。"
        print(f"构造的 DeepSeek API 输入内容: {prompt}")
        return prompt
    ```

5. 最终根据技战术或者`attack_type`对相应文件进行分类操作

## 未来方向

1. **规则库优化：** 因规则库的不同类型、版本, 很多已知恶意pcap并没有被 Snort 检测出来, 这会导致很多漏报或者误报
2. **检测机制改进：** 在包检测与流检测的对应方法需要进一步完善, 查看是否有更好的办法
3. **性能优化：** 调用gpt api进行映射的时间成本较高, 尝试过 deepseek-v3 模型(较快, 但存在乱说的情况), deepseek-r1 模型(很慢, 但是较为准确), 看后续用不用添加部分知识库, 使用其他较快模型进行映射