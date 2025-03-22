import json
import os
import subprocess
import math
import tempfile
import shutil

def extract_json(input_path: str, output_dir: str, key: str) -> None:
    """从输入目录中提取所有 JSON 文件，并pcap流的全部包检测结果输出到指定的输出目录中。"""
    results = {}
    for root, dirs, files in os.walk(input_path):
        for file in files:
            if file.endswith('.json'):
                file_path = os.path.join(root, file)
                if os.path.getsize(file_path) > 0:
                    with open(file_path) as f:
                        try:
                            data = json.load(f)
                            log_entries = data.get(key, [])
                            pcap_path = data.get('pcap_path', 'N/A') # 添加 pcap_path 字段
                            if pcap_path not in results:
                                results[pcap_path] = []
                            for entry in log_entries:
                                if all(k in entry for k in ('src_ip', 'dst_ip', 'src_port', 'dst_port')):
                                    entry['pcap_path'] = pcap_path  # Add pcap_path to each entry
                                    results[pcap_path].append(entry)
                        except json.JSONDecodeError:
                            print(f"Error decoding JSON from file: {file_path}")
                else:
                    print(f"Skipping empty file: {file_path}")
    
    with open(output_dir, 'w') as f:
        json.dump(results, f, indent=4)
    
    return results

def check_inconsistencies(results: dict) -> list:
    """检查结果中是否存在不一致的TCP流"""
    five_tuple_entries = {}
    
    # 收集所有相同五元组的entries
    for pcap_path, entries in results.items():
        for entry in entries:
            five_tuple = (
                entry['src_ip'], 
                entry['dst_ip'], 
                entry['protocol'], 
                entry['src_port'], 
                entry['dst_port']
            )
            if five_tuple not in five_tuple_entries:
                five_tuple_entries[five_tuple] = []
            five_tuple_entries[five_tuple].append(entry)
    
    def calculate_weight(entries):
        """计算entries的权重"""
        # 1. 规则优先级得分
        priorities = [int(entry.get('priority', 3)) for entry in entries]
        min_priority = min(priorities)
        priority_score = max(0, (5 - min_priority) / 4)
        
        # 2. 触发频次得分
        frequency = len(entries)
        frequency_score = min(1.0, math.log(frequency + 1) / math.log(10))
        
        # 3. 协议一致性得分
        # 基于ATT&CK战术和技术以及Snort规则类型的关键词
        security_keywords = {
            # ATT&CK相关
            'initial access', 'execution', 'persistence', 'privilege escalation',
            'defense evasion', 'credential access', 'discovery', 'lateral movement',
            'collection', 'exfiltration', 'command and control', 'impact',
            'backdoor', 'exploit', 'malware', 'ransomware', 'spyware', 'trojan',
            'reconnaissance', 'brute force', 'credential dumping', 'keylogging',
            
            # Snort规则相关
            'overflow', 'injection', 'xss', 'sqli', 'rce', 'traversal', 
            'bypass', 'disclosure', 'unauthorized', 'suspicious', 'malicious',
            'attack', 'compromise', 'scan', 'probe', 'attempt', 'violation',
            'shell', 'upload', 'access', 'admin', 'root', 'id', 'privilege'
            
            # 常见攻击类型
            'buffer', 'format string', 'race condition',
            'memory corruption', 'heap spray', 'stack overflow', 'csrf',
            'directory traversal', 'file inclusion', 'command injection',
            'code execution', 'privilege', 'escalation'
        }
        
        def calculate_security_score(entry):
            """计算权重"""
            desc = entry.get('description', '').lower()
            class_info = entry.get('classification', '').lower()
            msg = entry.get('msg', '').lower()  # 添加msg字段检查
            text = f"{desc} {class_info} {msg}"
            
            # 计算匹配的关键词数量
            matched_keywords = sum(1 for keyword in security_keywords if keyword in text)
            # 归一化得分
            return min(1.0, matched_keywords / 5)  # 假设匹配5个或以上关键词为满分
        
        # 使用最高的安全得分
        protocol_score = max(calculate_security_score(entry) for entry in entries)
        
        # 计算加权平均分数
        final_score = (
            0.5 * priority_score +
            0.3 * frequency_score +
            0.2 * protocol_score
        )
        
        return final_score, {
            'priority_score': priority_score,
            'frequency_score': frequency_score,
            'protocol_score': protocol_score,
            'min_priority': min_priority,
            'alert_count': frequency
        }
    
    # 存储所有entry及其得分
    scored_entries = []
    for five_tuple, entries in five_tuple_entries.items():
        weight, scores = calculate_weight(entries)
        
        # 对于每个五元组，选择优先级最高的entry
        best_entry = min(entries, key=lambda x: (
            int(x.get('priority', 3)),  # 首先按优先级排序
            -len(x.get('description', '')),  # 其次选择描述信息最详细的
            -len(x.get('classification', '')),  # 再次选择分类信息最详细的
            x.get('timestamp', '')  # 最后选择最早的告警
        ))
        
        # 添加权重相关信息
        best_entry['weight_score'] = weight
        best_entry['priority_score'] = scores['priority_score']
        best_entry['frequency_score'] = scores['frequency_score']
        best_entry['protocol_score'] = scores['protocol_score']
        best_entry['alert_count'] = scores['alert_count']
        
        scored_entries.append(best_entry)
    
    # 按多个条件排序
    scored_entries.sort(key=lambda x: (
        x['weight_score'],  # 首先按总权重降序
        x['priority_score'],  # 相同权重按优先级得分降序
        x['frequency_score'],  # 再按频次得分降序
        x['protocol_score'],  # 最后按协议一致性得分降序
        -int(x.get('priority', 3))  # 如果还相同，选择原始优先级更高的
    ), reverse=True)
    
    return scored_entries

def process_inconsistencies(inconsistencies: list, output_dir: str) -> None:
    """处理不一致的告警，并生成最终的告警列表"""
    os.makedirs(output_dir, exist_ok=True)
    
    # 按pcap文件路径分组五元组
    pcap_groups = {}
    for inconsistency in inconsistencies:
        pcap_path = inconsistency['pcap_path']
        if pcap_path not in pcap_groups:
            pcap_groups[pcap_path] = []
        pcap_groups[pcap_path].append(inconsistency)
    
    # 对每个pcap文件只执行一次SplitCap
    for pcap_path, entries in pcap_groups.items():
        process_single_pcap(pcap_path, entries, output_dir)

def process_single_pcap(pcap_path: str, entries: list, output_dir: str) -> None:
    """对单个pcap文件处理多个五元组"""
    pcap_name = os.path.basename(pcap_path)
    pcap_dir = os.path.join(output_dir, pcap_name.replace('.pcap', ''))
    os.makedirs(pcap_dir, exist_ok=True)
    
    # 创建临时目录用于SplitCap输出
    temp_dir = tempfile.mkdtemp()
    try:
        # 使用SplitCap进行会话拆包 - 只执行一次
        splitcap_cmd = [
            'mono', 'SplitCap.exe',
            '-r', pcap_path,           # 输入文件
            '-o', temp_dir,            # 输出到临时目录
            '-s', 'session',           # 使用会话模式
            '-y', 'pcap'               # 输出完整pcap帧
        ]
        
        print(f"执行命令: {' '.join(splitcap_cmd)}")
        subprocess.run(splitcap_cmd, check=True)
        
        # 查找临时目录中的所有pcap文件
        pcap_files = [f for f in os.listdir(temp_dir) if f.endswith('.pcap')]
        print(f"在临时目录中找到的文件: {len(pcap_files)} 个文件")
        
        # 处理每个五元组条目
        for entry in entries:
            five_tuple = (
                entry['src_ip'],
                entry['dst_ip'],
                entry['protocol'],
                entry['src_port'],
                entry['dst_port']
            )
            process_five_tuple(five_tuple, temp_dir, pcap_files, pcap_dir, entry)
    
    except subprocess.CalledProcessError as e:
        print(f"运行SplitCap时出错: {e}")
    except Exception as e:
        print(f"处理会话时出错: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # 清理临时目录
        shutil.rmtree(temp_dir, ignore_errors=True)
        print(f"已清理临时目录: {temp_dir}")

def process_five_tuple(five_tuple: tuple, temp_dir: str, pcap_files: list, 
                       pcap_dir: str, json_entry: dict) -> None:
    """处理单个五元组的匹配和复制"""
    src_ip, dst_ip, protocol, src_port, dst_port = five_tuple
    
    # 转换IP格式来匹配SplitCap生成的文件名
    src_ip_dash = src_ip.replace('.', '-')
    dst_ip_dash = dst_ip.replace('.', '-')
    src_port_str = str(src_port)
    dst_port_str = str(dst_port)
    
    # 查找匹配的文件
    matched_files = []
    for file in pcap_files:
        # 检查是否包含所有四个元素：两个IP和两个端口
        has_src_ip = src_ip_dash in file
        has_dst_ip = dst_ip_dash in file
        has_src_port = src_port_str in file
        has_dst_port = dst_port_str in file
        
        if has_src_ip and has_dst_ip and has_src_port and has_dst_port:
            matched_files.append(file)
    
    print(f"五元组 {five_tuple} 找到 {len(matched_files)} 个匹配的文件")
    
    if matched_files:
        # 目标文件路径
        output_file = os.path.join(pcap_dir, f"{src_ip}_{src_port}_to_{dst_ip}_{dst_port}.pcap")
        json_file = os.path.join(pcap_dir, f"{src_ip}_{src_port}_to_{dst_ip}_{dst_port}.json")
        
        # 复制第一个匹配的文件到目标位置
        shutil.copy2(os.path.join(temp_dir, matched_files[0]), output_file)
        
        # 更新JSON条目中的pcap路径
        json_entry['pcap_path'] = output_file
        
        # 保存JSON文件
        with open(json_file, 'w') as jf:
            json.dump(json_entry, jf, indent=2)
        
        print(f"成功提取会话到 {output_file} 并保存JSON到 {json_file}")
    else:
        print(f"未找到与五元组匹配的会话: {five_tuple}")
        print(f"寻找元素: src_ip_dash={src_ip_dash}, dst_ip_dash={dst_ip_dash}, src_port={src_port_str}, dst_port={dst_port_str}")

def main():
    input_path = '/Users/lnhsec/Desktop/Lnh/github/NetAttackClassifier/snort_result'
    out_file = '/Users/lnhsec/Desktop/Lnh/github/NetAttackClassifier/output.json'
    output_dir = '/Users/lnhsec/Desktop/Lnh/github/NetAttackClassifier/extracted_streams'
    key = 'log_entries'

    results = extract_json(input_path, out_file, key)
    inconsistencies = check_inconsistencies(results)
    process_inconsistencies(inconsistencies, output_dir)

if __name__ == '__main__':
    main()