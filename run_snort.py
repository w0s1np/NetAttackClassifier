import threading
from openai import OpenAI
import subprocess
import os
import re
from scapy.all import rdpcap, wrpcap
import json
from collections import defaultdict
import sys
from concurrent.futures import ThreadPoolExecutor
import time
from pathlib import Path
import shutil

"""配置信息"""
SNORT_CONFIG = {
    'snort_path': 'snort',
    'config_path': '/usr/local/etc/snort/snort.lua',
    'log_dir': '/home/lnh/test/logs/'  # 存放 Snort 日志的目录
}

class Snort:
    def __init__(self,pcap_path):
        self.pcap_path = pcap_path

    def run_snort(self, pcap_path: str) -> bool:
        """运行 Snort 对 pcap 文件进行检测"""
        print(f"正在运行 Snort 对 pcap 文件 {pcap_path} 进行检测...")
        cmd = [
            SNORT_CONFIG['snort_path'],
            '-c', SNORT_CONFIG['config_path'], 
            "-A", "fast",
            "-l", SNORT_CONFIG['log_dir'],
            '-r', pcap_path,
            '-q'
        ]
        try:
            subprocess.run(cmd, check=True)
            print("Snort 运行完成。")
            return True
        except subprocess.CalledProcessError as e:
            print(f"Snort 运行失败: {str(e)}")
            return False
        
    def process_snort_logs(self) -> dict:
        """处理 Snort 日志，提取出威胁信息"""
        log_path: str = os.path.join(SNORT_CONFIG['log_dir'], "alert_fast.txt")

        if not os.path.exists(log_path):
            print("日志文件不存在，可能未检测到威胁。")
            return self.generate_empty_log_result()
        
        with open(log_path, 'r') as f:
            log_content: str = f.read().strip()

        # 解析日志内容，提取威胁信息
        if not log_content:
            print("日志文件为空，可能未检测到威胁。")
            return self.generate_empty_log_result()
        else:
            # 解析日志内容，提取威胁信息
            threat_info  = self.extract_snort_log(log_content)
            result: dict = {
                'log_entries': threat_info,
                'pcap_path': self.pcap_path
            }

        os.remove(log_path)  # 删除原始日志文件
        print("删除原始日志文件。")
        return result
    
    def generate_empty_log_result(self) -> dict:
        """生成空的日志结果"""
        empty_result = {
            "message": "未检测到任何有效的网络威胁",
            "attack_tactics": None,
            "attack_type": None,
            "threat_level": "none",
            "suggested_action": "无",
            "confidence": 1.0,
            "pcap_path": self.pcap_path
        }
        print("生成未检测到威胁的 JSON 记录。")
        return empty_result
    
    def extract_snort_log(self, log_content: str) -> list:
        """解析 Snort 日志内容，提取威胁信息"""
        log_entries = []
        pattern = re.compile(
            r'(?P<timestamp>\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+\[\*\*\]\s+'
            r'\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+'
            r'"(?P<description>[^"]+)"\s+\[\*\*\]\s+'
            r'\[Classification:\s+(?P<classification>[^\]]+)\]\s+'
            r'\[Priority:\s+(?P<priority>\d+)\]\s+'
            r'{(?P<protocol>\w+)}\s+'
            r'(?P<src_ip>(?:\d{1,3}\.){3}\d{1,3})(?::(?P<src_port>\d+))?\s+->\s+'
            r'(?P<dst_ip>(?:\d{1,3}\.){3}\d{1,3})(?::(?P<dst_port>\d+))?'
        )

        for match in pattern.finditer(log_content):
            log_entry = {
                "timestamp": match.group("timestamp"),
                "gid": int(match.group("gid")),
                "sid": int(match.group("sid")),
                "rev": int(match.group("rev")),
                "description": match.group("description"),
                "classification": match.group("classification"),
                "priority": int(match.group("priority")),
                "protocol": match.group("protocol"),
                "src_ip": match.group("src_ip"),
                "dst_ip": match.group("dst_ip")
            }
            if match.group("src_port"):
                log_entry["src_port"] = int(match.group("src_port"))
            if match.group("dst_port"):
                log_entry["dst_port"] = int(match.group("dst_port"))

            log_entries.append(log_entry)

        return log_entries
        
def analyze_pcap(pcap_path: str) -> list:
    """分析单个拆分后的 pcap 文件，返回检测结果字典"""
    analyzer = Snort(pcap_path)
    if analyzer.run_snort(pcap_path):
        time.sleep(2)  # 确保 Snort 生成日志
        return analyzer.process_snort_logs()
    else:
        return {"error": "Snort 运行失败", "pcap_path": pcap_path}
    
def process_single_pcap(pcap_path: str, output_dir: str) -> dict:
    """
    针对每个原始 pcap 文件：
    1. 在 OUTPUT_PCAP_DIR 下创建一个以原文件名命名的子目录
    2. 拆分 pcap
    3. 分析拆分后的 pcap，并将所有结果写入一个 JSON 文件（文件名为 <original_name>.json）
    """
    original_name = os.path.splitext(os.path.basename(pcap_path))[0]
    output_subdir = os.path.join(output_dir, original_name)

    print(f"正在处理原始 pcap 文件: {pcap_path}")
    results = analyze_pcap(pcap_path)

    # 检查 log_content 是否为空
    if results.get('log_entries'):
        os.makedirs(output_subdir, exist_ok=True)

        # 3. 保存分析结果到 JSON 文件（以原 pcap 名称命名）
        result_json_file = os.path.join(output_subdir, f"{original_name}.json")
        with open(result_json_file, 'w') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"分析结果已保存到: {result_json_file}")

        # 复制原始 pcap 文件到 JSON 结果文件的目录下
        shutil.copy(pcap_path, output_subdir)
        print(f"原始 pcap 文件已复制到: {output_subdir}")
    else:
        print("日志内容为空，未生成结果文件。")

def process_pcap_files(input_path: str, output_dir: str):
    """遍历指定目录下的所有 pcap 文件，并逐个处理。"""
    # 检查输入路径是否存在
    if not os.path.exists(input_path):
        print(f"指定路径不存在: {input_path}")
        return

    # 如果输入路径是文件，直接处理
    if os.path.isfile(input_path) and input_path.endswith(".pcap"):
        process_single_pcap(input_path, output_dir)
        return

    # 如果输入路径是目录，递归遍历所有子目录和文件
    for root, dirs, files in os.walk(input_path):
        for file in files:
            if file.endswith(".pcap"):
                pcap_file_path = os.path.join(root, file)
                process_single_pcap(pcap_file_path, output_dir)

def main():
    if len(sys.argv) > 1:
        input_path = sys.argv[1]
        output_dir = sys.argv[2]
    else:
        input_path = "/Users/lnhsec/Desktop/Lnh/github/NetAttackClassifier/pcaps/"  # 默认目录
        output_dir = "/Users/lnhsec/Desktop/Lnh/github/NetAttackClassifier/pcap_split"  # 默认目录

    process_pcap_files(input_path)

if __name__ == "__main__":
    main()