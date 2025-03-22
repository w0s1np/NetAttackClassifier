import json
import os
import re
from openai import OpenAI

client = OpenAI(api_key="sk-*********", base_url="https://api.deepseek.com")

def process_json_file(file_path, out_file):
    try:
        with open(file_path) as f:
            data = json.load(f)
            if isinstance(data, dict):
                converted_json = convert_json_format([data])
                prompt = construct_prompt(converted_json)
                result = deepseek_analysis(prompt, out_file, data.get('pcap_path', 'N/A'))
                return result
            else:
                print(f"Unexpected JSON format in file: {file_path}")
                return None
    except json.JSONDecodeError:
        print(f"Error decoding JSON from file: {file_path}")
        return None

def convert_json_format(input_json):
    log_entries = []
    for entry in input_json:
        log_entries.append({
            "timestamp": entry["timestamp"],
            "sid": entry["sid"],
            "gid": entry["gid"],
            "rev": entry["rev"],
            "description": entry["description"],
            "classification": entry["classification"],
            "priority": int(entry["priority"]),
            "protocol": entry["protocol"],
            "src_ip": entry["src_ip"],
            "src_port": int(entry["src_port"]),
            "dst_ip": entry["dst_ip"],
            "dst_port": int(entry["dst_port"])
        })
    return log_entries

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

def format_deepseek_output(raw_text):
    try:
        print(f"DeepSeek API 返回的原始内容: {raw_text}")
        return json.loads(raw_text)
    except json.JSONDecodeError:
        print("DeepSeek 返回的文本无法解析为 JSON")
        json_match = re.search(r'\{.*\}', raw_text, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group())
            except json.JSONDecodeError:
                return {"error": "解析失败"}
        else:
            return {"error": "解析失败"}

def deepseek_analysis(prompt, out_file, pcap_path):
    try:
        print("调用 DeepSeek API 进行分析...")
        response = client.chat.completions.create(
            model="deepseek-reasoner",
            messages=[
                {"role": "system", "content": "You are a master of network traffic analysis"},
                {"role": "user", "content": prompt},
            ],
            stream=False
        )
        raw_text = response.choices[0].message.content
        json_result = format_deepseek_output(raw_text)
        print(f"API 返回的分析结果: {json.dumps(json_result, indent=2, ensure_ascii=False)}")

        # Add the pcap_path to the result
        json_result['pcap_path'] = pcap_path

        with open(out_file, 'w') as f:
            json.dump(json_result, f, indent=2, ensure_ascii=False)
        return json_result

    except Exception as e:
        print(f"API调用失败: {str(e)}")
        return {"error": "API 调用失败"}

def main():
    input_path = '/Users/lnhsec/Desktop/Lnh/github/NetAttackClassifier/extracted_streams'
    output_dir = '/Users/lnhsec/Desktop/Lnh/github/NetAttackClassifier/deepseek_results'
    os.makedirs(output_dir, exist_ok=True)

    for root, dirs, files in os.walk(input_path):
        for file in files:
            if file.endswith('.json'):
                file_path = os.path.join(root, file)
                out_file = os.path.join(output_dir, f"result_{file}")
                print(f"Processing file: {file_path}")
                result = process_json_file(file_path, out_file)
                if result:
                    print(f"Successfully processed and saved result for {file_path}")
                else:
                    print(f"Failed to process {file_path}")

if __name__ == '__main__':
    main()