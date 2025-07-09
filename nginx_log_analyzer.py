#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import requests
import json
import time
from collections import Counter
from urllib.parse import quote
import argparse
import sys


class NginxLogAnalyzer:
    def __init__(self, log_file, rate_limit=0.5):
        """
        初始化分析器
        :param log_file: nginx访问日志文件路径
        :param rate_limit: API调用间隔（秒），避免频繁请求
        """
        self.log_file = log_file
        self.rate_limit = rate_limit
        self.ip_location_cache = {}
        self.api_url = "https://whois.pconline.com.cn/ipJson.jsp"

        # 匹配IP地址的正则表达式
        self.ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')

        # 常见的nginx日志格式正则（可根据实际情况调整）
        self.log_patterns = [
            # 标准combined格式
            re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "([^"]*)" (\d+) (\d+) "([^"]*)" "([^"]*)"'),
            # 简单格式
            re.compile(r'^(\S+) - - \[([^\]]+)\] "([^"]*)" (\d+) (\d+)'),
            # 仅提取IP的通用格式
            re.compile(r'^(\S+)')
        ]

    def extract_ips_from_log(self):
        """
        从nginx日志中提取IP地址
        :return: IP地址计数器
        """
        ip_counter = Counter()

        try:
            with open(self.log_file, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue

                    # 尝试不同的日志格式
                    ip = None
                    for pattern in self.log_patterns:
                        match = pattern.match(line)
                        if match:
                            ip = match.group(1)
                            break

                    # 如果正则匹配失败，尝试提取第一个IP
                    if not ip:
                        ip_match = self.ip_pattern.search(line)
                        if ip_match:
                            ip = ip_match.group(0)

                    if ip and self.is_valid_ip(ip):
                        ip_counter[ip] += 1

                    # 每处理1000行显示进度
                    if line_num % 1000 == 0:
                        print(f"已处理 {line_num} 行...")

        except FileNotFoundError:
            print(f"错误：找不到日志文件 {self.log_file}")
            sys.exit(1)
        except Exception as e:
            print(f"读取日志文件时出错：{e}")
            sys.exit(1)

        return ip_counter

    def is_valid_ip(self, ip):
        """
        验证IP地址是否有效
        :param ip: IP地址字符串
        :return: 布尔值
        """
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            for part in parts:
                if not (0 <= int(part) <= 255):
                    return False
            return True
        except ValueError:
            return False

    def get_ip_location(self, ip):
        """
        获取IP地址的归属地信息
        :param ip: IP地址
        :return: 归属地信息字典
        """
        if ip in self.ip_location_cache:
            return self.ip_location_cache[ip]

        try:
            # 构造请求URL
            params = {
                'ip': ip,
                'json': 'true'
            }

            # 发送请求
            response = requests.get(self.api_url, params=params, timeout=10)
            response.raise_for_status()

            # 解析JSON响应
            data = response.json()

            # 提取有用信息
            location_info = {
                'ip': ip,
                'country': data.get('country', '未知'),
                'region': data.get('region', '未知'),
                'city': data.get('city', '未知'),
                'isp': data.get('isp', '未知'),
                'full_address': data.get('addr', '未知')
            }

            # 缓存结果
            self.ip_location_cache[ip] = location_info

            # 添加延迟避免频繁请求
            time.sleep(self.rate_limit)

            return location_info

        except requests.RequestException as e:
            print(f"获取IP {ip} 归属地时网络错误: {e}")
            return {
                'ip': ip,
                'country': '网络错误',
                'region': '网络错误',
                'city': '网络错误',
                'isp': '网络错误',
                'full_address': '网络错误'
            }
        except json.JSONDecodeError:
            print(f"解析IP {ip} 归属地响应时出错")
            return {
                'ip': ip,
                'country': '解析错误',
                'region': '解析错误',
                'city': '解析错误',
                'isp': '解析错误',
                'full_address': '解析错误'
            }
        except Exception as e:
            print(f"获取IP {ip} 归属地时出错: {e}")
            return {
                'ip': ip,
                'country': '未知错误',
                'region': '未知错误',
                'city': '未知错误',
                'isp': '未知错误',
                'full_address': '未知错误'
            }

    def analyze_and_report(self, top_n=20):
        """
        分析日志并生成报告
        :param top_n: 显示访问量最多的前N个IP
        """
        print("开始分析nginx访问日志...")

        # 提取IP地址
        ip_counter = self.extract_ips_from_log()

        if not ip_counter:
            print("未在日志中找到有效的IP地址")
            return

        print(f"共找到 {len(ip_counter)} 个唯一IP地址")
        print(f"总访问次数：{sum(ip_counter.values())}")

        # 获取访问量最多的IP
        top_ips = ip_counter.most_common(top_n)

        print(f"\n正在获取前 {len(top_ips)} 个IP的归属地信息...")

        # 创建结果列表
        results = []

        for i, (ip, count) in enumerate(top_ips, 1):
            print(f"处理第 {i}/{len(top_ips)} 个IP: {ip}")
            location = self.get_ip_location(ip)
            location['访问次数'] = count
            results.append(location)

        # 显示结果
        self.display_results(results)

        # 生成统计报告
        self.generate_statistics(results)

    def display_results(self, results):
        """
        显示分析结果
        :param results: 结果列表
        """
        print("\n" + "=" * 80)
        print("IP地址归属地分析结果")
        print("=" * 80)

        print(f"{'排名':<4} {'IP地址':<15} {'访问次数':<8} {'国家':<8} {'地区':<10} {'城市':<10} {'ISP':<15}")
        print("-" * 80)

        for i, result in enumerate(results, 1):
            print(f"{i:<4} {result['ip']:<15} {result['访问次数']:<8} "
                  f"{result['country']:<8} {result['region']:<10} "
                  f"{result['city']:<10} {result['isp']:<15}")

    def generate_statistics(self, results):
        """
        生成统计报告
        :param results: 结果列表
        """
        print("\n" + "=" * 50)
        print("统计报告")
        print("=" * 50)

        # 按国家统计
        country_stats = Counter()
        region_stats = Counter()
        isp_stats = Counter()

        for result in results:
            country_stats[result['country']] += result['访问次数']
            region_stats[result['region']] += result['访问次数']
            isp_stats[result['isp']] += result['访问次数']

        print("\n访问量最多的国家/地区:")
        for country, count in country_stats.most_common(5):
            print(f"  {country}: {count} 次")

        print("\n访问量最多的省/州:")
        for region, count in region_stats.most_common(5):
            print(f"  {region}: {count} 次")

        print("\n访问量最多的ISP:")
        for isp, count in isp_stats.most_common(5):
            print(f"  {isp}: {count} 次")

    def save_to_file(self, results, output_file):
        """
        将结果保存到文件
        :param results: 结果列表
        :param output_file: 输出文件路径
        """
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                # 写入CSV格式
                f.write("排名,IP地址,访问次数,国家,地区,城市,ISP,完整地址\n")
                for i, result in enumerate(results, 1):
                    f.write(f"{i},{result['ip']},{result['访问次数']},"
                            f"{result['country']},{result['region']},{result['city']},"
                            f"{result['isp']},{result['full_address']}\n")
            print(f"\n结果已保存到 {output_file}")
        except Exception as e:
            print(f"保存文件时出错: {e}")


def main():
    parser = argparse.ArgumentParser(description='分析nginx访问日志中的IP地址归属地')
    parser.add_argument('log_file', help='nginx访问日志文件路径')
    parser.add_argument('-n', '--top', type=int, default=20, help='显示访问量最多的前N个IP (默认: 20)')
    parser.add_argument('-r', '--rate', type=float, default=0.5, help='API调用间隔秒数 (默认: 0.5)')
    parser.add_argument('-o', '--output', help='输出结果到CSV文件')

    args = parser.parse_args()

    # 创建分析器
    analyzer = NginxLogAnalyzer(args.log_file, args.rate)

    # 执行分析
    analyzer.analyze_and_report(args.top)

    # 如果指定了输出文件，保存结果
    if args.output:
        # 重新获取结果以保存
        ip_counter = analyzer.extract_ips_from_log()
        top_ips = ip_counter.most_common(args.top)
        results = []
        for ip, count in top_ips:
            location = analyzer.get_ip_location(ip)
            location['访问次数'] = count
            results.append(location)
        analyzer.save_to_file(results, args.output)


if __name__ == "__main__":
    main()