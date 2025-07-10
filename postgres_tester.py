import psycopg2
import socket
import sys
import ipaddress
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
import time


class PostgreSQLNetworkTester:
    def __init__(self, port=5432, database='postgres', timeout=3, max_threads=50):
        self.port = port
        self.database = database
        self.timeout = timeout
        self.max_threads = max_threads
        self.found_services = []
        self.lock = threading.Lock()

    def scan_host_port(self, host):
        """扫描单个主机的PostgreSQL端口"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, self.port))
            sock.close()

            if result == 0:
                with self.lock:
                    self.found_services.append(host)
                    print(f"✓ 发现PostgreSQL服务: {host}:{self.port}")
                return True
            return False
        except Exception:
            return False

    def scan_network_range(self, network_range):
        """扫描网络范围内的PostgreSQL服务"""
        print(f"开始扫描网段: {network_range}")
        print(f"端口: {self.port}, 超时: {self.timeout}秒, 线程数: {self.max_threads}")
        print("-" * 60)

        try:
            network = ipaddress.ip_network(network_range, strict=False)
            hosts = list(network.hosts()) if network.num_addresses > 2 else [network.network_address]

            print(f"将扫描 {len(hosts)} 个主机...")

            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                futures = {executor.submit(self.scan_host_port, str(host)): host for host in hosts}

                completed = 0
                for future in as_completed(futures):
                    completed += 1
                    if completed % 50 == 0:
                        print(f"已扫描: {completed}/{len(hosts)}")

            print(f"\n扫描完成! 找到 {len(self.found_services)} 个PostgreSQL服务")
            return self.found_services

        except ValueError as e:
            print(f"无效的网络范围: {e}")
            return []

    def test_single_connection(self, host, username, password):
        """测试单个主机的认证"""
        try:
            conn = psycopg2.connect(
                host=host,
                port=self.port,
                database=self.database,
                user=username,
                password=password,
                connect_timeout=self.timeout
            )
            conn.close()
            return True
        except psycopg2.OperationalError as e:
            error_msg = str(e).lower()
            if "authentication failed" in error_msg or "password authentication failed" in error_msg:
                return False
            elif "database" in error_msg and "does not exist" in error_msg:
                return True  # 认证成功但数据库不存在
            else:
                return False
        except Exception:
            return False

    def load_password_dictionary(self, dict_file):
        """从文件加载密码字典"""
        passwords = []
        try:
            with open(dict_file, 'r', encoding='utf-8') as f:
                for line in f:
                    password = line.strip()
                    if password:  # 跳过空行
                        passwords.append(password)
            print(f"从 {dict_file} 加载了 {len(passwords)} 个密码")
            return passwords
        except FileNotFoundError:
            print(f"错误: 找不到密码字典文件 {dict_file}")
            return []
        except Exception as e:
            print(f"读取密码字典时出错: {e}")
            return []

    def generate_credential_combinations(self, usernames, passwords):
        """生成用户名和密码的组合"""
        combinations = []
        for username in usernames:
            for password in passwords:
                combinations.append((username, password))
        return combinations

    def test_credentials_limited(self, hosts, credential_list, max_attempts_per_host=10):
        """测试凭据（限制尝试次数以防止滥用）"""
        print(f"\n开始测试 {len(hosts)} 个主机的认证...")
        print(f"每个主机最多尝试 {max_attempts_per_host} 个凭据")
        print("-" * 60)

        successful_logins = []

        for host in hosts:
            print(f"\n测试主机: {host}")
            host_success = False
            attempts = 0

            for username, password in credential_list:
                if attempts >= max_attempts_per_host:
                    print(f"  已达到最大尝试次数 ({max_attempts_per_host})")
                    break

                attempts += 1
                print(f"  [{attempts}/{max_attempts_per_host}] {username}:{password}", end=" ")

                if self.test_single_connection(host, username, password):
                    print("✓ 成功")
                    successful_logins.append((host, username, password))
                    host_success = True
                    break  # 找到成功的凭据后停止
                else:
                    print("✗ 失败")

                # 添加延迟以避免过于频繁的尝试
                time.sleep(0.1)

            if not host_success:
                print(f"  主机 {host} 没有找到有效凭据")

        return successful_logins

    def generate_host_list(self, targets):
        """生成要扫描的主机列表"""
        all_hosts = []

        for target in targets:
            if '/' in target:  # CIDR网段
                try:
                    network = ipaddress.ip_network(target, strict=False)
                    hosts = list(network.hosts()) if network.num_addresses > 2 else [network.network_address]
                    all_hosts.extend([str(host) for host in hosts])
                except ValueError:
                    print(f"无效的网段: {target}")
            elif '-' in target:  # IP范围 (如 192.168.1.1-192.168.1.100)
                try:
                    start_ip, end_ip = target.split('-')
                    start = ipaddress.ip_address(start_ip.strip())
                    end = ipaddress.ip_address(end_ip.strip())

                    current = start
                    while current <= end:
                        all_hosts.append(str(current))
                        current += 1
                except ValueError:
                    print(f"无效的IP范围: {target}")
            else:  # 单个IP
                try:
                    ipaddress.ip_address(target)
                    all_hosts.append(target)
                except ValueError:
                    print(f"无效的IP地址: {target}")

        return all_hosts


def main():
    print("PostgreSQL 网络服务发现和连接测试工具")
    print("=" * 60)
    print("重要提醒:")
    print("- 请确保你有权限扫描目标网络")
    print("- 此工具仅用于合法的网络管理和安全审计")
    print("- 未经授权的网络扫描可能违法")
    print("=" * 60)

    # 配置扫描参数
    targets = [
        "10.0.4.0/24",  # 示例网段
        "10.0.5.0/24",  # 示例网段
        "10.0.6.0/24",  # 示例网段
        # "10.0.0.1-10.0.0.50",   # 示例IP范围
        # "172.16.1.100",         # 示例单个IP
    ]

    print("\n请修改脚本中的 targets 列表来指定要扫描的目标")
    print("当前配置的目标:")
    for target in targets:
        print(f"  - {target}")

    response = input("\n使用当前配置继续? (y/N): ")
    if response.lower() != 'y':
        print("请修改脚本中的 targets 列表")
        return

    # 创建扫描器
    scanner = PostgreSQLNetworkTester(
        port=5432,
        timeout=3,
        max_threads=50
    )

    # 生成主机列表
    print("\n正在生成主机列表...")
    host_list = scanner.generate_host_list(targets)
    print(f"共 {len(host_list)} 个主机待扫描")

    if not host_list:
        print("没有有效的主机地址")
        return

    # 扫描PostgreSQL服务
    print("\n=== 第1步: 服务发现 ===")
    found_hosts = []

    with ThreadPoolExecutor(max_workers=scanner.max_threads) as executor:
        futures = {executor.submit(scanner.scan_host_port, host): host for host in host_list}

        for future in as_completed(futures):
            host = futures[future]
            if future.result():
                found_hosts.append(host)

    if not found_hosts:
        print("没有发现PostgreSQL服务")
        return

    print(f"\n发现 {len(found_hosts)} 个PostgreSQL服务:")
    for host in found_hosts:
        print(f"  - {host}:5432")

    # 询问是否进行认证测试
    response = input(f"\n是否测试这些服务的认证? (y/N): ")
    if response.lower() != 'y':
        print("扫描完成")
        return

    # 测试认证
    print("\n=== 第2步: 认证测试 ===")

    # 选择密码来源
    print("选择密码来源:")
    print("1. 使用内置常见密码")
    print("2. 从文件读取密码字典")

    choice = input("请选择 (1/2): ")

    if choice == '2':
        dict_file = input("请输入密码字典文件路径 (默认: password_dict.txt): ").strip()
        if not dict_file:
            dict_file = "password_dict.txt"

        passwords = scanner.load_password_dictionary(dict_file)
        if not passwords:
            print("使用内置密码作为备选")
            passwords = ["postgres", "password", "123456", "", "admin", "root", "user", "test"]
    else:
        passwords = ["postgres", "password", "123456", "", "admin", "root", "user", "test"]

    # 用户名列表
    usernames = ["postgres", "admin", "root", "codvision", "user", "test"]

    # 生成凭据组合
    test_credentials = scanner.generate_credential_combinations(usernames, passwords)

    print(f"将测试 {len(usernames)} 个用户名和 {len(passwords)} 个密码的组合")
    print(f"总共 {len(test_credentials)} 个凭据组合")

    # 安全限制
    max_attempts = 1000  # 每个主机最多尝试20个凭据
    if len(test_credentials) > max_attempts:
        print(f"为了防止滥用，每个主机最多只会尝试前 {max_attempts} 个凭据")

    response = input("确认继续认证测试? (y/N): ")
    if response.lower() != 'y':
        print("已取消认证测试")
        return

    successful_logins = scanner.test_credentials_limited(found_hosts, test_credentials, max_attempts)

    # 显示结果
    print("\n" + "=" * 60)
    print("扫描结果汇总:")
    print(f"- 扫描主机数: {len(host_list)}")
    print(f"- 发现服务数: {len(found_hosts)}")
    print(f"- 成功认证数: {len(successful_logins)}")

    if successful_logins:
        print("\n成功的登录凭据:")
        for host, username, password in successful_logins:
            print(f"  {host} - {username}:{password}")

    print("\n扫描完成!")


if __name__ == "__main__":
    # 检查依赖
    try:
        import psycopg2
    except ImportError:
        print("错误: 需要安装 psycopg2 库")
        print("请运行: pip install psycopg2-binary")
        sys.exit(1)

    main()