import redis
import socket
import sys
import ipaddress
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
import time


class RedisNetworkTester:
    def __init__(self, port=6379, timeout=3, max_threads=50):
        self.port = port
        self.timeout = timeout
        self.max_threads = max_threads
        self.found_services = []
        self.lock = threading.Lock()

    def scan_host_port(self, host):
        """扫描单个主机的Redis端口"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, self.port))
            sock.close()

            if result == 0:
                with self.lock:
                    self.found_services.append(host)
                    print(f"✓ 发现Redis服务: {host}:{self.port}")
                return True
            return False
        except Exception:
            return False

    def scan_network_range(self, network_range):
        """扫描网络范围内的Redis服务"""
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

            print(f"\n扫描完成! 找到 {len(self.found_services)} 个Redis服务")
            return self.found_services

        except ValueError as e:
            print(f"无效的网络范围: {e}")
            return []

    def test_single_connection(self, host, password=None):
        """测试单个主机的Redis认证"""
        try:
            r = redis.Redis(
                host=host,
                port=self.port,
                password=password,
                socket_timeout=self.timeout,
                socket_connect_timeout=self.timeout,
                decode_responses=True
            )

            # 尝试ping命令
            response = r.ping()
            r.close()
            return response == True

        except redis.AuthenticationError:
            return False
        except redis.ResponseError as e:
            # 如果是NOAUTH错误，说明不需要密码
            if "NOAUTH" in str(e):
                return True
            return False
        except redis.ConnectionError:
            return False
        except Exception:
            return False

    def check_redis_info(self, host, password=None):
        """获取Redis信息"""
        try:
            r = redis.Redis(
                host=host,
                port=self.port,
                password=password,
                socket_timeout=self.timeout,
                socket_connect_timeout=self.timeout,
                decode_responses=True
            )

            info = r.info()
            r.close()

            return {
                'version': info.get('redis_version', 'Unknown'),
                'mode': info.get('redis_mode', 'Unknown'),
                'role': info.get('role', 'Unknown'),
                'connected_clients': info.get('connected_clients', 0),
                'used_memory_human': info.get('used_memory_human', 'Unknown')
            }
        except Exception:
            return None

    def check_no_auth_access(self, host):
        """检查Redis是否可以无密码访问"""
        try:
            r = redis.Redis(
                host=host,
                port=self.port,
                socket_timeout=self.timeout,
                socket_connect_timeout=self.timeout,
                decode_responses=True
            )

            # 尝试基本命令
            r.ping()

            # 尝试获取一些信息
            info = r.info()

            # 尝试列出keys (限制数量)
            keys = r.keys()
            key_count = len(keys) if keys else 0

            r.close()

            return {
                'accessible': True,
                'version': info.get('redis_version', 'Unknown'),
                'role': info.get('role', 'Unknown'),
                'key_count': key_count,
                'sample_keys': keys[:5] if keys else []  # 只显示前5个key
            }
        except redis.AuthenticationError:
            return {'accessible': False, 'reason': 'Authentication required'}
        except Exception as e:
            return {'accessible': False, 'reason': str(e)}

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

    def test_passwords_limited(self, hosts, passwords, max_attempts_per_host=10):
        """测试密码（限制尝试次数以防止滥用）"""
        print(f"\n开始测试 {len(hosts)} 个主机的Redis认证...")
        print(f"每个主机最多尝试 {max_attempts_per_host} 个密码")
        print("-" * 60)

        results = []

        for host in hosts:
            print(f"\n测试主机: {host}")

            # 首先检查是否需要认证
            no_auth_result = self.check_no_auth_access(host)
            if no_auth_result['accessible']:
                print(f"  ✓ 无需密码即可访问!")
                info = self.check_redis_info(host)
                results.append({
                    'host': host,
                    'password': None,
                    'accessible': True,
                    'info': info,
                    'no_auth_info': no_auth_result
                })
                continue
            else:
                print(f"  需要密码认证: {no_auth_result['reason']}")

            # 测试密码
            success = False
            attempts = 0

            for password in passwords:
                if attempts >= max_attempts_per_host:
                    print(f"  已达到最大尝试次数 ({max_attempts_per_host})")
                    break

                attempts += 1
                print(f"  [{attempts}/{max_attempts_per_host}] 测试密码: {password}", end=" ")

                if self.test_single_connection(host, password):
                    print("✓ 成功")
                    info = self.check_redis_info(host, password)
                    results.append({
                        'host': host,
                        'password': password,
                        'accessible': True,
                        'info': info,
                        'no_auth_info': None
                    })
                    success = True
                    break
                else:
                    print("✗ 失败")

                # 添加延迟以避免过于频繁的尝试
                time.sleep(0.1)

            if not success:
                print(f"  主机 {host} 没有找到有效密码")
                results.append({
                    'host': host,
                    'password': None,
                    'accessible': False,
                    'info': None,
                    'no_auth_info': None
                })

        return results

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
    print("Redis 网络服务发现和连接测试工具")
    print("=" * 60)
    print("重要提醒:")
    print("- 请确保你有权限扫描目标网络")
    print("- 此工具仅用于合法的网络管理和安全审计")
    print("- 未经授权的网络扫描可能违法")
    print("=" * 60)

    # 确认继续
    response = input("确认你有权限扫描目标网络? (y/N): ")
    if response.lower() != 'y':
        print("已取消扫描")
        return

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
    scanner = RedisNetworkTester(
        port=6379,
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

    # 扫描Redis服务
    print("\n=== 第1步: 服务发现 ===")
    found_hosts = []

    with ThreadPoolExecutor(max_workers=scanner.max_threads) as executor:
        futures = {executor.submit(scanner.scan_host_port, host): host for host in host_list}

        for future in as_completed(futures):
            host = futures[future]
            if future.result():
                found_hosts.append(host)

    if not found_hosts:
        print("没有发现Redis服务")
        return

    print(f"\n发现 {len(found_hosts)} 个Redis服务:")
    for host in found_hosts:
        print(f"  - {host}:6379")

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
            passwords = ["", "redis", "password", "123456", "admin", "root", "test", "default", "guest"]
    else:
        passwords = ["", "redis", "password", "123456", "admin", "root", "test", "default", "guest"]

    print(f"将测试 {len(passwords)} 个密码")

    # 安全限制
    max_attempts = 1000  # 每个主机最多尝试10个密码
    if len(passwords) > max_attempts:
        print(f"为了防止滥用，每个主机最多只会尝试前 {max_attempts} 个密码")

    response = input("确认继续认证测试? (y/N): ")
    if response.lower() != 'y':
        print("已取消认证测试")
        return

    results = scanner.test_passwords_limited(found_hosts, passwords, max_attempts)

    # 显示结果
    print("\n" + "=" * 60)
    print("扫描结果汇总:")
    print(f"- 扫描主机数: {len(host_list)}")
    print(f"- 发现服务数: {len(found_hosts)}")

    accessible_count = sum(1 for r in results if r['accessible'])
    no_auth_count = sum(1 for r in results if r['accessible'] and r['password'] is None)

    print(f"- 可访问服务数: {accessible_count}")
    print(f"- 无密码访问数: {no_auth_count}")

    if accessible_count > 0:
        print(f"\n可访问的Redis服务:")
        for result in results:
            if result['accessible']:
                host = result['host']
                password = result['password']
                info = result['info']

                if password is None:
                    print(f"  {host} - 无需密码 ⚠️")
                else:
                    print(f"  {host} - 密码: {password}")

                if info:
                    print(f"    版本: {info.get('version', 'Unknown')}")
                    print(f"    角色: {info.get('role', 'Unknown')}")
                    print(f"    内存使用: {info.get('used_memory_human', 'Unknown')}")

                # 显示无密码访问的详细信息
                if result['no_auth_info']:
                    no_auth = result['no_auth_info']
                    print(f"    Keys数量: {no_auth.get('key_count', 0)}")
                    if no_auth.get('sample_keys'):
                        print(f"    示例Keys: {', '.join(no_auth['sample_keys'])}")

    # 安全警告
    if no_auth_count > 0:
        print(f"\n⚠️  警告: 发现 {no_auth_count} 个无密码保护的Redis服务!")
        print("   这可能存在安全风险，建议:")
        print("   1. 配置Redis密码 (requirepass)")
        print("   2. 绑定到特定IP (bind)")
        print("   3. 使用防火墙限制访问")

    print("\n扫描完成!")


if __name__ == "__main__":
    # 检查依赖
    try:
        import redis
    except ImportError:
        print("错误: 需要安装 redis 库")
        print("请运行: pip install redis")
        sys.exit(1)

    main()