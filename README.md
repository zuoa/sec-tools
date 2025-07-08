## ssh_tester.py

```bash
# 保存结果到指定文件
python ssh_tester.py 192.168.1.0/24 -d password_dict.txt --save-results my_results.txt

# 或者不指定文件名，会自动生成带时间戳的文件名
python ssh_tester.py 192.168.1.0/24 -d password_dict.txt

# 仅扫描模式并保存结果
python ssh_tester.py 192.168.1.0/24 --scan-only --save-results scan_results.txt
```

**所有可用参数：**

```bash
# 查看帮助
python ssh_tester.py -h

# 完整示例
python ssh_tester.py 192.168.1.0/24 \
    -p 22 \
    -u root \
    -d password_dict.txt \
    -t 10 \
    --threads 10 \
    --save-results results.txt
```

**其他常用命令：**

```bash
# 创建示例密码字典
python ssh_tester.py --create-dict

# 扫描单个主机
python ssh_tester.py 192.168.1.100 -d password_dict.txt

# 扫描网段但只查看存活主机
python ssh_tester.py 192.168.1.0/24 --scan-only

# 使用更多线程加速扫描大网段
python ssh_tester.py 10.0.0.0/16 -d password_dict.txt --threads 50
```
