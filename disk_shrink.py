#!/usr/bin/env python3
import os
import hashlib
from pathlib import Path
import argparse
from collections import defaultdict

import shutil
import subprocess
from datetime import datetime

def _format_bytes(size):
    """格式化字节显示"""
    units = ('B', 'KB', 'MB', 'GB')
    index = 0
    while size >= 1024 and index < 3:
        size /= 1024
        index += 1
    return f"{size:.2f} {units[index]}"

class DiskAnalyzer:
    def __init__(self, target_path, chunk_size=8192, quiet_mode=False):
        self.target_path = Path(target_path).expanduser()
        self.file_stats = defaultdict(list)
        self.chunk_size = chunk_size
        self.total_saved = 0
        self.quiet_mode = quiet_mode  # 新增静默模式开关

    def analyze_filesystem(self):
        """主分析函数"""
        if not self.quiet_mode:
            print("\n🔍 开始实时文件分析...")
        self._recover_orphaned_files()
        
        for file_path in self.target_path.rglob('*'):
            # 新增符号链接检查
            if file_path.is_symlink():
                print(f"⏩ 跳过符号链接：{file_path}")
                continue
                
            if file_path.is_file():
                self._collect_file_metadata(file_path)
        
        duplicates = self._find_duplicate_files()
        
        return {
            'total_files': sum(len(v) for v in self.file_stats.values()),
            'estimated_saved': self.total_saved,
            'duplicates': duplicates
        }

    def _calculate_file_hash(self, file_path):
        """计算文件哈希值（SHA-256）"""
        hasher = hashlib.sha256()
        with file_path.open('rb') as f:
            while chunk := f.read(self.chunk_size):
                hasher.update(chunk)
        return hasher.hexdigest()

    def _compare_files(self, file1, file2):
        """二进制内容比对"""
        with file1.open('rb') as f1, file2.open('rb') as f2:
            while True:
                b1 = f1.read(self.chunk_size)
                b2 = f2.read(self.chunk_size)
                if b1 != b2:
                    return False
                if not b1:
                    return True

    def _collect_file_metadata(self, file_path):
        # 新增二次验证（防止通过符号链接访问文件）
        if file_path.is_symlink():
            return
            
        stat = file_path.stat()
        file_size = stat.st_size
        
        if file_size == 0:
            return
        
        file_hash = self._calculate_file_hash(file_path)
        file_size = stat.st_size
        
        existing_files = self.file_stats.get(file_hash, [])
        if existing_files:
            if not self.quiet_mode:  # 静默模式下不输出重复文件信息
                print(f"🔍 发现重复文件：{file_path}")
                print(f"  原始文件：{existing_files[0]['path']}")
                print(f"  预估节省空间：{_format_bytes(file_size)}\n")
            self.total_saved += file_size

        self.file_stats[file_hash].append({
            'path': str(file_path),
            'size': file_size,
            'created': stat.st_ctime,
            'modified': stat.st_mtime,
            'file_type': file_path.suffix.lower()
        })

    def _find_duplicate_files(self):
        """查找重复文件"""
        return {
            h: files for h, files in self.file_stats.items()
            if len(files) > 1
        }

    def deduplicate_files(self):
        import uuid
        
        for file_hash, files in self.file_stats.items():
            if len(files) > 1:
                files.sort(key=lambda x: x['created'])
                retained = files[0]
                
                for f in files[1:]:
                    original_path = f['path']
                    current_file = Path(original_path)
                    
                    if not current_file.exists():
                        print(f"⏩ 跳过已删除文件：{original_path}")
                        continue

                    temp_path = f"{original_path}.{uuid.uuid4().hex}.bak"
                    
                    try:
                        print(f"⌛ 开始处理：{original_path}")
                        
                        # 保存原始元数据
                        current_stat = current_file.stat()
                        
                        Path(original_path).rename(temp_path)
                        subprocess.run(['cp', '-c', retained['path'], original_path], check=True)
                        
                        # 恢复元数据
                        os.utime(original_path, (current_stat.st_atime, current_stat.st_mtime))

                        if not self._compare_files(Path(retained['path']), Path(original_path)):
                            raise RuntimeError("文件验证失败")
                            
                        Path(temp_path).unlink()
                        print(f"✅ 完成处理：{original_path}\n")
                        
                    except Exception as e:
                        if Path(temp_path).exists() and not Path(original_path).exists():
                            Path(temp_path).rename(original_path)
                        print(f"❌ 处理失败：{original_path} ({e})\n")

    def _recover_orphaned_files(self):
        import re
        print("\n🔍 扫描残留临时文件...")
        recovered = 0
        
        temp_file_pattern = re.compile(r'^(.+)\.([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\.bak$')
        
        for temp_file in self.target_path.rglob('*'):
            if match := temp_file_pattern.match(temp_file.name):
                original_name = match.group(1)
                uuid_part = match.group(2)
                original_path = temp_file.parent / original_name
                
                if not self._is_valid_uuid(uuid_part):
                    print(f"⚠️ 忽略无效UUID格式：{temp_file}")
                    continue
                    
                if original_path.exists():
                    if self._compare_files(original_path, temp_file):
                        temp_file.unlink()
                        print(f"✅ 清理已完成的临时文件：{temp_file}")
                        recovered +=1
                    else:
                        try:
                            original_path.unlink()
                            temp_file.rename(original_path)
                            recovered +=1
                            print(f"🔄 恢复不一致文件：{temp_file} -> {original_path}")
                        except Exception as e:
                            print(f"❌ 恢复失败：{temp_file} -> {original_path} ({e})")
                else:
                    try:
                        temp_file.rename(original_path)
                        print(f"🔄 恢复未完成操作：{original_path}")
                        recovered +=1
                    except Exception as e:
                        print(f"❌ 恢复失败：{temp_file} -> {original_path} ({e})")
        
        print(f"临时文件恢复完成，共处理{recovered}个文件\n")

    def _is_valid_uuid(self, uuid_str):
        """验证是否为标准UUID的hex格式"""
        import uuid
        try:
            uuid.UUID(hex=uuid_str, version=4)
            return True
        except ValueError:
            return False

        # 生成唯一临时文件名（保持原有逻辑）
        temp_path = f"{original_path}.{uuid.uuid4().hex}.bak"

def _check_cow_support(target_path):
    """检查是否满足COW执行条件"""
    target_path = Path(target_path).resolve()
    
    if not target_path.exists():
        raise SystemExit(f"❌ 错误：路径不存在 {target_path}")

    # 新增获取真实挂载点
    try:
        df_output = subprocess.check_output(
            ['df', str(target_path)], 
            stderr=subprocess.STDOUT,
            text=True
        ).splitlines()[1].split()[0]
    except Exception as e:
        raise SystemExit(f"❌ 挂载点获取失败: {e}")

    try:
        output = subprocess.check_output(
            ['diskutil', 'info', df_output],
            stderr=subprocess.STDOUT,
            text=True
        )
        if 'APFS' not in output:
            raise SystemExit(f"❌ 错误：目标目录必须位于APFS文件系统（当前文件系统：{output.split('File System Personality: ')[-1].split()[0]}）")
    except subprocess.CalledProcessError as e:
        raise SystemExit(f"❌ 文件系统检测失败: {e.output}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='macOS磁盘文件分析工具')
    parser.add_argument('path', help='要分析的目录路径')
    parser.add_argument('--shrink', action='store_true', 
                       help='执行空间收缩（自动去重+COW恢复）')
    args = parser.parse_args()

    # 执行前置检查
    if args.shrink:
        print("🔍 正在检查系统环境...")
        _check_cow_support(args.path)
        print("✅ 环境检查通过（macOS + APFS）\n")

    analyzer = DiskAnalyzer(args.path, quiet_mode=args.shrink)
    report = analyzer.analyze_filesystem()
    
    # 当不指定参数时显示分析报告
    if not args.shrink:
        print(f"\n分析完成：{args.path}")
        print(f"总文件数: {report['total_files']}")
        print(f"发现重复文件组: {len(report['duplicates'])} 组")
        print(f"预估可节省空间: {_format_bytes(report['estimated_saved'])}\n")
    
    # 合并去重和恢复操作为一个参数
    if args.shrink:
        print("正在执行实时空间优化...")
        # 新增空间统计
        before_usage = shutil.disk_usage(args.path)
        analyzer.deduplicate_files()
        after_usage = shutil.disk_usage(args.path)
        saved_space = before_usage.used - after_usage.used
        
        # 新增空间统计输出
        print("\n空间优化统计:")
        print(f"初始占用空间: {_format_bytes(before_usage.used)}")
        print(f"优化后占用空间: {_format_bytes(after_usage.used)}")
        print(f"节省存储空间: {_format_bytes(saved_space)}")
        print("空间优化完成，已通过APFS克隆替换所有重复文件")