import re
from contextlib import contextmanager
from pathlib import Path

log_pattern = re.compile(r'(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?"(?P<method>GET|PUT|POST)\s(?P<url>\S+).*?"\s(?P<status>\d{1,3})')
src_path = Path(__file__)
log_route = src_path.parent.parent /'logs'


for log_file in log_route.glob('*.log'):
    print(f"\n----Log file: {log_file.name}----\n")

    log_entries = []

    with open(log_file, 'r', encoding='utf-8') as file:
        for line in file:
            found = log_pattern.search(line)
            if found:
                log_entries.append(found.groupdict())

    print(log_entries)
