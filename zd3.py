# zd3.py
# Запуск: python3 zd3.py < log.txt
from collections import namedtuple
import sys

LogRecord = namedtuple(
    'LogRecord',
    ['remote_addr', 'remote_user', 'time_local', 'request',
     'status', 'body_bytes_sent', 'http_referer', 'http_user_agent']
)

def parse_log_record(line: str) -> LogRecord:
    start_time = line.find('[')
    end_time = line.find(']')
    time_local = line[start_time + 1 : end_time]
    start_req = line.find('"', end_time)
    end_req = line.find('"', start_req + 1)
    request = line[start_req + 1 : end_req]
    start_tail = end_req + 1
    end_tail = line.find('"', start_tail)
    if end_tail == -1: end_tail = len(line)
    status_and_bytes = line[start_tail : end_tail].split()
    status = int(status_and_bytes[0])
    body_bytes_sent = int(status_and_bytes[1])
    ip_and_user = line[:start_time].split()
    remote_addr = ip_and_user[0]
    remote_user = ip_and_user[1]
    tail = line[end_tail:].strip()
    if '"' in tail:
        parts = tail.split('"')
        http_referer = parts[1]
        http_user_agent = parts[3] if len(parts) > 3 else "-"
    else:
        http_referer = "-"
        http_user_agent = tail.strip('"')
    return LogRecord(remote_addr, remote_user, time_local, request,
                     status, body_bytes_sent, http_referer, http_user_agent)

def read_log(stream) -> list:
    records = []
    for line in stream:
        line = line.strip()
        if not line: break
        records.append(parse_log_record(line))
    return records

if __name__ == '__main__':
    records = read_log(sys.stdin)
    unique_ips = sorted({r.remote_addr for r in records})
    
    print(f'Всего: {len(records)}')
    print(f'Уникальных IP: {len(unique_ips)}\n')
    
    for i, ip in enumerate(unique_ips, start=1):
        print(f'{i:>3}. {ip}')
