from collections import namedtuple, Counter, defaultdict
from datetime import datetime
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

KNOWN_METHODS = {'GET', 'POST', 'HEAD', 'PUT', 'DELETE', 'OPTIONS', 'PATCH', 'CONNECT', 'TRACE'}
BAD_PATHS = ['.env', '.git', 'phpmyadmin', 'pma/', 'wp-login', 'setup.php', 'cgi-bin', 'viewlog', '/shell?', 'wget', 'mozi', 'jaws', 'jndi:', 'passwd', 'win.ini', '/bin/sh', '../', '%2e%2e']
BAD_UAS = ['zgrab', 'masscan', 'nessus', 'censys', 'r00ts3c', 'hello, world', 'mtmkilledyou', 'python-requests', 'curl', 'fasthttp']

def _minute_key(t: str) -> str:
    try:
        return datetime.strptime(t, '%d/%b/%Y:%H:%M:%S %z').strftime('%d/%b/%Y:%H:%M')
    except ValueError:
        return t[:16]

def _no_method(req: str) -> bool:
    if not req or not req.strip(): return True
    return req.split(maxsplit=1)[0] not in KNOWN_METHODS

def find_attacks(records: list) -> dict:
    by_ip = defaultdict(list)
    for r in records:
        by_ip[r.remote_addr].append(r)

    attackers = {}
    for ip, recs in by_ip.items():
        suspicious = False
        
        per_minute = Counter(_minute_key(r.time_local) for r in recs)
        if max(per_minute.values(), default=0) >= 20: 
            suspicious = True
        
        errors = sum(1 for r in recs if 400 <= r.status < 600)
        if len(recs) >= 10 and errors / len(recs) >= 0.5: 
            suspicious = True
        
        if any(_no_method(r.request) for r in recs): 
            suspicious = True
        
        for r in recs:
            req_low = r.request.lower()
            if any(bad in req_low for bad in BAD_PATHS):
                suspicious = True
                break
                
        for r in recs:
            ua_low = r.http_user_agent.lower()
            if ua_low in ('', '-') or any(bad in ua_low for bad in BAD_UAS):
                suspicious = True
                break

        if suspicious:
            attackers[ip] = recs
    return attackers

if __name__ == '__main__':
    records = read_log(sys.stdin)
    attackers = find_attacks(records)

    print('а) IP-адреса атакующих')
    for ip in sorted(attackers):
        print(f'  {ip:>15}  (записей: {len(attackers[ip])})')

    print('\nб) полные логи атак')
    for ip in sorted(attackers):
        print(f'\n')
        print(f' атакующий IP: {ip}')
        
        for i, r in enumerate(attackers[ip], start=1):
            print(f'Лог #{i}')
            print(f'  Время:          {r.time_local}')
            print(f'  Запрос:         {r.request}')
            print(f'  Статус:         {r.status}')
            print(f'  Размер ответа:  {r.body_bytes_sent} байт')
            print(f'  Реферер:        {r.http_referer}')
            print(f'  Юзер-агент:     {r.http_user_agent}')
            print()
