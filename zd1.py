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
    if end_tail == -1:
        end_tail = len(line)
    
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

if __name__ == '__main__':
    record_string = (
        '85.237.48.26 - - [02/Oct/2022:22:14:50 +0300] '
        '"GET /masterclass/ HTTP/1.1" 200 527 '
        '"http://82.179.90.12/" '
        '"Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0"'
    )
    rec = parse_log_record(record_string)
    print(rec)
    print('status          =', rec.status, type(rec.status).__name__)
    print('body_bytes_sent =', rec.body_bytes_sent, type(rec.body_bytes_sent).__name__)
