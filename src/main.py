import re
import json
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import unquote
from collections import defaultdict

log_pattern = re.compile(r'(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?"(?P<method>GET|PUT|POST)\s(?P<url>\S+).*?"\s(?P<status>\d{1,3})')
src_path = Path(__file__)
log_route = src_path.parent.parent /'logs'
critical_routes = ['.env', '/etc/passwd', '/wp-admin', 'id_rsa']
sqli_quotes = ["'", "or 1=1", "union", "--"]

def signature_threats(log_sheet):

    error_founded = False
    ip = log_sheet['ip']
    
    normalized_url = log_sheet['url'].lower()
    decoded_url = unquote(normalized_url)

    for critical_r in critical_routes:

        if critical_r in normalized_url:

            print(f"Critical error. Access attempt to {critical_r} from IP {log_sheet['ip']}\n")
            error_founded = True
                
    for critical_sqli in sqli_quotes:
                    
        if critical_sqli in decoded_url:

            print(f"Critical error, Sqli injection attempt: {critical_sqli} from IP {log_sheet['ip']}\n")
            error_founded = True

    return error_founded

def behavioral_threats(log_entries, max_errors = 3):
      
    errors_404 = defaultdict(int)

    for entry in log_entries:
        if entry['status'] == '404':
            errors_404[entry['ip']] += 1

    for ip, attempts in errors_404.items():
        if attempts > max_errors:
            print(f"Critical error, so many 404 errors from IP {ip}. Total attempts: {attempts}\n")
        
#|-------------------------------------------------------------|
#|-------------------------------------------------------------|
#|                      MAIN FUNCTION                          |
#|-------------------------------------------------------------|
#|-------------------------------------------------------------|

for log_file in log_route.glob('*.log'):
    print(f"\n----Log file: {log_file.name}----\n")

    log_entries = []
    error_check = False

    with open(log_file, 'r', encoding='utf-8') as file:

        for line in file:

            found = log_pattern.search(line)

            if found:

                log_sheet = found.groupdict()
                log_entries.append(found.groupdict())

                if signature_threats(log_sheet):
                    error_check = True
                   
        if not error_check:
             print("\nNo critical errors were found\n")     

        behavioral_threats(log_entries)

        print(json.dumps(log_entries, indent = 4))
        print("\n")


