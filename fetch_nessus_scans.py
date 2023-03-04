#!/usr/bin/env python3

from os import getenv, path
from re import search
from time import time
from json import dumps
from posixpath import join as urljoin
from requests import packages, get, post
from datetime import datetime
from dotenv import load_dotenv
from opensearchpy import OpenSearch

load_dotenv()
packages.urllib3.disable_warnings()

log_file = 'nessus_log.txt'
timestamp_file = 'nessus_timestamp.txt'

def write_log(log_msg: str) -> None:
    """ Write log message """
    with open(log_file, 'a') as f:
        f.write(log_msg)

##########
# Nessus #
##########
def nessus_login(url: str, user: str, password: str) -> str:
    """ Login to Nessus with User & Password """
    payload = {"username": user, "password": password}
    try:
        response = post(urljoin(url, f"session"), payload, verify=False)
        if response.status_code == 200:
            if response.headers["content-type"].lower() == "application/json" and "token" in response.json():
                return response.json()["token"]
            else:
                write_log('nessus_login() | Nessus did not response with a valid token' + '\n')
        else:
            write_log('nessus_login() | reponse code: %s | Error: %s' % (response.status_code, response.json()) + '\n')
    except Exception as e:
        write_log('nessus_login() | Error: %s' % (e) + '\n')

def get_x_api_token(url: str, token: str) -> str:
    """ Get X-API-Token to authenticate calls API """
    x_token = None
    headers = {"X-Cookie": f"token={token}"}
    pattern = (r"\{key:\"getApiToken\",value:function\(\)\{"
               r"return\"([a-zA-Z0-9]*-[a-zA-Z0-9]*-[a-zA-Z0-9]*-"
               r"[a-zA-Z0-9]*-[a-zA-Z0-9]*)\"\}")
    try:
        response = get(urljoin(url, f"nessus6.js"), headers=headers, verify=False)
        if response.status_code == 200:
            matched = search(pattern, str(response.content))
            if(matched):
                x_token = matched.group(1)
                return x_token
            else:
                write_log('get_x_api_token() | X-API-TOKEN not found' + '\n')
        else:
            write_log('get_x_api_token() | reponse code: %s | Error: %s' % (response.status_code, response.json()) + '\n')
    except Exception as e:
        write_log('get_x_api_token() | Error: %s' % (e) + '\n')

def get_scans_list(url: str, token: str, x_token: str, last_timestamp_query: int) -> dict:
    """ Get lits of scans """
    headers = {"X-Cookie": "token={}".format(token), "X-API-Token": x_token, 'Accept': 'application/json'}
    params = {"last_modification_date": last_timestamp_query}
    try:
        response = get(urljoin(url, f"scans/"), headers=headers, params=params, verify=False)
        if response.status_code == 200:
            return response.json()
        else:
            write_log('get_scans_list() | reponse code: %s | Error: %s' % (response.status_code, response.json()) + '\n')
    except Exception as e:
        write_log('get_scans_list() | Error: %s' % (e) + '\n')

def get_scan(url: str, token: str, x_token: str, scan_id: int) -> dict:
    """ Get scan data """
    headers = {"X-Cookie": "token={}".format(token), "X-API-Token": x_token, "Accept": "application/json"}
    try:
        response = get(urljoin(url, f"scans/{scan_id}"), headers=headers, verify=False)
        if response.status_code == 200:
            return response.json()
        else:
            write_log('get_scan() | reponse code: %s | Error: %s' % (response.status_code, response.json()) + '\n')
    except Exception as e:
        write_log('get_scan() | Error: %s' % (e) + '\n')

def get_host_details(url: str, token: str, x_token: str, scan_id: int, host_id: int) -> dict:
    """ Get host detail """
    headers = {"X-Cookie": "token={}".format(token), "X-API-Token": x_token, "Accept": "application/json"}
    try:
        response = get(urljoin(url, f"scans/{scan_id}/hosts/{host_id}"), headers=headers, verify=False)
        if response.status_code == 200:
            return response.json()
        else:
            write_log('get_host_details() | reponse code: %s | Error: %s' % (response.status_code, response.json()) + '\n')
    except Exception as e:
        write_log('get_host_details() | Error: %s' % (e) + '\n')

def get_last_timestamp_query() -> int:
    """ Get last timestamp when we have made query to not get list of all scans """
    cur_timestamp = current_timestamp()
    prev_timestamp = read_previous_timestamp()
    write_current_timestamp(cur_timestamp)
    return prev_timestamp

def vuln_score_decode(vuln_score: str | None) -> float:
    """ Convert score str to float """
    if(vuln_score is not None):
        return float(vuln_score)
    else:
        return float(0)
    
def vuln_severity_decode(vuln_severity: int) -> str:
    """ Turn severity code into readable category """
    if(vuln_severity == 0):
        return "info"
    elif(vuln_severity == 1):
        return "low"
    elif(vuln_severity == 2):
        return "medium"
    elif(vuln_severity == 3):
        return "high"
    elif(vuln_severity == 4):
        return "critical"
    else:
        return None

#############
# Timestamp #
#############
def read_previous_timestamp() -> int:
    """ Read the timestamp to the file """
    if path.exists(timestamp_file):
        with open(timestamp_file, 'r') as f:
            timestamp = f.readline().strip()
            if (timestamp):
                return int(timestamp)
            else:
                return 1
    else:
        cur_timestamp = current_timestamp()
        write_current_timestamp(cur_timestamp)
        return 1

def write_current_timestamp(current_timestamp: int) -> None:
    """ Write the current timestamp to the file """
    with open(timestamp_file, 'w') as f:
        f.write(str(current_timestamp))

def current_timestamp() -> int:
    """ Get current timestamp """
    return int(time())
    
def date_for_index() -> str:
    """ Get date format YYYY.MM.DD for index name """
    return datetime.now().strftime("%Y.%m.%d")

def timestamp_to_iso_format(timestamp: int) -> str:
    """ Transform timestamp in date format compatible with Opensearch """
    return datetime.fromtimestamp(timestamp).isoformat()

def nessus_date_to_iso_format(nessus_date: str) -> str:
    """ Transform Nessus date format in date format compatible with Opensearch """
    return datetime.strptime(nessus_date, "%a %b %d %H:%M:%S %Y").isoformat()

##############
# Opensearch #
##############
def opensearch_login(host: str, port: int, user: str, password: str) -> OpenSearch:
    """ Opensearch login """
    ### Optional client certificates if you don't want to use HTTP basic authentication. ###
    # client_cert_path = '/full/path/to/client.pem'
    # client_key_path = '/full/path/to/client-key.pem'
    # ca_certs_path = '/full/path/to/root-ca.pem'

    ### Create the client with SSL/TLS enabled, but hostname verification disabled. ###
    opensearch = OpenSearch(
        hosts = [{'host': host, 'port': port}],
        http_compress = True, # enables gzip compression for request bodies
        http_auth = (user, password),
        # client_cert = client_cert_path,
        # client_key = client_key_path,
        # ca_certs = ca_certs_path,
        use_ssl = True,
        verify_certs = False,
        ssl_assert_hostname = False,
        ssl_show_warn = False,
    )
    return opensearch

def build_index_name(dest_index_pattern: str) -> str:
    """ Build index name """
    return dest_index_pattern + "-" + date_for_index()

def append_data_opensearch(opensearch: OpenSearch, index_name: str, scans_data: list) -> None:
    """ Append scans results to Opensearch """
    try:
        ### bulk API - https://github.com/opensearch-project/opensearch-py/blob/main/USER_GUIDE.md#adding-documents-in-bulk
        bulk_body = ""
        for scan in scans_data:
            bulk_body += f'{{"index": {{"_index": "{index_name}"}}}}\n'
            bulk_body += f'{dumps(scan)}\n'
        if(bulk_body):
            opensearch.bulk(index=index_name, body=bulk_body)
    except Exception as e:
            write_log('append_data_opensearch() | index: %s | Error: %s' % (index_name, e) + '\n')

def main() -> None:
    """ Main """
    NESSUS_URL = getenv("NESSUS_URL")
    NESSUS_USERNAME = getenv("NESSUS_USERNAME")  
    NESSUS_PASSWORD = getenv("NESSUS_PASSWORD")  

    OPENSEARCH_HOST = getenv("OPENSEARCH_HOST")  
    OPENSEARCH_PORT = getenv("OPENSEARCH_PORT")  
    OPENSEARCH_USER = getenv("OPENSEARCH_USER")
    OPENSEARCH_PASSWORD = getenv("OPENSEARCH_PASSWORD")

    token = nessus_login(NESSUS_URL, NESSUS_USERNAME, NESSUS_PASSWORD)
    x_token = get_x_api_token(NESSUS_URL, token)

    if(token and x_token):
        last_timestamp_query = get_last_timestamp_query()
        scans_list = get_scans_list(NESSUS_URL, token, x_token, last_timestamp_query)
        
        result_all_scans = []

        if(scans_list["scans"]):
            for scan in scans_list["scans"]:
                if(scan["status"] == "completed"):
                    scan_result = {}
                    scan_result = get_scan(NESSUS_URL, token, x_token, scan["id"])
                    for host in scan_result["hosts"]:
                        host_details = {}
                        host_details = get_host_details(NESSUS_URL, token, x_token, scan["id"], host["host_id"])
                        ## Opensearch dashboard doesn't support nested object visualisation, so for each vulnerability we create an entry ...
                        ## https://github.com/opensearch-project/OpenSearch-Dashboards/issues/657
                        for vuln in host_details["vulnerabilities"]:
                            data = {}
                            # Scan infos
                            data["@timestamp"]       = timestamp_to_iso_format(scan_result["info"]["scan_end"])   # ISO format is use to be compliante with Opensearch dynamic field mapping
                            data["scan_start"]       = timestamp_to_iso_format(scan_result["info"]["scan_start"])
                            data["scan_end"]         = timestamp_to_iso_format(scan_result["info"]["scan_end"])
                            data["scan_name"]        = scan_result["info"]["name"]
                            data["scan_targets"]     = scan_result["info"]["targets"]
                            data["scan_policy"]      = scan_result["info"]["policy"]
                            # Host infos
                            data["host_start"]       = nessus_date_to_iso_format(host_details["info"]["host_start"])
                            data["host_end"]         = nessus_date_to_iso_format(host_details["info"]["host_end"])
                            data["host_ip"]          = host_details["info"]["host-ip"]
                            # Vulnerability infos
                            data["plugin_count"]     = vuln["count"]
                            data["plugin_score"]     = vuln_score_decode(vuln["score"])
                            data["plugin_severity"]  = vuln_severity_decode(vuln["severity"])
                            data["plugin_name"]      = vuln["plugin_name"]
                            data["plugin_id"]        = str(vuln["plugin_id"])
                            data["plugin_family"]    = vuln["plugin_family"]
                            data["plugin_name"]      = vuln["plugin_name"]
    
                            result_all_scans.append(data)

        # print(dumps(result_all_scans))
        if(result_all_scans):
            opensearch = opensearch_login(OPENSEARCH_HOST, OPENSEARCH_PORT, OPENSEARCH_USER, OPENSEARCH_PASSWORD)
            index_name = build_index_name(getenv("OPENSEARCH_INDEX_NAME")) # Choose your policy for index naming
            append_data_opensearch(opensearch, index_name, result_all_scans)

if __name__ == "__main__":
    main()