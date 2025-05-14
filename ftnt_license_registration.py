#!/usr/bin/env python3

"""
## Converted from perl to Python
## By David Thomson @ 20250514

Please install these libraries first:

pip install termcolor requests PyPDF2
"""

import argparse
import os
import sys
import re
import json
from zipfile import ZipFile
from pathlib import Path
from termcolor import colored
import requests
from PyPDF2 import PdfReader
from io import BytesIO

def log_output(*args):
    print(colored('- ', 'green', attrs=['bold']) + ' '.join(map(str, args)), file=sys.stderr)

def log_error(*args):
    print(colored('- ' + ' '.join(map(str, args)), 'red', attrs=['bold']), file=sys.stderr)
    sys.exit(1)

def log_warning(*args):
    print(colored('- ' + ' '.join(map(str, args)), 'yellow', attrs=['bold']), file=sys.stderr)

def extract_reg_codes(zip_files):
    codes = []
    for zip_file in zip_files:
        log_output(f"Reading {zip_file}")
        try:
            with ZipFile(zip_file, 'r') as zip_ref:
                for pdf_name in zip_ref.namelist():
                    pdf_content = zip_ref.read(pdf_name)
                    pdf = PdfReader(BytesIO(pdf_content))
                    text = pdf.pages[0].extract_text()
                    match = re.search(r'Registration Code\s+:\s+((\w{5}-){4}(\w{6}))', text)
                    if match:
                        registration_code = match.group(1)
                        log_output(f"Extracted code {registration_code}")
                        codes.append(registration_code)
                    else:
                        log_warning(f"Error extracting code from '{pdf_name}'")
        except:
            log_warning(f"{zip_file} does not appear to be a valid zip file, skipping...")
    return codes

def dotfile_creds():
    cred_path = os.path.expanduser('~/.ftnt/ftnt_cloud_api')
    creds = {}
    try:
        with open(cred_path, 'r') as f:
            for line in f:
                if line.strip().startswith('#'):
                    continue
                username, password = line.strip().split(':')
                creds['username'] = username
                creds['password'] = password
                return creds
    except:
        return {}

def is_ipv4_address(ip):
    return re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip) is not None

def license_ipv4_addresses(ip_or_file, n_codes):
    if ip_or_file is None:
        return []
    
    try:
        with open(ip_or_file, 'r') as f:
            log_output(f"Successfully opened IPv4 address list '{ip_or_file}'")
            return [line.strip() for line in f if is_ipv4_address(line.strip())]
    except:
        log_output(f"Cannot open '{ip_or_file}' as file, treating as IPv4 address")
        if is_ipv4_address(ip_or_file):
            return [ip_or_file] * n_codes
        else:
            log_warning("Argument to '--ipv4-addresses' is neither a file, nor an IP address, ignoring")
            return []

def forticare_auth(credentials):
    auth_info = {
        'uri': 'https://customerapiauth.fortinet.com/api/v1/oauth/token/',
        'json': {
            'username': credentials['username'],
            'password': credentials['password'],
            'client_id': credentials['client_id'],
            'grant_type': 'password'
        }
    }
    
    res = requests.post(auth_info['uri'], json=auth_info['json'])
    
    if res.status_code != 200:
        msg = res.json().get('oauth', {}).get('message') or res.json().get('error_message') or res.json().get('error_description', "Unknown Error")
        log_error(f"Authentication Error: {msg}")
    
    log_output("Authentication Success")
    return res.json()['access_token']

def forticare_register(access_token, reg_codes, ipv4_addresses):
    licenses = []
    headers = {'Authorization': f'Bearer {access_token}'}
    
    for code in reg_codes:
        log_output(f"Registering code {code}")
        ipv4_address = ipv4_addresses.pop(0) if ipv4_addresses else None
        if ipv4_address:
            log_output(f"IPv4 address found to be assigned: {ipv4_address}")
        
        request_json = {
            'licenseRegistrationCode': code,
            'description': f"Auto Registered {requests.utils.formatdate()}"
        }
        if ipv4_address:
            request_json['additionalInfo'] = ipv4_address
        
        res = requests.post('https://support.fortinet.com/ES/api/registration/v3/licenses/register', headers=headers, json=request_json)
        
        if res.status_code != 200:
            log_warning(f"API Error: {res.json().get('message', 'Unknown error')}")
            continue
        
        license_data = res.json()
        license_info = {
            'sku': license_data['assetDetails']['license']['licenseSKU'],
            'file': license_data['assetDetails']['license']['licenseFile'],
            'serial': license_data['assetDetails']['serialNumber']
        }
        
        log_output(f"Registered {license_info['sku']} ({license_info['serial']})")
        licenses.append(license_info)
    
    return licenses

def write_license_files(directory, licenses):
    directory = directory or os.getcwd()
    for license in licenses:
        if not license['file']:
            log_warning(f"No license file received for {license['serial']}")
            continue
        
        license_path = os.path.join(directory, f"{license['serial']}.lic")
        try:
            with open(license_path, 'w') as f:
                log_output(f"Writing {license_path}")
                f.write(license['file'])
        except:
            log_warning(f"Could not open {license_path} for writing, skipping...")

def main():
    parser = argparse.ArgumentParser(description='Extract, register, and download Fortinet licenses.')
    parser.add_argument('zip_files', nargs='*', help='ZIP files containing license PDFs')
    parser.add_argument('-u', '--username', help='FortiCloud API username')
    parser.add_argument('-p', '--password', help='FortiCloud API password')
    parser.add_argument('-c', '--client_id', default='assetmanagement', help='Client ID')
    parser.add_argument('-l', '--license-dir', help='Path to save registered licenses')
    parser.add_argument('-n', '--no-licenses', action='store_true', help="Don't download licenses")
    parser.add_argument('-i', '--ipv4-addresses', help='Assign IPv4 addresses when registering')
    args = parser.parse_args()

    codes = extract_reg_codes(args.zip_files)
    if not codes:
        log_error("No codes found, exiting")

    ipv4_addresses = license_ipv4_addresses(args.ipv4_addresses, len(codes))

    dotfile_creds_data = dotfile_creds()
    credentials = {
        'username': dotfile_creds_data.get('username') or args.username or os.environ.get('FORTICLOUD_API_USER'),
        'password': dotfile_creds_data.get('password') or args.password or os.environ.get('FORTICLOUD_API_PASSWORD') or os.environ.get('FORTICARE_API_PASSWORD'),
        'client_id': args.client_id
    }

    access_token = forticare_auth(credentials)
    licenses = forticare_register(access_token, codes, ipv4_addresses)

    if not args.no_licenses:
        write_license_files(args.license_dir, licenses)

if __name__ == '__main__':
    main()