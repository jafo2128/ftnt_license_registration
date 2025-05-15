#!/usr/bin/env python3

"""
## Converted from perl to Python
## By David Thomson @ 20250514
## Version 6.0

Please install these libraries first:

pip install termcolor requests PyPDF2
pip install tabulate

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

import csv
from tabulate import tabulate

import urllib.parse


def log_output(*args):
    print(colored('- ', 'green', attrs=['bold']) + ' '.join(map(str, args)), file=sys.stderr)

def log_error(*args):
    print(colored('- ' + ' '.join(map(str, args)), 'red', attrs=['bold']), file=sys.stderr)
    sys.exit(1)

def log_warning(*args):
    print(colored('- ' + ' '.join(map(str, args)), 'yellow', attrs=['bold']), file=sys.stderr)

def create_and_display_csv(codes, output_file='extracted_codes.csv'):
    # Prepare the data
    data = [['ZIP File', 'PDF Name', 'Registration Code']]
    for code_info in codes:
        data.append([code_info['zip_file'], code_info['pdf_name'], code_info['code']])
    
    # Write to CSV
    with open(output_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerows(data)
    
    log_output(f"CSV file created: {output_file}")
    
    # Display on console
    headers = data.pop(0)
    print("\nExtracted Registration Codes:")
    print(tabulate(data, headers=headers, tablefmt="grid"))

def extract_reg_codes(zip_files):
    codes = []
    for zip_file in zip_files:
        log_output(f"Reading {zip_file}")
        try:
            with ZipFile(zip_file, 'r') as zip_ref:
                for pdf_name in zip_ref.namelist():
                    if not pdf_name.lower().endswith('.pdf'):
                        continue
                    
                    log_output(f"Processing PDF: {pdf_name}")
                    pdf_content = zip_ref.read(pdf_name)
                    
                    try:
                        pdf = PdfReader(BytesIO(pdf_content))
                        
                        # Check first 3 pages
                        for page_num in range(min(3, len(pdf.pages))):
                            text = pdf.pages[page_num].extract_text()
                            
                            patterns = [
                                r'CONTRACT REGISTRATION CODE\s*:?\s*((\w{5}-){4}\w{6})',
                                r'CONTRACT REGISTRATION CODE\s*:?\s*(\S+)',
                                r'Registration Code\s*:\s*((\w{5}-){4}\w{6})',
                                r'Registration Code\s*:\s*(\S+)',
                                r'Registration\s+Code[:\s]+([A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{6})'
                            ]
                            
                            for pattern in patterns:
                                match = re.search(pattern, text, re.IGNORECASE)
                                if match:
                                    registration_code = match.group(1)
                                    log_output(f"Extracted code {registration_code} from page {page_num + 1}")
                                    codes.append({
                                        'zip_file': zip_file,
                                        'pdf_name': pdf_name,
                                        'code': registration_code
                                    })
                                    break
                            
                            if match:
                                break  # Stop checking pages if we found a code
                        
                        if not match:
                            log_warning(f"Error extracting code from '{pdf_name}'")
                            # Debug output
                            log_warning("First 500 characters of extracted text from each page:")
                            for page_num in range(min(3, len(pdf.pages))):
                                log_warning(f"Page {page_num + 1}:")
                                log_warning(pdf.pages[page_num].extract_text()[:500])
                                log_warning("---")
                    
                    except Exception as e:
                        log_warning(f"Error processing PDF {pdf_name}: {str(e)}")
                        
        except Exception as e:
            log_warning(f"Error processing zip file {zip_file}: {str(e)}")
    
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
    # Strip any leading/trailing whitespace from credentials
    username = credentials['username'].strip()
    password = credentials['password'].strip()
    client_id = credentials['client_id'].strip()

    auth_info = {
        'uri': 'https://customerapiauth.fortinet.com/api/v1/oauth/token/',
        'data': {
            'username': username,
            'password': password,
            'client_id': client_id,
            'grant_type': 'password'
        }
    }
    
    log_output(f"Attempting authentication for user: {username}")
    log_output(f"Using client_id: {client_id}")
    
    try:
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'FortinetLicenseRegistration/1.0'
        }
        res = requests.post(auth_info['uri'], data=auth_info['data'], headers=headers)
        res.raise_for_status()  # This will raise an exception for HTTP errors
        
        log_output("Authentication Success")
        return res.json()['access_token']
    except requests.exceptions.RequestException as e:
        log_error(f"Authentication Error: {str(e)}")
        if res.status_code == 401:
            log_error("This usually indicates incorrect username or password.")
        elif res.status_code == 400:
            log_error("This could indicate a problem with the client_id, grant type, or request format.")
        
        log_error("Response content:")
        log_error(res.text)
        
        # Additional debugging information
        log_error("Request details:")
        log_error(f"URL: {auth_info['uri']}")
        log_error(f"Headers: {headers}")
        log_error(f"Data: username={username}, password=******, client_id={client_id}, grant_type=password")
        
        sys.exit(1)


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
    parser.add_argument('-o', '--output-csv', default='extracted_codes.csv', help='Output CSV file name')
    args = parser.parse_args()

    extracted_info = extract_reg_codes(args.zip_files)
    if not extracted_info:
        log_error("No codes found, exiting")

    create_and_display_csv(extracted_info, args.output_csv)

    codes = [info['code'] for info in extracted_info]
    ipv4_addresses = license_ipv4_addresses(args.ipv4_addresses, len(codes))

    dotfile_creds_data = dotfile_creds()
    credentials = {
        'username': dotfile_creds_data.get('username') or args.username or os.environ.get('FORTICLOUD_API_USER'),
        'password': dotfile_creds_data.get('password') or args.password or os.environ.get('FORTICLOUD_API_PASSWORD') or os.environ.get('FORTICARE_API_PASSWORD'),
        'client_id': args.client_id
    }

    log_output("Using credentials:")
    log_output(f"Username: {credentials['username']}")
    log_output(f"Password: {'*' * len(credentials['password'])}")
    log_output(f"Client ID: {credentials['client_id']}")

    access_token = forticare_auth(credentials)
    licenses = forticare_register(access_token, codes, ipv4_addresses)

    if not args.no_licenses:
        write_license_files(args.license_dir, licenses)

if __name__ == '__main__':
    main()