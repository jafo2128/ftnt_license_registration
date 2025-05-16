#!/usr/bin/env python3

"""
## Converted from perl to Python
## By David Thomson @ 20250514
## Version 10.0

Please install these libraries first:

python.exe -m pip install --upgrade pip
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
import re
from datetime import datetime

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
    headers = ['ZIP File', 'PDF Name', 'Issue Date', 'Purchase Order', 'Registration Code', 'Qty', 'Part Number', 'Description']
    data = [headers]
    
    for code_info in codes:
        row = [
            code_info.get('zip_file', ''),
            code_info.get('pdf_name', ''),
            code_info.get('issue_date', ''),
            code_info.get('purchase_order', ''),
            code_info.get('registration_code', ''),
            code_info.get('qty', ''),
            code_info.get('part_number', ''),
            code_info.get('description', '')
        ]
        data.append(row)
        
        # Debug output for each row
        log_output("\nRow being added to CSV:")
        for header, value in zip(headers, row):
            log_output(f"{header}: {value}")
    
    # Write to CSV with UTF-8 encoding
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerows(data)
    
    log_output(f"\nCSV file created: {output_file}")
    
    # Display on console
    print("\nExtracted Information:")
    print(tabulate(data[1:], headers=headers, tablefmt="grid"))

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
                        info = {}
                        
                        # Check first 2 pages
                        for page_num in range(min(2, len(pdf.pages))):
                            text = pdf.pages[page_num].extract_text()
                            
                            # Debug: Print the exact text we're working with
                            log_output(f"\nPage {page_num + 1} Content:")
                            log_output("=" * 50)
                            log_output(text)
                            log_output("=" * 50)
                            
                            # Try multiple date patterns
                            date_patterns = [
                                r'Issue\s*Date\s*:\s*((?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},?\s*\d{4})',
                                r'Issue\s*Date\s*:\s*(\w+\s+\d{1,2},?\s*\d{4})',
                                r'IssueDate\s*:\s*(\w+\s*\d{1,2},?\s*\d{4})'
                            ]
                            
                            for pattern in date_patterns:
                                date_match = re.search(pattern, text, re.IGNORECASE)
                                if date_match:
                                    info['issue_date'] = date_match.group(1).strip()
                                    log_output(f"Found Issue Date: {info['issue_date']}")
                                    break
                            
                            # Try multiple registration code patterns
                            # Update the registration code pattern
                            code_patterns = [
                                r'Contract\s*Registration\s*Code\s*:\s*([A-Z0-9]{12})',  # Changed to 12 characters
                                r'Registration\s*Code\s*:\s*([A-Z0-9]{12})'  # Changed to 12 characters
                            ]        

                            for pattern in code_patterns:
                                code_match = re.search(pattern, text, re.IGNORECASE)
                                if code_match:
                                    info['registration_code'] = code_match.group(1).strip()
                                    log_output(f"Found Registration Code: {info['registration_code']}")
                                    break
  
                            po_match = re.search(r'Purchase\s*Order\s*Number\s*:\s*(\d+)', text, re.IGNORECASE)
                            if po_match:
                                info['purchase_order'] = po_match.group(1).strip()
                                log_output(f"Found Purchase Order: {info['purchase_order']}")
                            
                            qty_match = re.search(r'Qty\s*Part\s*Number.*?\n(\d+)\s+([\w-]+)\s+(.*?)(?=\n\d|\Z)', text, re.DOTALL | re.IGNORECASE)
                            if qty_match:
                                info['qty'] = qty_match.group(1).strip()
                                info['part_number'] = qty_match.group(2).strip()
                                info['description'] = qty_match.group(3).replace('\n', ' ').strip()
                                log_output(f"Found Qty: {info['qty']}, Part Number: {info['part_number']}")
                        
                        if info:
                            info['zip_file'] = os.path.basename(zip_file)
                            info['pdf_name'] = pdf_name
                            log_output("\nExtracted Information:")
                            for key, value in info.items():
                                log_output(f"{key}: {value}")
                            codes.append(info)
                        else:
                            log_warning(f"No information extracted from '{pdf_name}'")
                    
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


def format_registration_code(code):
    """Format registration code with hyphens every 4 characters"""
    # Remove any existing hyphens or spaces
    code = code.replace('-', '').replace(' ', '')
    # Insert hyphens every 4 characters
    return '-'.join([code[i:i+4] for i in range(0, len(code), 4)])

def forticare_register(access_token, reg_codes, ipv4_addresses):
    licenses = []
    ua = requests.Session()

    for code in reg_codes:
        log_output(f"Validating code {code}")
        
        # First, try to validate the license
        validate_json = {
            "licenseRegistrationCode": code
        }

        try:
            validate_res = ua.post(
                'https://support.fortinet.com/ES/api/registration/v3/licenses/validate',
                headers={
                    'Authorization': f'Bearer {access_token}',
                    'Content-Type': 'application/json'
                },
                json=validate_json
            )
            
            log_output(f"Validation API Response Status: {validate_res.status_code}")
            log_output(f"Validation API Response Content: {validate_res.text}")

            if validate_res.status_code != 200:
                log_warning(f"License validation failed for code {code}")
                continue

            # If validation successful, proceed with registration
            log_output(f"License validation successful. Proceeding with registration for code {code}")

            current_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            register_json = {
                "licenseRegistrationCode": code,
                "description": f"Auto NetOPS Registered {current_date}"
            }

            register_res = ua.post(
                'https://support.fortinet.com/ES/api/registration/v3/licenses/register',
                headers={
                    'Authorization': f'Bearer {access_token}',
                    'Content-Type': 'application/json'
                },
                json=register_json
            )
            
            log_output(f"Registration API Response Status: {register_res.status_code}")
            log_output(f"Registration API Response Content: {register_res.text}")

            if register_res.status_code == 200:
                license_data = register_res.json()
                
                if 'error' not in license_data:
                    license_info = {
                        'sku': license_data.get('assetDetails', {}).get('license', {}).get('licenseSKU', ''),
                        'file': license_data.get('assetDetails', {}).get('license', {}).get('licenseFile', ''),
                        'serial': license_data.get('assetDetails', {}).get('serialNumber', '')
                    }
                    log_output(f"Successfully registered {license_info['sku']} ({license_info['serial']})")
                    licenses.append(license_info)
                else:
                    log_warning(f"API returned an error: {license_data['error'].get('message', 'Unknown error')}")
            else:
                log_warning(f"API Error for code {code}: {register_res.status_code}")
                log_warning(f"Response content: {register_res.text}")

        except Exception as e:
            log_warning(f"Error processing registration for code {code}: {str(e)}")

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
        log_error("No information found, exiting")

    create_and_display_csv(extracted_info, args.output_csv)

    codes = [info['registration_code'] for info in extracted_info if 'registration_code' in info]
    if not codes:
        log_error("No registration codes found, exiting")

    # Verify registration code format
    valid_codes = [code for code in codes if re.match(r'^[A-Z0-9]{12}$', code)]  # Changed to 12 characters
    if len(valid_codes) != len(codes):
        log_warning(f"Found {len(codes) - len(valid_codes)} invalid registration codes. They will be skipped.")
        log_warning(f"Invalid codes: {set(codes) - set(valid_codes)}")
    
    if not valid_codes:
        log_error("No valid registration codes found, exiting")

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

    try:
        access_token = forticare_auth(credentials)
        licenses = forticare_register(access_token, codes, ipv4_addresses)

        if not args.no_licenses:
            write_license_files(args.license_dir, licenses)
    except Exception as e:
        log_error(f"An error occurred during registration: {str(e)}")

if __name__ == '__main__':
    main()