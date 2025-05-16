Calling the python app.  Ver 6

usage: ftnt_license_registration.py [-h] [-u USERNAME] [-p PASSWORD] [-c CLIENT_ID] [-l LICENSE_DIR] [-n]
                                    [-i IPV4_ADDRESSES] [-o OUTPUT_CSV]
                                    [zip_files ...]


As example:

python C:\david\Dev\GitHub\jafo2128\ftnt_license_registration\ftnt_license_registration.py -u 'xxxxxxxx' -p 'xxxxxxx' -l C:\david\Inprogress\Core\license\20250514 --client-id YourClientID FC3-10-FGVVS-990-02-36_99438909.zip

Now with CSV support

python C:\david\Dev\GitHub\jafo2128\ftnt_license_registration\ftnt_license_registration.py -u 'xxxxxxx' -p 'xxxxxxxx' -l C:\david\Inprogress\Core\license\20250514 -o IranIt.csv -c YourClientID FC3-10-FGVVS-990-02-36_99438909.zip


REF:
me@me.com
1274448 / me

{
    "username": "IAM API username",

    "password": "IAM API password",

    "client_id": "assetmanagement",
    
    "grant_type": "password"
}

python C:\david\Dev\GitHub\jafo2128\ftnt_license_registration\ftnt_license_registration.py -u '68E3B49C-EAEA-4A07-A0C0-A47B32961574' -p 'fc4f42c88eac146f7eb4ed022457d4b5!1Aa' -l C:\david\Inprogress\Core\license\20250514 -o IranIt.csv -c 'assetmanagement' FC3-10-FGVVS-990-02-36_99438909.zip


current call looks like this :

python ftnt_license_registration.py -u '68E3B49C-EAEA-4A07-A0C0-A47B32961574' -p 'fc4f42c88eac146f7eb4ed022457d4b5!1Aa' -l C:\david\Inprogress\Core\license\20250514 -o IranIt.csv -c 'assetmanagement' C:\david\Inprogress\Core\license\20250514\test\0326HM425917.zip



