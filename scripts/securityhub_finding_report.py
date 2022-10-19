# Generates a CSV file with a list of all CRITICAL and HIGH SecurityHub findings
# Row output is the title, resource type, resource ARN and the remediation URL if it exists

import argparse
import boto3
import csv
from datetime import datetime as dt

parser = argparse.ArgumentParser()
parser.add_argument('--profile', help='AWS profile; default profile will be used if --profile not used')
parser.add_argument('--accountName', required=True, help='Used in csv file name')
parser.add_argument('--regions', required=True, nargs='+', help="Regions to inspect; --regions us-east-1 us-west-2")
parser.add_argument('--apiRegion', default='us-east-1', help='Region to use for API calls; default is us-east-1')
args = parser.parse_args()
aws_profile = args.profile
aws_regions = args.regions
account_name = args.accountName
api_region = args.apiRegion

dt_format = '%Y-%m-%d'
output_csvfile = f'sechub_findings_{account_name}_{dt.strftime(dt.utcnow(), dt_format)}.csv'

# Set up the SecurityHub finding filter
finding_filter = {
    'Region': [{'Value': i, 'Comparison': 'EQUALS'} for i in aws_regions],
    'SeverityLabel': [
        {
            'Value': 'HIGH',
            'Comparison': 'EQUALS'
        },
        {
            'Value': 'CRITICAL',
            'Comparison': 'EQUALS'
        }
    ],
    'RecordState': [
        {
            'Value': 'ACTIVE',
            'Comparison': 'EQUALS'
        }
    ],
    'WorkflowState': [
        {
            'Value': 'NEW',
            'Comparison': 'EQUALS'
        }
    ],
    'WorkflowStatus': [
        {
            'Value': 'NEW',
            'Comparison': 'EQUALS'
        }
    ],
}

def transform_resp(resp_paginator):
    def get_remediation_url(afinding):
        '''Verifies Remediation and Url exist; return n/a if not'''
        if afinding.get('Remediation', None) and afinding['Remediation']['Recommendation'].get('Url', None):
            return afinding['Remediation']['Recommendation']['Url']
        else:
            return 'n/a'

    for rp in resp_paginator:
        finding_output = [[i['Severity']['Label'],
        i['Title'],
        i['Resources'][0]['Type'],
        i['Resources'][0]['Id'],
        get_remediation_url(i)]
        for i in rp['Findings']]
    return finding_output

session_params = {'region_name': api_region}
if aws_profile:
    session_params['profile_name'] = aws_profile
client = boto3.Session(**session_params).client('securityhub')

paginator = client.get_paginator('get_findings')
resp_paginator = paginator.paginate(Filters=finding_filter)

output_data = transform_resp(resp_paginator)
if output_data:
    with open(output_csvfile, 'w') as f:
        writer = csv.writer(f)
        writer.writerows(output_data)
    print(f'... Findings output to {output_csvfile}')
else:
    print('... No SecurityHub findings output')