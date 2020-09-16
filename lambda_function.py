#########################
#    Work in progress   #
#########################

import boto3
import json
import os
from datetime import datetime, timedelta
from dateutil import parser
from botocore.exceptions import ClientError
from collections import namedtuple

# initialize IAM connection
resource = boto3.resource('iam')
client = boto3.client("iam")

# custom log stream
logs = boto3.client('logs')
try:
    logs.create_log_group(logGroupName='disable-inactive-unused-iam')
except Exception as e:
    print(e)
try:
    logs.create_log_stream(logGroupName='disable-inactive-unused-iam', logStreamName='user')
except Exception as e:
    print(e)
try:
    logs.create_log_stream(logGroupName='disable-inactive-unused-iam', logStreamName='key')
except Exception as e:
    print(e)

# user tuple format
User = namedtuple('User', 'user arn user_creation_time password_enabled password_last_used password_last_changed password_next_rotation mfa_active access_key_1_active access_key_1_last_rotated access_key_1_last_used_date access_key_1_last_used_region access_key_1_last_used_service access_key_2_active access_key_2_last_rotated access_key_2_last_used_date access_key_2_last_used_region access_key_2_last_used_service cert_1_active cert_1_last_rotated cert_2_active cert_2_last_rotated')

def lambda_handler(event, context):
    # generate report
    # response = client.generate_credential_report()
    
    # format report to readable
    response = client.get_credential_report()
    body = response['Content'].decode('utf-8')
    lines = body.split('\n')
    users = [User(*line.split(',')) for line in lines[1:]]
    
    # current Datetime
    today = datetime.now()
    
    # initialize lists
    never_logged_in_user = []            # console user
    inactive_past_90_days_user = []      # console user
    never_used_key = []                  # access key user
    inactive_past_90_days_key = []       # access key user
    
    for user in users:
        # user has access privilege to web aws console
        if user.password_enabled == 'true':
            
            # user used their password at least one time
            if (user.password_last_used != 'N/A' and user.password_last_used != 'no_information'):
                
                # convert string to datetime
                temp_user_password_last_used = parser.parse(user.password_last_used)
                delta = (today - temp_user_password_last_used.replace(tzinfo=None)).days
                
                # check if user dont logged in for the past 90 days
                if delta >= 90:
                    inactive_past_90_days_user.append({
                        'username': user.user,
                        'inactivity_time': delta
                    })
                    
            # user never used password (never made login)
            else:
                never_logged_in_user.append({
                        'username': user.user
                    })
              
        # user has only api keys
        else:
            # check if access key 1 is active
            if user.access_key_1_active == 'true':
                
                # user used this key at least one time
                try:
                    # convert string to datetime
                    temp_user_password_last_used = parser.parse(user.access_key_1_last_used_date)
                    delta = (today - temp_user_password_last_used.replace(tzinfo=None)).days
                    
                    # check if user dont logged in for the past 90 days
                    if delta >= 90:
                        inactive_past_90_days_key.append({
                            'username': user.user,
                            'key': 'key1',
                            'inactivity_time': delta
                        })
                        
                except:
                    never_used_key.append({
                        'username': user.user,
                        'key': 'key1'
                    })
                    
            # check if access key 1 is active
            if user.access_key_2_active == 'true':
                
                # user used this key at least one time
                try:
                    # convert string to datetime
                    temp_user_password_last_used = parser.parse(user.access_key_2_last_used_date)
                    delta = (today - temp_user_password_last_used.replace(tzinfo=None)).days
                    
                    # check if user dont logged in for the past 90 days
                    if delta >= 90:
                        inactive_past_90_days_key.append({
                            'username': user.user,
                            'key': 'key2',
                            'inactivity_time': delta
                        })
                        
                except:
                    never_used_key.append({
                        'username': user.user,
                        'key': 'key2'
                    })
                

        
    print(inactive_past_90_days_user)
    print(never_logged_in_user)
    print()
    print(inactive_past_90_days_key)
    print(never_used_key)
    
    # timestamp = int(round(time.time() * 1000))
    # response = logs.put_log_events(
    # logGroupName='disable-inactive-unused-iam',
    # logStreamName='user',
    # logEvents=[
    #         {
    # 'timestamp': timestamp,
    # 'message': time.strftime('%Y-%m-%d %H:%M:%S')+'\tHello world, here is our first log message!'
    #         }
    #     ]
    # )
        
    return {
        "statusCode": 200,
        "body": json.dumps({
            "message": "Disable Inactive IAM Users Execution successful",
        }),
    }
