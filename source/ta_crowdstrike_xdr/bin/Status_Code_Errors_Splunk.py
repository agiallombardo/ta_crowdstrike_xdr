#!/usr/bin/env python
# encoding = utf-8
import sys

class Status_Code_Errors():
    
    def status_code_errors(response, api_endpoint, log_label, helper, ew):
        log_label="testing: "
        #handles status codes that aren't 200 level responses
        status_code = response['status_code']
        helper.log_info(f"{log_label}:  Response code from the {api_endpoint} = {status_code}")

        status_code_check = str(status_code)
        if status_code_check.startswith('40'):
            cs_traceid = response['body']['meta']['trace_id']
            cs_error_msg = response['body']['errors'][0]['message']
            
            helper.log_error(f"{log_label}: Error contacting the CrowdStrike API, please provide this TraceID to CrowdStrike support = {cs_traceid}")
            helper.log_error(f"{log_label}: Error contacting the CrowdStrike API, error message = {cs_error_msg}")
            
        elif status_code_check.startswith('50'):
            cs_error_msg = response['body']['errors'][0]['message']
            helper.log_error(f"{log_label}: Error contacting the CrowdStrike API, error message = {cs_error_msg}")
            
        else:
            cs_traceid = response['headers']['X-Cs-Traceid']
            cs_error_msg = response['body']['errors'][0]['message']
            
            helper.log_error(f"{log_label}: Error contacting the CrowdStrike API, please provide this TraceID to CrowdStrike support = {cs_traceid}")
            helper.log_error(f"{log_label}: Error contacting the CrowdStrike API, error message = {cs_error_msg}")
            
  
        helper.log_error(f"{log_label}: TA is shutting down.")
        sys.exit()