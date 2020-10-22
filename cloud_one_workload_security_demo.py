from cloud_one_antimalware_test import antimalwaretest
from cloud_one_ips_test import ipstest
from cloud_one_web_reputation_test import webreputationtest
from cloud_one_integrity_monitoring_test import integritymonitoringtest
from cloud_one_log_inspection_test import loginspectiontest
from cloud_one_application_control_test import applicationcontroltest
from cloud_one_docker_am_test import dockeramtest
from cloud_one_workload_security_demo_utils import getpolicyid, listpolicies, getoperatingsystem, gethostid
import deepsecurity
from deepsecurity.rest import ApiException
import sys, warnings
import time

# This script will run tests against Deep Security or Cloud One agents to create events in the console and populate the dashboard
# Setup:
#    These tests use curl and netcat so ensure that you have them installed on the system under tests
#    The Deep Security Agent should be installed on the machine under test and it needs to be activated with a policy assigned
#    You may need to modify two lines:
#       configuration.host - If you are not using Cloud One Workload Security and are using an on-premise Deep Security Manager, change the URL to point to the correct Deep Security Manager
#       configuration.api_key - Modify this line with the API key you have created for your Cloud One Workload Security or Deep Security Account
#                               For more information on creating API keys see: https://cloudone.trendmicro.com/docs/workload-security/api-send-request/#create-an-api-key
# Running the script:
#    You can run the script using: python3 cloud_one_workload_security_demo.py
#    After you run the script, it will provide a list of the policies in your Cloud One Workload or Deep Security Account
#    Select the policy that is assigned to the system under test
#    Confirm the system under test is correct, or if you have multiple computers with the policy assigned, select the correct system under test
#    Then select which test to run:
#        1) Anti-malware
#        2) Intrusion Prevention
#        3) Integrity Monitoring
#        4) Web Reputation
#        5) Log Inspection
#        6) Application Control
#        7) Docker Anti-Malware (Supported on Linux only)
#        8) All Tests

def main ():
    # Setup and connect to Cloud One Workload Security or Deep Security
    api_version = 'v1'
    overrides = False
    if not sys.warnoptions:
        warnings.simplefilter("ignore")
    configuration = deepsecurity.Configuration()
    configuration.host = 'https://cloudone.trendmicro.com:443/api'
    configuration.api_key['api-secret-key'] = '<Your API Key>'
    
    print("Welcome to the test suite for Cloud One Workload Security")
    print("This script works by running a set of tests and assigns rules at the policy level if necessary")
    # Get the Operating System information
    operating_system = getoperatingsystem()
    print("")
    print("The policies in your Cloud One account are:")
    
    # List the policies and get the policy_id
    policy_id = getpolicyid(configuration, api_version, overrides)
    
    # Check the hosts that the policy is applied to so we can know what host
    # the tests are being run on
    host_id = gethostid(policy_id, configuration, api_version, overrides)
    print("")
    time.sleep(2)
    
    # Set the variables for the tests to run
    ips_rule_to_apply = "Restrict Download Of EICAR Test File Over HTTP"
    if("redhat" in operating_system or "ubuntu" in operating_system):
        im_rule_to_apply = "Unix - Open Port Monitor"
        li_rule_to_apply = "Unix - Syslog"
    if("windows" in operating_system):
        im_rule_to_apply = "Microsoft Windows - 'Hosts' file modified"
        li_rule_to_apply = "Microsoft Windows Events"
        
    # Check with the user what test the user wants to run
    user_input = 0
    while(user_input == 0):
        print("The available tests are: ")
        print("1 = Anti-Malware")
        print("2 = Intrusion Prevention")
        print("3 = Integrity Monitoring")
        print("4 = Web Reputation")
        print("5 = Log Inspection")
        print("6 = Application Control (Note: This test takes about 3 minutes to run)")
        print("7 = Docker Anti-Malware (only works on Ubuntu and Redhat)")
        print("8 = All Tests")
        print("Which test would you like to perform: ")
        user_input = input()
        if (not user_input.isdigit()) or (int(user_input) > 8):
            print("Invalid option, please try again")
            user_input = 0
    
    # Run the anti-malware test
    if(int(user_input) == 1):
        antimalwaretest(operating_system)
        exit()
    
    # Run the intrusion prevention test
    if(int(user_input) == 2):
        ipstest(ips_rule_to_apply, policy_id, configuration, api_version, overrides, operating_system)
        exit()
    
    # Run the Integrity Monitoring test
    if(int(user_input) == 3):
        integritymonitoringtest(host_id, im_rule_to_apply, policy_id, configuration, api_version, overrides, operating_system)
        exit()
    
    # Run the Web Reputation test
    if(int(user_input) == 4):
        webreputationtest(policy_id, configuration, api_version, overrides, operating_system)
        exit()
    
    # Run the Log Inspection test
    if(int(user_input) == 5):
        loginspectiontest(li_rule_to_apply,policy_id, configuration, api_version, overrides, operating_system)
        exit()
        
    # Run the Application Control test
    if(int(user_input) == 6):
        applicationcontroltest(host_id, policy_id, configuration, api_version, overrides, operating_system)
        exit()
    
    # Run the Docker antimalware test
    if(int(user_input) == 7):
        dockeramtest(host_id, policy_id, configuration, api_version, overrides, operating_system)
        exit()
        
    # Run all tests
    if(int(user_input) == 8):
        print("Running all tests")
        antimalwaretest(operating_system)
        ipstest(ips_rule_to_apply,policy_id, configuration, api_version, overrides, operating_system)
        integritymonitoringtest(host_id, im_rule_to_apply, policy_id, configuration, api_version, overrides, operating_system)
        webreputationtest(policy_id, configuration, api_version, overrides, operating_system)
        loginspectiontest(li_rule_to_apply,policy_id, configuration, api_version, overrides, operating_system)
        applicationcontroltest(host_id, policy_id, configuration, api_version, overrides, operating_system)
        if("ubuntu" in operating_system or "redhat" in operating_system):
            dockeramtest(host_id, policy_id, configuration, api_version, overrides, operating_system)
        exit()
        
if __name__ == "__main__":
    main()
