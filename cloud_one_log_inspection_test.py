import deepsecurity
from deepsecurity.rest import ApiException
from pprint import pprint
import subprocess
from subprocess import Popen, PIPE, STDOUT
from cloud_one_workload_security_demo_utils import getruleid, checkifruleassigned, runcommand, sendheartbeat
import time

# This is the log inspection test
# The Log Inspection test will check if the LIrule has been assigned
# If it's not assigned the test will assign it
# The test will then create a new user in the system
# This should trigger an event that a user was created
# The test will then delete that user
# This should trigger an event that a user was deleted
# If the rule was not assigned originally, the rule will be removed from the policy
# The test will also perform a heartbeat to ensure the events get back to 
# Cloud One Workload Security or Deep Security Manager
def loginspectiontest(rule_to_apply, policy_id, configuration, api_version, overrides, operating_system):
    print("---Running The Log Inspection Test---")
    #Get the LI Rule ID
    rule_id = getruleid("li", rule_to_apply, configuration, api_version)
    
    # Check if the rule is assigned to the policy
    found = checkifruleassigned(rule_to_apply, "li", rule_id, policy_id, configuration, api_version, overrides)
    
    # If the rule is not assigned, then assign it
    if(found == False):
        assignlirule(rule_to_apply, rule_id, policy_id, configuration, api_version, overrides, True)
    
    # Run the tests
    runtest(operating_system)

    # If the rule was not originally assigned, remove it to restore the state of the policy
    if(found == False):
        assignlirule(rule_to_apply, rule_id, policy_id, configuration, api_version, overrides, False)
    
    # Perform a heartbeat to get the events to Cloud One or Deep Security Manager
    sendheartbeat(operating_system)
    print("---Log Inspection Test Completed---")  
        
# This function will assign the rule to the policy if it is not already assigned
# If add_rule is True then it will assign the rule
# If add_rule is False then it will remove the rule from the policy        
def assignlirule(rule_to_apply, rule_id, policy_id, configuration, api_version, overrides, add_rule):
    try:
        # Get the current list of rules from the policy
        policies_api = deepsecurity.PoliciesApi(deepsecurity.ApiClient(configuration))
        current_rules = policies_api.describe_policy(policy_id, api_version, overrides=False)
        
        # Add the rule_id if it doesn't already exist in current_rules
        if(add_rule == True):
            print("Adding the " + rule_to_apply + " rule to the policy")
            if current_rules.log_inspection.rule_ids is None:
                current_rules.log_inspection.rule_ids = rule_id
        
            elif rule_id not in current_rules.log_inspection.rule_ids:
                current_rules.log_inspection.rule_ids.append(rule_id)
        # Remove the rule_id if it was originally unassigned
        else:
            print("Removing the " + rule_to_apply + " rule from the policy")
            current_rules.log_inspection.rule_ids.remove(rule_id)
        
        # Add the new and existing intrusion prevention rules to a policy
        log_inspection_policy_extension = deepsecurity.LogInspectionPolicyExtension()
        log_inspection_policy_extension.rule_ids = current_rules.log_inspection.rule_ids
        policy = deepsecurity.Policy()
        policy.log_inspection = log_inspection_policy_extension
    
        # Configure sending policy updates when the policy changes
        policy.auto_requires_update = "on"
    
        # Modify the policy on Deep Security Manager
        modified_policy = policies_api.modify_policy(policy_id, policy, api_version)
    except ApiException as e:
        print("An exception occurred when calling PolicyIntegrityMonitoringRuleAssignmentsRecommendationsApi.add_intrusion_prevention_rule_ids_to_policy: %s\n" % e)

# This function will run the tests
# It uses adduser and deluser on Linux
# It uses net user on Windows
def runtest(operating_system):
    if("ubuntu" in operating_system):
        #Run the test
        cmd = "sudo adduser --disabled-password --gecos \"\" hacker1"
        output = runcommand(cmd)
        time.sleep(2)
        cmd = "sudo deluser hacker1"
        output = runcommand(cmd)
    if("redhat" in operating_system):
        #Run the test
        cmd = "sudo adduser -m hacker1"
        output = runcommand(cmd)
        time.sleep(2)
        cmd = "sudo userdel -f -r hacker1"
        output = runcommand(cmd)
    if("windows" in operating_system):
        #Run the test
        cmd = "net user hacker1 Temp12345! /add"
        output = runcommand(cmd)
        time.sleep(2)
        cmd = "net user hacker1 /delete"
        output = runcommand(cmd)