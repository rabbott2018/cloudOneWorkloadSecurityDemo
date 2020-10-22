import deepsecurity
from deepsecurity.rest import ApiException
import subprocess
from pprint import pprint
from cloud_one_workload_security_demo_utils import getruleid, checkifruleassigned, sendheartbeat
import time

# This is the intrusion prevention test
# The intrusion prevention test will ensure that the IPS rule for 
# Restrict Download Of EICAR Test File Over HTTP is assigned to the policy
# If it's not assigned the test will assign it
# Then an attempt will be be made to download the eicar file
# This should result in a block of the file being downloaded and an event in Intrusion Prevention
# If the rule was not assigned originally, the rule will be removed from the policy
# The test will also perform a heartbeat to ensure the events get back to 
# Cloud One Workload Security or Deep Security Manager
def ipstest(rule_to_apply, policy_id, configuration, api_version, overrides, operating_system):
    #Get the IPS rule id for the rule defined by rule_to_apply
    print("---Running The Intrusion Prevention Test---")
    rule_id = getruleid("ips", rule_to_apply, configuration, api_version)
    
    #Check if the rule is assigned to the policy
    found = checkifruleassigned(rule_to_apply, "ips", rule_id, policy_id, configuration, api_version, overrides)
    
    #If the rule is not assigned, assign it
    if(found == False):
        assignipsrule(rule_to_apply, rule_id, policy_id, configuration, api_version, overrides, True)
    
    # Wait for the policy to be sent
    time.sleep(10)
    
    # Run the test
    runtest()
    
    #If the rule was not originally assigned, unassign it to restore the original state
    if(found == False):
        assignipsrule(rule_to_apply, rule_id, policy_id, configuration, api_version, overrides, False)
    
    #Perform a heartbeat to get the events to Cloud One or Deep Security Manager
    sendheartbeat(operating_system)
    print("---Intrusion Prevention Test Complete---")
    
# This function will assign the rule to the policy if it is not already assigned
# If add_rule is True then it will assign the rule
# If add_rule is False then it will remove the rule from the policy
def assignipsrule(rule_to_apply, rule_id, policy_id, configuration, api_version, overrides, add_rule):
    try:
        # Get the current list of rules from the policy
        policies_api = deepsecurity.PoliciesApi(deepsecurity.ApiClient(configuration))
        current_rules = policies_api.describe_policy(policy_id, api_version, overrides=False)

        # Add the rule_id if it doesn't already exist in current_rules
        if(add_rule == True):
            print("Adding the " + rule_to_apply + " rule to the policy")
            if current_rules.intrusion_prevention.rule_ids is None:
                current_rules.intrusion_prevention.rule_ids = rule_id
        
            elif rule_id not in current_rules.intrusion_prevention.rule_ids:
                current_rules.intrusion_prevention.rule_ids.append(rule_id)
        # Remove the rule_id if it was originally unassigned
        else:
            print("Removing the " + rule_to_apply + " rule from the policy")
            current_rules.intrusion_prevention.rule_ids.remove(rule_id)
    
        # Update the intrusion prevention rules for the policy
        intrusion_prevention_policy_extension = deepsecurity.IntrusionPreventionPolicyExtension()
        intrusion_prevention_policy_extension.rule_ids = current_rules.intrusion_prevention.rule_ids
        policy = deepsecurity.Policy()
        policy.intrusion_prevention = intrusion_prevention_policy_extension
    
        # Configure sending policy updates when the policy changes
        policy.auto_requires_update = "on"
    
        # Modify the policy on Cloud One Workload Security or Deep Security Manager
        modified_policy = policies_api.modify_policy(policy_id, policy, api_version)
    except ApiException as e:
        print("An exception occurred when calling PolicyIntrusionPreventionRuleAssignmentsRecommendationsApi.add_intrusion_prevention_rule_ids_to_policy: %s\n" % e)
    
# This function will attempt to download the eicar file and trigger the rule   
def runtest():
    print("Attempting to download the Eicar file")       
    subprocess.call(['curl','http://malware.wicar.org/data/eicar.com'])