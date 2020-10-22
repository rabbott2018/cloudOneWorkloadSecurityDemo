import deepsecurity
from deepsecurity.rest import ApiException
import subprocess
from pprint import pprint
import time
from cloud_one_workload_security_demo_utils import sendheartbeat

# This is the Web Reputation Test
# This test will ensure that WRS is turned on for the policy
# It will then attempt to access suspicious URLS to trigger events
# Note the default for a policy is to block pages that are Dangerous or Highly Suspicious
# So you may not get events for all of these URLs
# After the tests are run then WRS is turned off it was off originally to reset the policy
# To it's original state
def webreputationtest(policy_id, configuration, api_version, overrides, operating_system):
    print("---Running The Web Reputation Test---")
    # Check if WRS is on or off
    current_state = checkifwrson(policy_id, configuration, api_version, overrides)
    
    # If it's off, let's turn it on
    if ("off" in current_state):
        modifywrsstate(policy_id, configuration, api_version, overrides, "on")
    time.sleep(10)
    
    # Attempt to access each of the sites to trigger events
    print("Testing the Dangerous URL: http://wrs49.winshipway.com/")
    print(subprocess.call(['curl','http://wrs49.winshipway.com/']))
    
    print("Testing the Highly Suspicious URL: http://wrs65.winshipway.com/")
    print(subprocess.call(['curl','http://wrs65.winshipway.com/']))
    
    print("Testing the Suspicious URL: http://wrs70.winshipway.com/")
    print(subprocess.call(['curl','http://wrs70.winshipway.com/']))
    
    print("Testing the Unrated URL: http://wrs71.winshipway.com/")
    print(subprocess.call(['curl','http://wrs71.winshipway.com/']))
    
    print("Testing the Normal URL: http://wrs81.winshipway.com/")
    print(subprocess.call(['curl','http://wrs81.winshipway.com/']))
    
    print("Testing the Dangerous C&C URL: http://ca91-1.winshipway.com/")
    print(subprocess.call(['curl','http://ca91-1.winshipway.com/']))
    
    # If WRS was off originally, turn it off again
    if ("off" in current_state):
        modifywrsstate(policy_id, configuration, api_version, overrides, "off")
        
    # Perform a heartbeat to get the events to Cloud One or Deep Security Manager
    sendheartbeat(operating_system)
    print("---Web Reputation Test Completed---")

# This function will check the current status of WRS
def checkifwrson(policy_id, configuration, api_version, overrides):
    policies_api = deepsecurity.PoliciesApi(deepsecurity.ApiClient(configuration))
    current_wrs_settings = policies_api.describe_policy(policy_id, api_version, overrides=False)
    return(current_wrs_settings.web_reputation.state)

# This function will turn WRS on or off
# If on_off is set to "on" then it will turn WRS on
# If on_off is set to "off" then it will turn WRS off
def modifywrsstate(policy_id, configuration, api_version, overrides, on_off):
    print("Changing the WRS state to: " + on_off)
    policies_api = deepsecurity.PoliciesApi(deepsecurity.ApiClient(configuration))
    current_wrs_settings = policies_api.describe_policy(policy_id, api_version, overrides=False)
    #Configure sending policy updates when the policy changes
    web_reputation_policy_extension = deepsecurity.WebReputationPolicyExtension()
    web_reputation_policy_extension.state = on_off
    policy = deepsecurity.Policy()
    policy.web_reputation = web_reputation_policy_extension
         
    # Modify the policy on Deep Security Manager
    modified_policy = policies_api.modify_policy(policy_id, policy, api_version)
