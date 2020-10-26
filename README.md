# cloudOneWorkloadSecurityDemo
These scripts will help you trigger events in Cloud One Workload Security
NOTE: These scripts are provided as-is with no implied support.  You are welcome to comment if you find issues, but there's no guarantee on if or when they'll be fixed.

Before running these scripts perform ensure you have the following:
1)	A Cloud One Workload Security Account
2)	A Ubuntu 18.04, Redhat 8 or Windows Server
3)	You have installed the agent on the system and activated it in your Cloud One Workload Security console
4)	The system under test must have:
* Python3
* Curl
* Netcat (Linux Only)
* Unzip
5)	The files from this repository
* Download these files and put them in a directory on the system under test
6)	The Python SDK for Deep Security/Cloud One
* Download the SDK from: https://automation.deepsecurity.trendmicro.com/wp-content/sdk/fr/on-premise/v1/dsm-py-sdk.zip and put it in the same folder as the files you just downloaded
* Unzip the file
* Install the sdk using: python3 -m pip install .
7)	Edit the cloud_one_workload_security_demo.py
* Find the line: configuration.api_key['api-secret-key'] = '<Your API Key>'
* Modify the line and change the <Your API Key> to your actual API key (if you don't have an API key see the help: https://cloudone.trendmicro.com/docs/workload-security/api-cookbook-set-up/#create-an-api-key
* Once you've added your API key save the file
  
Now you can run the script using: python3 cloud_one_workload_security_demo.py
