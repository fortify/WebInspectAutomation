import requests
import json
import os
import sys
import time


###########################
##  Collect Scan Args   ###
###########################

#Capture command line arguments
arguments = sys.argv

print ("############ Scan Parameters ############", flush=True)
#Grab the scan mode from the command line arguments
if "ScanMode" in arguments:
    ScanMode = arguments[arguments.index("ScanMode") +1]
    print ("Scan mode: " + ScanMode, flush=True)

#Grab the BaseUrl from the command line arguments
if "BaseUrl" in arguments:
    BaseUrl = arguments[arguments.index("BaseUrl") + 1]
    print("Base WI URL: " + BaseUrl, flush=True)

#Grab the Payload file location from the command line arguments
if "DefaultFilePath" in arguments:
    DefaultFilePath = arguments[arguments.index("DefaultFilePath") + 1]
    print ("Default path for PayloadFile.txt and results: " + DefaultFilePath, flush=True)

#Grab the SSC URL
if "SSCUrl" in arguments:
    SSCUrl = arguments[arguments.index("SSCUrl") + 1]
    print ("SSC URL: " + SSCUrl, flush=True)

#Grab the SSC Auth token
if "SSCAuthToken" in arguments:
    SSCAuthToken = arguments[arguments.index("SSCAuthToken") + 1]
    print ("SSC Auth Token: " + SSCAuthToken, flush=True)

#Grab the Application Version ID
if "ApplicationVersionID" in arguments:
    ApplicationVersionID = arguments[arguments.index("ApplicationVersionID") + 1]
    print ("App Version ID in SSC: " + ApplicationVersionID, flush=True)

print ("#########################################", flush=True)

#Setting headers for all calls
headers = {
    'Content-Type': "application/json",
    'cache-control': "no-cache",
    }

###########################
##WebInspect Status     ###
###########################

#Build WebInspect Status URL
WebInspectStatusUrl = BaseUrl + "/Scanner/Scans"
querystring = {"Status":"Running"}

#Check for running scans
StatusResponse = requests.request("Get", WebInspectStatusUrl, params=querystring, headers=headers)

#Convert response to Dictionary 
json_data = json.loads(StatusResponse.text)
runningScans = len(json_data)

#Pause if there are any running scans
while (runningScans > 0):
    print (runningScans, flush=True)
    print ("Scans running.  Pausing for 60 seconds", flush=True)
    time.sleep(60)
    
    #Check for running scans
    StatusResponse = requests.request("Get", WebInspectStatusUrl, params=querystring, headers=headers)
    
    #Convert response to Dictionary 
    json_data = json.loads(StatusResponse.text)
    runningScans = len(json_data)


###########################
##        Scan Run      ###
###########################
#Build Scan Control URL
ScansUrl = BaseUrl + "/Scanner/Scans/"

if ScanMode == "Payload":
    #Open and read JSON Payload containing scan details to be passed to WebInspect
    f = open(DefaultFilePath + "\PayloadFile.txt", "r")
    payload = f.read()
    f.close()

#if ScanMode == "URL":
#    #Create JSON Payload
#    data['key'] = 'value'
#    json_data = json.dumps(data)

#Make the request to the API
response = requests.request("POST", ScansUrl, data=payload, headers=headers)

#Convert response to Dictionary 
json_data = json.loads(response.text)

#Print and store the ScanId of running scan from response payload
print("ScanId " + json_data.get("ScanId") + " is now running", flush=True)
ScanId = json_data.get("ScanId")


###########################
##      Scan Status     ###
###########################

#Build the URL for getting scan status
ScanStatusUrl = BaseUrl + "/Scanner/Scans/" + ScanId

#Wait for the scan to complete before exporting results
querystring = {"action":"WaitForStatusChange"}
StatusResponse = requests.request("Get", ScanStatusUrl, params=querystring, headers=headers)


###########################
##      Print Vulns     ###
###########################

#create the URL for requesting issue from sessionchecks
VulnsUrl = ScansUrl + "/" + ScanId + "/data/SessionChecks"
response = requests.request("Get", VulnsUrl, headers=headers)
json_data = json.loads(response.text)

#Make the vulnerability output pretty
jsondump = json.dumps(json_data, indent = 4, sort_keys=True)
print(jsondump, flush=True)

#Create a folder for this scan id
os.mkdir(DefaultFilePath + "\\" + ScanId)
outputFile = open(DefaultFilePath + "\\" + ScanId +"\\Vulnerabilities.txt","w")
outputFile.write(jsondump)
outputFile.close()


###########################
##      Download FPR    ###
###########################

r = requests.get(ScansUrl + "//" + ScanId + ".fpr")
with open(DefaultFilePath + "\\" + ScanId + "\\" + "Vulnerabilities.fpr", 'wb') as f:  
    f.write(r.content)
f.close()


###########################
##     Download Scan    ###
###########################

r = requests.get(ScansUrl + "//" + ScanId + ".scan")
with open(DefaultFilePath + "\\" + ScanId + "\\" + "Vulnerabilities.scan", 'wb') as f:  
    f.write(r.content)
f.close()


###########################
## Download Vuln Report ###
###########################
#ReportUrl = BaseUrl + "/Scanner/Reports/"
#r = requests.get(ReportUrl + ScanId + ".pdf" + "?reportType=Standard&reportName=Vulnerability")
#with open(DefaultFilePath + "\\" + ScanId + "\\" + "Vulnerabilities.pdf", 'wb') as f:  
#    f.write(r.content)
#f.close()


###########################
##  Upload FPR to SSC   ###
###########################
os.system("fortifyclient -url " + SSCUrl + " -authtoken " + SSCAuthToken + " uploadFPR " + "-f \"" + DefaultFilePath  + "\\" + ScanId + "\\" + "Vulnerabilities.fpr\"" + " -applicationVersionID " + ApplicationVersionID)



