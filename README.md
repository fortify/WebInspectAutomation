# WebInspect Automation
Sample Python script for automating dynamic scanning with WebInspect and pushing results to SSC
1. Checks for running scans and queues if an existing scan is running
2. Takes payload.txt file from DefaultFilePath to start scan.  The payload.txt file is a JSON definition that defines the scan
3. Starts scan saving scan ID for generating results
4. Watches for scan to complete
5. Pulls scan as txt, .scan, and .fpr
6. Uploads FPR to SSC

## Requirements
1. WebInspect 18.2+
2. Python 3.7
3. SSC 18.2+
4. Fortifyclient utility 18.2+

## Sample Command
WebInspectAutomation.py 

## File Requirements

## arguments.json
This file contains the necessary parameter for the script.This file needs to be in the same directory as WebInspectAutomation.py
BaseUrl : base url for web inspect
DefaultFilePath : path where the payload file will exist and where results will be created. If empty it defaults to current directory
SSCUrl : url to SSC
SSCAuthToken : fortify token
ApplicationVersionID : fortify application version

## PayloadFile.txt

This file contains the payload for the new scan.
