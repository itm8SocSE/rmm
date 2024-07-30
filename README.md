# Remote Monitoring & Management
Finding Remote Monitoring & Management tools is fairly easy but distigushing between malign and benign activites is quite hard. Creating a baseline with exlusions will however allow for the detection of new activities.

## Executables
This file contains known executable file names for RMM tools and can be used in EDR custom detections. Currently, 236 file names have been identified.

The following can be used in Microsoft Defender to find RMM process creations.
```
let RMMs = (externaldata(Software:string,Executable:string)
[@"https://raw.githubusercontent.com/itm8SocSE/rmm/main/executables.csv"]
with(format="csv",ignoreFirstRecord=true))
| project Executable;
DeviceProcessEvents
| where Timestamp > ago(1h)
| where ActionType == "ProcessCreated"
| where tolower(FileName) in (RMMs)
```
And the following can be used in Microsoft Defender to find RMM file creations.
```
let RMMs = (externaldata(Software:string,Executable:string)
[@"https://raw.githubusercontent.com/itm8SocSE/rmm/main/executables.csv"]
with(format="csv",ignoreFirstRecord=true))
| project Executable;
DeviceFileEvents
| where Timestamp > ago(1h)
| where ActionType == "FileCreated"
| where tolower(FileName) in (RMMs)
```
