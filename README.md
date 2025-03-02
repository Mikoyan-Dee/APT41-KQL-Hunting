# APT41-KQL-Hunting
This repository contains KQL (Kusto Query Language) threat hunting rules designed to detect APT41 campaign artifacts based on historical TTPs (Tactics, Techniques, and Procedures).

## This is Not a Test campaign/the ColunmTK campaign/MoonBounce Malware
Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder - T1547.001
```
DeviceRegistryEvents
| where ActionType == "RegistryValueSet"
| where RegistryKey contains @"\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost"
| where RegistryValueName has_any ("StorSyncSvc", "COMSysConfig", "iscsiwmi")
```
```
DeviceRegistryEvents
| where ActionType == "RegistryValueSet"
| where RegistryKey contains @"\SYSTEM\CurrentControlSet\Services\COMSysConfig\Parameters" or
		RegistryKey contains @"\SYSTEM\CurrentControlSet\Services\StorSyncSvc\Parameters" or	
		RegistryKey contains @"\SYSTEM\CurrentControlSet\Services\iscsiwmi\Parameters"
| where RegistryValueName contains "ServiceDll"
| where RegistryValueData has_any ("storesyncsvc.dll", "SecurityHealthSystray.dll", "System.Mail.Service.dll")

```

## DEADEYE Malware
Scheduled Task/Job: Scheduled Task - T1053.005

```
DeviceProcessEvents
| where ProcessCommandLine has "SCHTASKS" and ProcessCommandLine has "rundll32.exe" and ProcessCommandLine has "SHELL32.DLL" and ProcessCommandLine has "ShellExec_RunDLL" 
| where ProcessCommandLine has_any (
    @"\Microsoft\Windows\PLA\Server Manager Performance Monitor",
    @"\Microsoft\Windows\Ras\ManagerMobility",
    @"\Microsoft\Windows\WDI\SrvSetupResults",
    @"\Microsoft\Windows\WDI\USOShared"
)
| project DeviceName, InitiatingProcessCommandLine, ProcessCommandLine

```

## Winnti Implant
Hijack Execution Flow: Dynamic Linker Hijacking - T1574.006
```
Syslog
| where SyslogMessage contains "/etc/ld.so.preload" and SyslogMessage contains "libsshd.so"

````

## PipeMon Malware
Lateral Tool Transfer - 1570
```
let badPipeNames = pack_array(                         
      '\\CMDPipeRead',                                     
      '\\CMDPipeWrite'                                   
      '\\ComHeatPipeRead',                                    
      '\\FilePipeRead',
      '\\FilePipeWrite',                                      
      '\\InCmdPipeWrite',                                    
      '\\InCmdPipeRead',                                   
      '\\MainHeatPipeRead',
      '\\MainPipeWrite',
      '\\MainPipeRead',                                
      '\\RoutePipeWriite',                                    
      '\\ScreenPipeRead',
      '\\ScreenPipeWrite'                                   
);
DeviceEvents
  | where ActionType == "NamedPipeEvent" 
  | extend ParsedFields=parse_json(AdditionalFields)
  | where ParsedFields.FileOperation == "File created"
  | where ParsedFields.PipeName has_any(badPipeNames)
  | project TimeGenerated, ActionType, DeviceName, InitiatingProcessAccountDomain, InitiatingProcessAccountName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, ParsedFields.FileOperation, ParsedFields.PipeName

```


