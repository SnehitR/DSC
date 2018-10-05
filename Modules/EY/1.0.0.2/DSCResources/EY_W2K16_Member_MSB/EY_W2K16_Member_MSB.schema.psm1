Configuration EY_W2K16_Member_MSB
{
  Import-DSCResource -ModuleName 'xPSDesiredStateConfiguration'
  Import-DSCResource -ModuleName 'AuditPolicyDSC'
  Import-DSCResource -ModuleName 'SecurityPolicyDSC'
  
  xRegistry '3.5 - Local Policy | Turn off Autoplay - Turn off Autoplay on:' {
    Force     = $true
    ValueName = 'NoDriveTypeAutoRun'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    ValueData = 255 # 255=Disable Autorun for all drives
  }

  xRegistry '3.5 - Local Policy | Require user authentication for remote connections by using Network Level Authentication' {
    Force     = $true
    ValueName = 'UserAuthentication'
    ValueType = 'Dword'
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    ValueData = 0 # 0=Disabled
  }

  xRegistry '3.5 - Local Policy | Set client connection encryption level - Encryption Level' {
    Force     = $true
    ValueName = 'MinEncryptionLevel'
    ValueType = 'Dword'
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    ValueData = 3 # 3=High level
  }

  xRegistry '3.5 - Local Policy | Require secure RPC communication' {
    Force     = $true
    ValueName = 'fEncryptRPCTraffic'
    ValueType = 'Dword'
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    ValueData = 1 # 1=Enabled
  }

  xRegistry '3.5 - Local Policy | Always prompt for password upon connection' {
    Force     = $true
    ValueName = 'fPromptForPassword'
    ValueType = 'Dword'
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    ValueData = 1 # 1=Enabled
  }

  xRegistry '3.5 - Local Policy | Allow delegating fresh credentials with NTLM-only server authentication' {
    Force     = $true
    ValueName = 'AllowFreshCredentialsWhenNTLMOnly'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation'
    ValueData = 1 # 1=Enabled
  }

  xRegistry '3.5 - Local Policy | Allow Delegating Fresh Credentials with NTLM-only Server Authentication - Concatenate OS defaults with input above' {
    Force     = $true
    ValueName = 'ConcatenateDefaults_AllowFreshNTLMOnly'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation'
    ValueData = 0 # 0=False
  }

  xRegistry '3.5 - Local Policy | Allow delegating fresh credentials' {
    Force     = $true
    ValueName = 'AllowFreshCredentials'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation'
    ValueData = 1 # 1=Enabled
  }

  xRegistry '3.5 - Local Policy | Allow delegating fresh credentials - Concatenate OS defaults with input above' {
    Force     = $true
    ValueName = 'ConcatenateDefaults_AllowFresh'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation'
    ValueData = 0 # 0=False
  }

  xRegistry '3.5 - Local Policy | Allow delegating fresh credentials - Add servers to the list: - 1' {
    Force     = $true
    ValueName = '1'
    ValueType = 'String'
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentials'
    ValueData = 'WSMAN/*.ey.net'
  }

  xRegistry '3.5 - Local Policy | Allow delegating fresh credentials - Add servers to the list: - 2' {
    Force     = $true
    ValueName = '2'
    ValueType = 'String'
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentials'
    ValueData = 'WSMAN/*.cloudapp.ey.net'
  }

  xRegistry '3.5 - Local Policy | Allow delegating fresh credentials - Add servers to the list: - 3' {
    Force     = $true
    ValueName = '3'
    ValueType = 'String'
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentials'
    ValueData = 'WSMAN/*.eyua.net'
  }
    
  xRegistry '3.5 - Local Policy | Allow delegating fresh credentials - Add servers to the list: - 4' {
    Force     = $true
    ValueName = '4'
    ValueType = 'String'
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentials'
    ValueData = 'WSMAN/*.eyqa.net'
  }

  xRegistry '3.5 - Local Policy | Allow delegating fresh credentials - Add servers to the list: - 5' {
    Force     = $true
    ValueName = '5'
    ValueType = 'String'
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentials'
    ValueData = 'WSMAN/*.eydev.net'
  }
    
  xRegistry '3.5 - Local Policy | Allow delegating fresh credentials - Add servers to the list: - 6' {
    Force     = $true
    ValueName = '6'
    ValueType = 'String'
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentials'
    ValueData = 'WSMAN/*.cloudapp.eydev.net'
  }

  xRegistry '3.5 - Local Policy | Allow delegating fresh credentials - Add servers to the list: - 7' {
    Force     = $true
    ValueName = '7'
    ValueType = 'String'
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentials'
    ValueData = 'WSMAN/*.eydmz.net'
  }

  xRegistry '3.5 - Local Policy | Allow delegating fresh credentials - Add servers to the list: - 8' {
    Force     = $true
    ValueName = '8'
    ValueType = 'String'
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentials'
    ValueData = 'WSMAN/*.eyxstaging.net'
  }
  
  xRegistry '3.5 - Local Policy | Allow delegating fresh credentials - Add servers to the list: - 9' {
    Force     = $true
    ValueName = '9'
    ValueType = 'String'
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentials'
    ValueData = 'TERMSRV/*'
  }

  xRegistry '3.5 - Local Policy | Allow Delegating Fresh Credentials with NTLM-only Server Authentication - Add servers to the list: - 1' {
    Force     = $true
    ValueName = '1'
    ValueType = 'String'
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentialsWhenNTLMOnly'
    ValueData = 'WSMAN/*.ey.net'
  }

  xRegistry '3.5 - Local Policy | Allow Delegating Fresh Credentials with NTLM-only Server Authentication - Add servers to the list: - 2' {
    Force     = $true
    ValueName = '2'
    ValueType = 'String'
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentialsWhenNTLMOnly'
    ValueData = 'WSMAN/*.clouadpp.ey.net'
  }

  xRegistry '3.5 - Local Policy | Allow Delegating Fresh Credentials with NTLM-only Server Authentication - Add servers to the list: - 3' {
    Force     = $true
    ValueName = '3'
    ValueType = 'String'
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentialsWhenNTLMOnly'
    ValueData = 'WSMAN/*.eyua.net'
  }

  xRegistry '3.5 - Local Policy | Allow Delegating Fresh Credentials with NTLM-only Server Authentication - Add servers to the list: - 4' {
    Force     = $true
    ValueName = '4'
    ValueType = 'String'
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentialsWhenNTLMOnly'
    ValueData = 'WSMAN/*.eyqa.net'
  }
    
  xRegistry '3.5 - Local Policy | Allow Delegating Fresh Credentials with NTLM-only Server Authentication - Add servers to the list: - 5' {
    Force     = $true
    ValueName = '5'
    ValueType = 'String'
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentialsWhenNTLMOnly'
    ValueData = 'WSMAN/*.eydev.net'
  }

  xRegistry '3.5 - Local Policy | Allow Delegating Fresh Credentials with NTLM-only Server Authentication - Add servers to the list: - 6' {
    Force     = $true
    ValueName = '6'
    ValueType = 'String'
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentialsWhenNTLMOnly'
    ValueData = 'WSMAN/*.cloudapp.eydev.net'
  }

  xRegistry '3.5 - Local Policy | Allow Delegating Fresh Credentials with NTLM-only Server Authentication - Add servers to the list: - 7' {
    Force     = $true
    ValueName = '7'
    ValueType = 'String'
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentialsWhenNTLMOnly'
    ValueData = 'WSMAN/*.eydmz.net'
  }

  xRegistry '3.5 - Local Policy | Allow Delegating Fresh Credentials with NTLM-only Server Authentication - Add servers to the list: - 8' {
    Force     = $true
    ValueName = '8'
    ValueType = 'String'
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentialsWhenNTLMOnly'
    ValueData = 'WSMAN/*.eyxstaging.net'
  }

  xRegistry '3.5 - Local Policy | Allow Delegating Fresh Credentials with NTLM-only Server Authentication - Add servers to the list: - 9' {
    Force     = $true
    ValueName = '9'
    ValueType = 'String'
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentialsWhenNTLMOnly'
    ValueData = 'TERMSRV/*'
  }

  xRegistry '3.5 - Local Policy | Turn off encryption support - Secure Protocol combinations' {
    Force     = $true
    ValueName = 'SecureProtocols'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
    ValueData = 2560 # 2688=Use TLS 1.1, and TLS 1.2
  }

  xRegistry '3.5 - Local Policy | Application - Maximum Log Size (KB)' {
    Force     = $true
    ValueName = 'MaxSize'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\Application'
    ValueData = 32768 # 32768=32 MB
  }

  xRegistry '3.5 - Local Policy | Application - Retain old events' {
    Force     = $true
    ValueName = 'Retention'
    ValueType = 'String'
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\Application'
    ValueData = '0' # 0=Disabled
  }

  xRegistry '3.5 - Local Policy | Security - Maximum Log Size (KB)' {
    Force     = $true
    ValueName = 'MaxSize'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security'
    ValueData = 393216 # 393216=384 MB
  }
    
  xRegistry '3.5 - Local Policy | Security - Retain old events' {
    Force     = $true
    ValueName = 'Retention'
    ValueType = 'String'
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security'
    ValueData = '0' # 0=Disabled
  }

  xRegistry '3.5 - Local Policy | System - Maximum Log Size (KB)' {
    Force     = $true
    ValueName = 'MaxSize'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\System'
    ValueData = 32768 # 32768=32 MB
  }

  xRegistry '3.5 - Local Policy | System - Retain old events' {
    Force     = $true
    ValueName = 'Retention'
    ValueType = 'String'
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\System'
    ValueData = '0' # 0=Disabled
  }

  xRegistry '3.5 - Local Policy | Turn off heap termination on corruption' {
    Force     = $true
    ValueName = 'NoHeapTerminationOnCorruption'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\Explorer'
    ValueData = 0 # 0=Disabled
  }

  xRegistry '3.5 - Local Policy | Turn off Data Execution Prevention for Explorer' {
    Force     = $true
    ValueName = 'NoDataExecutionPrevention'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\Explorer'
    ValueData = 0 # 0=Disabled
  }

  xRegistry '3.5 - Local Policy | Configure registry policy processing - Do not apply during periodic background processing' {
    Force     = $true
    ValueName = 'NoBackgroundPolicy'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
    ValueData = 0 # 0=False
  }

  xRegistry '3.5 - Local Policy | Configure registry policy processing - Process even if the Group Policy objects have not changed' {
    Force     = $true
    ValueName = 'NoGPOListChanges'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
    ValueData = 0 # 0=True
  }

  xRegistry '3.5 - Local Policy | Allow user control over installs' {
    Force     = $true
    ValueName = 'EnableUserControl'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\Installer'
    ValueData = 0 # 0=Disabled
  }

  xRegistry '3.5 - Local Policy | Always install with elevated privileges' {
    Force     = $true
    ValueName = 'AlwaysInstallElevated'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\Installer'
    ValueData = 0 # 0=Disabled
  }

  xRegistry '3.5 - Local Policy | Turn on Script Execution - Execution Policy ' {
    Force     = $true
    ValueName = 'ExecutionPolicy'
    ValueType = 'String'
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell'
    ValueData = 'RemoteSigned' # RemoteSigned=Allow local scripts and remote signed scripts
  }

  xRegistry '3.5 - Local Policy | Turn on Script ExecutionTurn on Script Execution' {
    Force     = $true
    ValueName = 'EnableScripts'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell'
    ValueData = 1 # 1=Enabled
  }

  xRegistry '3.5 - Local Policy | Configure Windows Defender SmartScreen - Pick one of the following settings' {
    Force     = $true
    ValueName = 'EnableSmartScreen'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\System'
    ValueData = 2 # 2=Require approval from an administrator before running downloaded unknown software.

  }

  xRegistry '3.5 - Local Policy | Enumerate local users on domain-joined computers' {
    Force     = $true
    ValueName = 'EnumerateLocalUsers'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\System'
    ValueData = 0 # 0=Disabled

  }

  xRegistry '3.5 - Local Policy | Allow indexing of encrypted files' {
    Force     = $true
    ValueName = 'AllowIndexingEncryptedStoresOrItems'
    ValueType = 'Dword'
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
    ValueData = 0 # 0=Disabled
  }

  xRegistry '3.5 - Local Policy | Turn On Compatibility HTTP Listener' {
    Force     = $true
    ValueName = 'HttpCompatibilityListener'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service'
    ValueData = 0 # 0=Disabled
  }

  xRegistry '3.5 - Local Policy | Turn On Compatibility HTTPS Listener' {
    Force     = $true
    ValueName = 'HttpsCompatibilityListener'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service'
    ValueData = 0 # 0=Disabled
  }

  xRegistry '3.5 - Local Policy | Disallow Kerberos authentication' {
    Force     = $true
    ValueName = 'AllowKerberos'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service'
    ValueData = 1 # 1=Disabled
  }

  xRegistry '3.5 - Local Policy | Specify channel binding token hardening level' {
    Force     = $true
    ValueName = 'CBTHardeningLevelStatus'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service'
    ValueData = 1 # 1=Enabled
  }

  xRegistry '3.5 - Local Policy | Disallow Negotiate authentication' {
    Force     = $true
    ValueName = 'AllowNegotiate'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service'
    ValueData = 1 # 1=Disabled
  }

  xRegistry '3.5 - Local Policy | Allow Basic authentication' {
    Force     = $true
    ValueName = 'AllowBasic'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service'
    ValueData = 0 # 0=Disabled
  }

  xRegistry '3.5 - Local Policy | Specify channel binding token hardening level - Hardening Level:' {
    Force     = $true
    ValueName = 'CbtHardeningLevel'
    ValueType = 'String'
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service'
    ValueData = 'Strict' # Strict=Strict
  }

  xRegistry '3.5 - Local Policy | Allow remote server management through WinRM' {
    Force     = $true
    ValueName = 'AllowAutoConfig'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service'
    ValueData = 1 # 1=Enabled
  }

  xRegistry '3.5 - Local Policy | Allow remote server management through WinRM - IPv6 filter:' {
    Force     = $true
    ValueName = 'IPv6Filter'
    ValueType = 'String'
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service'
    ValueData = '*' # *=*
  }

  xRegistry '3.5 - Local Policy | Allow remote server management through WinRM - IPv4 filter:' {
    Force     = $true
    ValueName = 'IPv4Filter'
    ValueType = 'String'
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service'
    ValueData = '*' # *=*
  }

  xRegistry '3.5 - Local Policy | Allow unencrypted traffic' {
    Force     = $true
    ValueName = 'AllowUnencryptedTraffic'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service'
    ValueData = 0 # 0=Disabled
  }

  xRegistry '3.5 - Local Policy | Disallow WinRM from storing RunAs credentials' {
    Force     = $true
    ValueName = 'DisableRunAs'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service'
    ValueData = 1 # 1=Enabled
  }

  xRegistry '3.5 - Local Policy | Allow CredSSP authentication' {
    Force     = $true
    ValueName = 'AllowCredSSP'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service'
    ValueData = 0 # 0=Disabled
  }

  xRegistry '3.3 - Windows Firewall | Disable Domain Profile' {
    Force     = $true
    # Could also appear as 'Windows Firewall: Protect all network connections'
    ValueName = 'EnableFirewall'
    ValueType = 'Dword'
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
    ValueData = 0 # 0=Off
  }

  xRegistry '3.3 - Windows Firewall | Disable Standard Profile' {
    Force     = $true
    ValueName = 'EnableFirewall'
    ValueType = 'Dword'
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile'
    ValueData = 0 # 0=Off
  }

  xRegistry '3.5 - Local Policy | Windows Firewall: Private: Firewall state' {
    Force     = $true
    ValueName = 'EnableFirewall'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
    ValueData = 0 # 0=Off
  }

  xRegistry '3.5 - Local Policy | Windows Firewall: Public: Apply local firewall rules' {
    Force     = $true
    ValueName = 'AllowLocalPolicyMerge'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
    ValueData = 0 # 0=NO
  }

  xRegistry '3.5 - Local Policy | Windows Firewall: Public: Display a notification' {
    Force     = $true
    ValueName = 'DisableNotifications'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
    ValueData = 1 # 1=No
  }

  xRegistry '3.5 - Local Policy | Windows Firewall: Public: Firewall state' {
    Force     = $true
    ValueName = 'EnableFirewall'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
    ValueData = 0 # 0=Off
  }

  xRegistry '3.5 - Local Policy | Windows Firewall: Public: Apply local connection security rules' {
    Force     = $true
    ValueName = 'AllowLocalIPsecPolicyMerge'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
    ValueData = 0 # 0=No
  }

  xRegistry '3.5 - Local Policy | Enable NTFS pagefile encryption' {
    Force     = $true
    ValueName = 'NtfsEncryptPagingFile'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Policies'
    ValueData = 1 # 1=Enabled
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Object Access: Removable Storage (Success)' {
    Name      = 'Removable Storage'
    Ensure    = 'Absent' # Absent=Not auditing
    AuditFlag = 'Success'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Object Access: Removable Storage (Failure)' {
    Name      = 'Removable Storage'
    Ensure    = 'Absent' # Absent=Not auditing
    AuditFlag = 'Failure'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Object Access: Kernel Object (Success)' {
    Name      = 'Kernel Object'
    Ensure    = 'Absent' # Absent=Not auditing
    AuditFlag = 'Success'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Object Access: Kernel Object (Failure)' {
    Name      = 'Kernel Object'
    Ensure    = 'Absent' # Absent=Not auditing
    AuditFlag = 'Failure'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Object Access: Application Generated (Success)' {
    Name      = 'Application Generated'
    Ensure    = 'Absent' # Absent=Not auditing
    AuditFlag = 'Success'

  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Object Access: Application Generated (Failure)' {
    Name      = 'Application Generated'
    Ensure    = 'Absent' # Absent=Not auditing
    AuditFlag = 'Failure'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Object Access: File System (Success)' {
    Name      = 'File System'
    Ensure    = 'Present' # Present=Auditing
    AuditFlag = 'Success'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Object Access: File System (Failure)' {
    Name      = 'File System'
    Ensure    = 'Present' # Present=Auditing
    AuditFlag = 'Failure'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Other Object Access Events (Success)' {
    Name      = 'Other Object Access Events'
    Ensure    = 'Present' # Present=Auditing
    AuditFlag = 'Success'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Other Object Access Events (Failure)' {
    Name      = 'Other Object Access Events'
    Ensure    = 'Present' # Present=Auditing
    AuditFlag = 'Failure'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Object Access: Central Access Policy Staging (Success)' {
    Name      = 'Central Policy Staging'
    Ensure    = 'Absent' # Absent=Not auditing
    AuditFlag = 'Success'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Object Access: Central Access Policy Staging (Failure)' {
    Name      = 'Central Policy Staging'
    Ensure    = 'Absent' # Absent=Not auditing
    AuditFlag = 'Failure'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Object Access: Handle Manipulation (Success)' {
    Name      = 'Handle Manipulation'
    Ensure    = 'Absent' # Absent=Not auditing
    AuditFlag = 'Success'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Object Access: Handle Manipulation (Failure)' {
    Name      = 'Handle Manipulation'
    Ensure    = 'Absent' # Absent=Not auditing
    AuditFlag = 'Failure'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Object Access: Filtering Platform Packet Drop (Success)' {
    Name      = 'Filtering Platform Packet Drop'
    Ensure    = 'Absent' # Absent=Not auditing
    AuditFlag = 'Success'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Object Access: Filtering Platform Packet Drop (Failure)' {
    Name      = 'Filtering Platform Packet Drop'
    Ensure    = 'Absent' # Absent=Not auditing
    AuditFlag = 'Failure'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Object Access: Registry (Success)' {
    Name      = 'Registry'
    Ensure    = 'Absent' # Absent=Not auditing
    AuditFlag = 'Success'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Object Access: Registry (Failure)' {
    Name      = 'Registry'
    Ensure    = 'Absent' # Absent=Not auditing
    AuditFlag = 'Failure'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Object Access: Filtering Platform Connection (Success)' {
    Name      = 'Filtering Platform Connection'
    Ensure    = 'Absent' # Absent=Not auditing
    AuditFlag = 'Success'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Object Access: Filtering Platform Connection (Failure)' {
    Name      = 'Filtering Platform Connection'
    Ensure    = 'Absent' # Absent=Not auditing
    AuditFlag = 'Failure'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Object Access: Certification Services (Success)' {
    Name      = 'Certification Services'
    Ensure    = 'Present' # Present=Auditing
    AuditFlag = 'Success'

  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Object Access: Certification Services (Failure)' {
    Name      = 'Certification Services'
    Ensure    = 'Present' # Present=Auditing
    AuditFlag = 'Failure'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Object Access: Detailed File Share (Success)' {
    Name      = 'Detailed File Share'
    Ensure    = 'Absent' # Absent=Not auditing
    AuditFlag = 'Success'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Object Access: Detailed File Share (Failure)' {
    Name      = 'Detailed File Share'
    Ensure    = 'Absent' # Absent=Not auditing
    AuditFlag = 'Failure'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Object Access: SAM (Success)' {
    Name      = 'SAM'
    Ensure    = 'Absent' # Absent=Not auditing
    AuditFlag = 'Success'

  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Object Access: SAM (Failure)' {
    Name      = 'SAM'
    Ensure    = 'Absent' # Absent=Not auditing
    AuditFlag = 'Failure'

  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Object Access: File Share (Success)' {
    Name      = 'File Share'
    Ensure    = 'Present' # Present=Auditing
    AuditFlag = 'Success'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Object Access: File Share (Failure)' {
    Name      = 'File Share'
    Ensure    = 'Present' # Present=Auditing
    AuditFlag = 'Failure'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Logon-Logoff: Special Logon (Success)' {
    Name      = 'Special Logon'
    Ensure    = 'Present' # Present=Auditing
    AuditFlag = 'Success'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Logon-Logoff: Logoff (Success)' {
    Name      = 'Logoff'
    Ensure    = 'Present' # Present=Auditing
    AuditFlag = 'Success'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Logon-Logoff: Network Policy Server (Success)' {
    Name      = 'Network Policy Server'
    Ensure    = 'Absent' # Absent=Not auditing
    AuditFlag = 'Success'

  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Logon-Logoff: Network Policy Server (Failure)' {
    Name      = 'Network Policy Server'
    Ensure    = 'Absent' # Absent=Not auditing
    AuditFlag = 'Failure'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Logon-Logoff: IPsec Quick Mode (Success)' {
    Name      = 'IPsec Quick Mode'
    Ensure    = 'Absent' # Absent=Not auditing
    AuditFlag = 'Success'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Logon-Logoff: IPsec Quick Mode (Failure)' {
    Name      = 'IPsec Quick Mode'
    Ensure    = 'Absent' # Absent=Not auditing
    AuditFlag = 'Failure'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Logon-Logoff: Logon (Success)' {
    Name      = 'Logon'
    Ensure    = 'Present' # Present=Auditing
    AuditFlag = 'Success'

  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Logon-Logoff: Logon (Failure)' {
    Name      = 'Logon'
    Ensure    = 'Present' # Present=Auditing
    AuditFlag = 'Failure'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Logon-Logoff: Account Lockout (Success)' {
    Name      = 'Account Lockout'
    Ensure    = 'Present' # Present=Auditing
    AuditFlag = 'Success'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Logon-Logoff: Account Lockout (Failure)' {
    Name      = 'Account Lockout'
    Ensure    = 'Present' # Present=Auditing
    AuditFlag = 'Failure'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Logon-Logoff: IPsec Main Mode (Success)' {
    Name      = 'IPsec Main Mode'
    Ensure    = 'Absent' # Absent=Not auditing
    AuditFlag = 'Success'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Logon-Logoff: IPsec Main Mode (Failure)' {
    Name      = 'IPsec Main Mode'
    Ensure    = 'Absent' # Absent=Not auditing
    AuditFlag = 'Failure'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Logon-Logoff: Other Logon/Logoff Events (Success)' {
    Name      = 'Other Logon/Logoff Events'
    Ensure    = 'Absent' # Absent=Not auditing
    AuditFlag = 'Success'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Logon-Logoff: Other Logon/Logoff Events (Failure)' {
    Name      = 'Other Logon/Logoff Events'
    Ensure    = 'Absent' # Absent=Not auditing
    AuditFlag = 'Failure'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Logon-Logoff: IPsec Extended Mode (Success)' {
    Name      = 'IPsec Extended Mode'
    Ensure    = 'Absent' # Absent=Not auditing
    AuditFlag = 'Success'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Logon-Logoff: IPsec Extended Mode (Failure)' {
    Name      = 'IPsec Extended Mode'
    Ensure    = 'Absent' # Absent=Not auditing
    AuditFlag = 'Failure'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Account Management: Application Group Management (Success)' {
    Name      = 'Application Group Management'
    Ensure    = 'Present' # Present=Auditing
    AuditFlag = 'Success'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Account Management: Application Group Management (Failure)' {
    Name      = 'Application Group Management'
    Ensure    = 'Present' # Present=Auditing
    AuditFlag = 'Failure'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Account Management: Computer Account Management (Success)' {
    Name      = 'Computer Account Management'
    Ensure    = 'Present' # Present=Auditing
    AuditFlag = 'Success'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Account Management: Computer Account Management (Failure)' {
    Name      = 'Computer Account Management'
    Ensure    = 'Present' # Present=Auditing
    AuditFlag = 'Failure'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Account Management: Security Group Management (Success)' {
    Name      = 'Security Group Management'
    Ensure    = 'Present' # Present=Auditing
    AuditFlag = 'Success'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Account Management: Security Group Management (Failure)' {
    Name      = 'Security Group Management'
    Ensure    = 'Present' # Present=Auditing
    AuditFlag = 'Failure'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Account Management: Distribution Group Management (Success)' {
    Name      = 'Distribution Group Management'
    Ensure    = 'Present' # Present=Auditing
    AuditFlag = 'Success'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Account Management: Distribution Group Management (Failure)' {
    Name      = 'Distribution Group Management'
    Ensure    = 'Present' # Present=Auditing
    AuditFlag = 'Failure'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Account Management: Other Account Management Events (Success)' {
    Name      = 'Other Account Management Events'
    Ensure    = 'Present' # Present=Auditing
    AuditFlag = 'Success'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Account Management: Other Account Management Events (Failure)' {
    Name      = 'Other Account Management Events'
    Ensure    = 'Present' # Present=Auditing
    AuditFlag = 'Failure'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Account Management: User Account Management (Success)' {
    Name      = 'User Account Management'
    Ensure    = 'Present' # Present=Auditing
    AuditFlag = 'Success'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Account Management: User Account Management (Failure)' {
    Name      = 'User Account Management'
    Ensure    = 'Present' # Present=Auditing
    AuditFlag = 'Failure'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: DS Access: Directory Service Replication (Success)' {
    Name      = 'Directory Service Replication'
    Ensure    = 'Absent' # Absent=Not auditing
    AuditFlag = 'Success'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: DS Access: Directory Service Replication (Failure)' {
    Name      = 'Directory Service Replication'
    Ensure    = 'Absent' # Absent=Not auditing
    AuditFlag = 'Failure'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: DS Access: Detailed Directory Service Replication (Success)' {
    Name      = 'Detailed Directory Service Replication'
    Ensure    = 'Absent' # Absent=Not auditing
    AuditFlag = 'Success'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: DS Access: Detailed Directory Service Replication (Failure)' {
    Name      = 'Detailed Directory Service Replication'
    Ensure    = 'Absent' # Absent=Not auditing
    AuditFlag = 'Failure'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: DS Access: Directory Service Changes (Success)' {
    Name      = 'Directory Service Changes'
    Ensure    = 'Absent' # Absent=Not auditing
    AuditFlag = 'Success'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: DS Access: Directory Service Changes (Failure)' {
    Name      = 'Directory Service Changes'
    Ensure    = 'Absent' # Absent=Not auditing
    AuditFlag = 'Failure'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: DS Access: Directory Service Access (Success)' {
    Name      = 'Directory Service Access'
    Ensure    = 'Absent' # Absent=Not auditing
    AuditFlag = 'Success'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: DS Access: Directory Service Access (Failure)' {
    Name      = 'Directory Service Access'
    Ensure    = 'Absent' # Absent=Not auditing
    AuditFlag = 'Failure'

  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Policy Change: Other Policy Change Events (Success)' {
    Name      = 'Other Policy Change Events'
    Ensure    = 'Present' # Present=Auditing
    AuditFlag = 'Success'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Policy Change: Other Policy Change Events (Failure)' {
    Name      = 'Other Policy Change Events'
    Ensure    = 'Present' # Present=Auditing
    AuditFlag = 'Failure'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Policy Change: Filtering Platform Policy Change (Success)' {
    Name      = 'Filtering Platform Policy Change'
    Ensure    = 'Absent' # Absent=Not auditing
    AuditFlag = 'Success'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Policy Change: Filtering Platform Policy Change (Failure)' {
    Name      = 'Filtering Platform Policy Change'
    Ensure    = 'Absent' # Absent=Not auditing
    AuditFlag = 'Failure'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Policy Change: Authentication Policy Change (Success)' {
    Name      = 'Authentication Policy Change'
    Ensure    = 'Present' # Present=Auditing
    AuditFlag = 'Success'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Policy Change: Authentication Policy Change (Failure)' {
    Name      = 'Authentication Policy Change'
    Ensure    = 'Present' # Present=Auditing
    AuditFlag = 'Failure'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Policy Change: Audit Policy Change (Success)' {
    Name      = 'Audit Policy Change'
    Ensure    = 'Present' # Present=Auditing
    AuditFlag = 'Success'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Policy Change: Audit Policy Change (Failure)' {
    Name      = 'Audit Policy Change'
    Ensure    = 'Present' # Present=Auditing
    AuditFlag = 'Failure'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Policy Change: Authorization Policy Change (Success)' {
    Name      = 'Authorization Policy Change'
    Ensure    = 'Present' # Present=Auditing
    AuditFlag = 'Success'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Policy Change: Authorization Policy Change (Failure)' {
    Name      = 'Authorization Policy Change'
    Ensure    = 'Present' # Present=Auditing
    AuditFlag = 'Failure'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Policy Change: MPSSVC Rule-Level Policy Change (Success)' {
    Name      = 'MPSSVC Rule-Level Policy Change'
    Ensure    = 'Absent' # Absent=Not auditing
    AuditFlag = 'Success'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Policy Change: MPSSVC Rule-Level Policy Change (Failure)' {
    Name      = 'MPSSVC Rule-Level Policy Change'
    Ensure    = 'Absent' # Absent=Not auditing
    AuditFlag = 'Failure'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Privilege Use: Non Sensitive Privilege Use (Success)' {
    Name      = 'Non Sensitive Privilege Use'
    Ensure    = 'Absent' # Absent=Not auditing
    AuditFlag = 'Success'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Privilege Use: Non Sensitive Privilege Use (Failure)' {
    Name      = 'Non Sensitive Privilege Use'
    Ensure    = 'Absent' # Absent=Not auditing
    AuditFlag = 'Failure'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Privilege Use: Sensitive Privilege Use (Success)' {
    Name      = 'Sensitive Privilege Use'
    Ensure    = 'Present' # Present=Auditing
    AuditFlag = 'Success'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Privilege Use: Sensitive Privilege Use (Failure)' {
    Name      = 'Sensitive Privilege Use'
    Ensure    = 'Present' # Present=Auditing
    AuditFlag = 'Failure'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Privilege Use: Other Privilege Use Events (Success)' {
    Name      = 'Other Privilege Use Events'
    Ensure    = 'Absent' # Absent=Not auditing
    AuditFlag = 'Success'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Privilege Use: Other Privilege Use Events (Failure)' {
    Name      = 'Other Privilege Use Events'
    Ensure    = 'Absent' # Absent=Not auditing
    AuditFlag = 'Failure'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Detailed Tracking: Process Creation (Success)' {
    Name      = 'Process Creation'
    Ensure    = 'Present' # Present=Auditing
    AuditFlag = 'Success'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Detailed Tracking: Process Termination (Success)' {
    Name      = 'Process Termination'
    Ensure    = 'Absent' # Absent=Not auditing
    AuditFlag = 'Success'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Detailed Tracking: Process Termination (Failure)' {
    Name      = 'Process Termination'
    Ensure    = 'Absent' # Absent=Not auditing
    AuditFlag = 'Failure'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Detailed Tracking: DPAPI Activity (Success)' {
    Name      = 'DPAPI Activity'
    Ensure    = 'Absent' # Absent=Not auditing
    AuditFlag = 'Success'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Detailed Tracking: DPAPI Activity (Failure)' {
    Name      = 'DPAPI Activity'
    Ensure    = 'Absent' # Absent=Not auditing
    AuditFlag = 'Failure'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Detailed Tracking: RPC Events (Success)' {
    Name      = 'RPC Events'
    Ensure    = 'Absent' # Absent=Not auditing
    AuditFlag = 'Success'

  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Detailed Tracking: RPC Events (Failure)' {
    Name      = 'RPC Events'
    Ensure    = 'Absent' # Absent=Not auditing
    AuditFlag = 'Failure'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: System: System Integrity (Success)' {
    Name      = 'System Integrity'
    Ensure    = 'Present' # Present=Auditing
    AuditFlag = 'Success'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: System: System Integrity (Failure)' {
    Name      = 'System Integrity'
    Ensure    = 'Present' # Present=Auditing
    AuditFlag = 'Failure'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: System: Security System Extension (Success)' {
    Name      = 'Security System Extension'
    Ensure    = 'Present' # Present=Auditing
    AuditFlag = 'Success'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: System: Security System Extension (Failure)' {
    Name      = 'Security System Extension'
    Ensure    = 'Present' # Present=Auditing
    AuditFlag = 'Failure'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: System: Security State Change (Success)' {
    Name      = 'Security State Change'
    Ensure    = 'Present' # Present=Auditing
    AuditFlag = 'Success'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: System: Security State Change (Failure)' {
    Name      = 'Security State Change'
    Ensure    = 'Present' # Present=Auditing
    AuditFlag = 'Failure'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Account Logon: Credential Validation (Success)' {
    Name      = 'Credential Validation'
    Ensure    = 'Present' # Present=Auditing
    AuditFlag = 'Success'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Account Logon: Credential Validation (Failure)' {
    Name      = 'Credential Validation'
    Ensure    = 'Present' # Present=Auditing
    AuditFlag = 'Failure'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Account Logon: Kerberos Authentication Service (Success)' {
    Name      = 'Kerberos Authentication Service'
    Ensure    = 'Absent' # Absent=Not auditing
    AuditFlag = 'Success'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Account Logon: Kerberos Authentication Service (Failure)' {
    Name      = 'Kerberos Authentication Service'
    Ensure    = 'Absent' # Absent=Not auditing
    AuditFlag = 'Failure'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Account Logon: Kerberos Service Ticket Operations (Success)' {
    Name      = 'Kerberos Service Ticket Operations'
    Ensure    = 'Absent' # Absent=Not auditing
    AuditFlag = 'Success'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Account Logon: Kerberos Service Ticket Operations (Failure)' {
    Name      = 'Kerberos Service Ticket Operations'
    Ensure    = 'Absent' # Absent=Not auditing
    AuditFlag = 'Failure'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Account Logon: Other Account Logon Events (Success)' {
    Name      = 'Other Account Logon Events'
    Ensure    = 'Present' # Present=Auditing
    AuditFlag = 'Success'
  }

  AuditPolicySubcategory '3.5 - Local Policy | Audit Policy: Account Logon: Other Account Logon Events (Failure)' {
    Name      = 'Other Account Logon Events'
    Ensure    = 'Present' # Present=Auditing
    AuditFlag = 'Failure'
  }

  xServiceSet '3.5 - Local Policy | Manual Services' {
    Name = @('BITS','IKEEXT','TrkWks')
    StartupType = 'Manual'
  }

  xServiceSet '3.5 - Local Policy | Disabled Services' {
    Name = @('Themes','SharedAccess')
    StartupType = 'Disabled'
    State = 'Stopped'
  }

  xServiceSet '3.5 - Local Policy | Automatic Services' {
    Name = @('TermService','lmhosts')
    StartupType = 'Automatic'
  }
  
  xRegistry '3.5 - Local Policy | Interactive logon: Smart card removal behavior' {
    Force     = $true
    ValueName = 'ScRemoveOption'
    ValueType = 'String'
    Key       = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
    ValueData = '2' #2=force logoff
  }

  xRegistry '3.5 - Local Policy | Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' {
    Force     = $true
    ValueName = 'SCENoApplyLegacyAuditPolicy'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Control\Lsa'
    ValueData = 1 # 1=Enabled
  }

  xRegistry '3.5 - Local Policy | MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds' {
    Force     = $true
    ValueName = 'KeepAliveTime'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters'
    ValueData = 300000 # 300000=5'
  }

  xRegistry '3.5 - Local Policy | MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)' {
    Force     = $true
    ValueName = 'SafeDllSearchMode'
    ValueType = 'Dword'
    Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
    ValueData = 1 # 1=Enabled
  }

  xRegistry '3.5 - Local Policy | Interactive logon: Machine inactivity limit' {
    Force     = $true
    ValueName = 'InactivityTimeoutSecs'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
    ValueData = 900 # 900=15'
  }

  xRegistry '3.5 - Local Policy | Microsoft network client: Digitally sign communications (always)' {
    Force     = $true
    ValueName = 'RequireSecuritySignature'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters'
    ValueData = 1 # 1 = 'Enabled'
  }

  xRegistry '3.5 - Local Policy | Network access: Remotely accessible registry paths and sub-paths' {
    Force     = $true
    ValueName = 'Machine'
    ValueType = 'MultiString'
    Key       = 'HKLM:\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths'
    ValueData = @('System\CurrentControlSet\Control\Print\Printers System\CurrentControlSet\Services\Eventlog Software\Microsoft\OLAP Server Software\Microsoft\Windows NT\CurrentVersion\Print Software\Microsoft\Windows NT\CurrentVersion\Windows System\CurrentControlSet\Control\ContentIndex System\CurrentControlSet\Control\Terminal Server System\CurrentControlSet\Control\Terminal Server\UserConfig System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration Software\Microsoft\Windows NT\CurrentVersion\Perflib System\CurrentControlSet\Services\SysmonLog'
    )
  }

  xRegistry '3.5 - Local Policy | Microsoft network client: Digitally sign communications (if server agrees)' {
    Force     = $true
    ValueName = 'EnableSecuritySignature'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters'
    ValueData = 1 # 1=Enabled

  }

  xRegistry '3.5 - Local Policy | User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop' {
    Force     = $true
    ValueName = 'EnableUIADesktopToggle'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
    ValueData = 0 # 0=Disabled
  }

  xRegistry '3.5 - Local Policy | Domain member: Require strong (Windows 2000 or later) session key' {
    Force     = $true
    ValueName = 'requirestrongkey'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters'
    ValueData = 1 # 1=Enabled

  }

  xRegistry '3.5 - Local Policy | MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted' {
    Force     = $true
    ValueName = 'TcpMaxDataRetransmissions'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters'
    ValueData = 3
  }

  xRegistry '3.5 - Local Policy | Interactive logon: Message title for users attempting to log on' {
    Force     = $true
    ValueName = 'LegalNoticeCaption'
    ValueType = 'String'
    Key       = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
    ValueData = 'Ernst & Young Logon Disclaimer'
  }

  xRegistry '3.5 - Local Policy | MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes' {
    Force     = $true
    ValueName = 'EnableICMPRedirect'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters'
    ValueData = 0 # 0=Disabled
  }

  xRegistry '3.5 - Local Policy | Network access: Remotely accessible registry paths' {
    Force     = $true
    ValueName = 'Machine'
    ValueType = 'MultiString'
    Key       = 'HKLM:\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths'
    ValueData = @('System\CurrentControlSet\Control\ProductOptions System\CurrentControlSet\Control\Server Applications Software\Microsoft\Windows NT\CurrentVersion'
    )
  }
  
  xRegistry '3.5 - Local Policy | User Account Control: Run all administrators in Admin Approval Mode' {
    Force     = $true
    ValueName = 'EnableLUA'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
    ValueData = 1 # 1=Enabled
  }

  xRegistry '3.5 - Local Policy | MSS: (AutoReboot) Allow Windows to automatically restart after a system crash' {
    Force     = $true
    ValueName = 'AutoReboot'
    ValueType = 'Dword'
    Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl'
    ValueData = 1 # 1=Enabled
  }

  xRegistry '3.5 - Local Policy | Shutdown: Clear virtual memory pagefile' {
    Force     = $true
    ValueName = 'ClearPageFileAtShutdown'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Control\Session Manager\Memory Management'
    ValueData = 0 # 0=Disabled
  }

  xRegistry '3.5 - Local Policy | System settings: Optional subsystems' {
    Force     = $true
    ValueName = 'optional'
    ValueType = 'MultiString'
    Key       = 'HKLM:\System\CurrentControlSet\Control\Session Manager\SubSystems'
    ValueData = ''
  }

  xRegistry '3.5 - Local Policy | Domain member: Digitally sign secure channel data (when possible)' {
    Force     = $true
    ValueName = 'signsecurechannel'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters'
    ValueData = 1 # 1=Enabled

  }

  xRegistry '3.5 - Local Policy | Audit: Shut down system immediately if unable to log security audits' {
    Force     = $true
    ValueName = 'CrashOnAuditFail'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Control\Lsa'
    ValueData = 0 # 0=Disabled
  }

  xRegistry '3.5 - Local Policy | User Account Control: Admin Approval Mode for the Built-in Administrator account' {
    Force     = $true
    ValueName = 'FilterAdministratorToken'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
    ValueData = 1 # 1=Enabled
  }

  xRegistry '3.5 - Local Policy | MSS: (AutoShareServer) Enable Administrative Shares (recommended except for highly secure environments)' {
    Force     = $true
    ValueName = 'AutoShareServer'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters'
    ValueData = 1 # 1=Enabled
  }

  xRegistry '3.5 - Local Policy | User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' {
    Force     = $true
    ValueName = 'ConsentPromptBehaviorAdmin'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
    ValueData = 5 # 5=Prompt for consent for non-Windows binaries
  }

  xRegistry '3.5 - Local Policy | Network security: Allow Local System to use computer identity for NTLM' {
    Force     = $true
    ValueName = 'UseMachineId'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Control\Lsa'
    ValueData = 1 # 1=Enabled
  }

  xRegistry '3.5 - Local Policy | MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted' {
    Force     = $true
    ValueName = 'TcpMaxDataRetransmissions'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters'
    ValueData = 3
  }

  xRegistry '3.5 - Local Policy | Microsoft network server: Digitally sign communications (always)' {
    Force     = $true
    ValueName = 'requiresecuritysignature'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters'
    ValueData = 1 # 1=Enabled
  }

  xRegistry '3.5 - Local Policy | Domain controller: Refuse machine account password changes' {
    Force     = $true
    ValueName = 'RefusePasswordChange'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters'
    ValueData = 0 # 0=Disabled
  }

  xRegistry '3.5 - Local Policy | Network access: Restrict anonymous access to Named Pipes and Shares' {
    Force     = $true
    ValueName = 'RestrictNullSessAccess'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters'
    ValueData = 1 # 1=Enabled
  }

  xRegistry '3.5 - Local Policy | Network access: Let everyone permissions apply to anonymous users' {
    Force     = $true
    ValueName = 'EveryoneIncludesAnonymous'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Control\Lsa'
    ValueData = 0 # 0=Disabled
  }

  xRegistry '3.5 - Local Policy | Interactive logon: Do not require CTRL+ALT+DEL' {
    Force     = $true
    ValueName = 'DisableCAD'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
    ValueData = 0 # 0=Disabled
  }

  xRegistry '3.5 - Local Policy | Network access: Do not allow anonymous enumeration of SAM accounts' {
    Force     = $true
    ValueName = 'RestrictAnonymousSAM'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Control\Lsa'
    ValueData = 1 # 1=Enabled
  }

  xRegistry '3.5 - Local Policy | MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)' {
    Force     = $true
    ValueName = 'DisableIPSourceRouting'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters'
    ValueData = 2 # 2=Highest protection, source routing is completely disabled
  }

  xRegistry '3.5 - Local Policy | Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' {
    Force     = $true
    ValueName = 'NTLMMinServerSec'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0'
    ValueData = 537395200 # 537395200=Require NTLMv2 session security,Require 128-bit encryption
  }

  xRegistry '3.5 - Local Policy | Interactive logon: Do not display last user name' {
    Force     = $true
    ValueName = 'DontDisplayLastUserName'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
    ValueData = 1 # 1=Enabled
  }

  xRegistry '3.5 - Local Policy | MSS:(ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires' {
    Force     = $true
    ValueName = 'ScreenSaverGracePeriod'
    ValueType = 'String'
    Key       = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
    ValueData = '0'
  }

  xRegistry '3.5 - Local Policy | User Account Control: Only elevate UIAccess applications that are installed in secure locations' {
    Force     = $true
    ValueName = 'EnableSecureUIAPaths'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
    ValueData = 1 # 1=Enabled
  }

  xRegistry '3.5 - Local Policy | Microsoft network server: Disconnect clients when logon hours expire' {
    Force     = $true
    ValueName = 'enableforcedlogoff'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters'
    ValueData = 1 # 1=Enabled
  }

  xRegistry '3.5 - Local Policy | Devices: Prevent users from installing printer drivers' {
    Force     = $true
    ValueName = 'AddPrinterDrivers'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers'
    ValueData = 1 # 1=Enabled
  }

  xRegistry '3.5 - Local Policy | Network access: Sharing and security model for local accounts' {
    Force     = $true
    ValueName = 'ForceGuest'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Control\Lsa'
    ValueData = 0 # 0=Classic - local users authenticate as themselves
  }

  xRegistry '3.5 - Local Policy | User Account Control: Detect application installations and prompt for elevation' {
    Force     = $true
    ValueName = 'EnableInstallerDetection'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
    ValueData = 1 # 1=Enabled
  }

  xRegistry '3.5 - Local Policy | Restrict Unauthenticated RPC clients - RPC Runtime Unauthenticated Client Restriction to Apply:' {
    Force     = $true
    ValueName = 'RestrictRemoteClients'
    ValueType = 'Dword'
    Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Rpc'
    ValueData = 2 # 2=Authenticated without exceptions
  }

  xRegistry '3.5 - Local Policy | Domain member: Maximum machine account password age' {
    Force     = $true
    ValueName = 'maximumpasswordage'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters'
    ValueData = 30
  }

  xRegistry '3.5 - Local Policy | MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses (could lead to DoS)' {
    Force     = $true
    ValueName = 'PerformRouterDiscovery'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters'
    ValueData = 0 # 0=Disabled
  }

  xRegistry '3.5 - Local Policy | User Account Control: Only elevate executables that are signed and validated' {
    Force     = $true
    ValueName = 'ValidateAdminCodeSignatures'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
    ValueData = 0 # 0=Disabled
  }

  xRegistry '3.5 - Local Policy | Interactive logon: Machine account lockout threshold' {
    Force     = $true
    ValueName = 'MaxDevicePasswordFailedAttempts'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
    ValueData = 10
  }

  xRegistry '3.5 - Local Policy | Devices: Allowed to format and eject removable media' {
    Force     = $true
    ValueName = 'AllocateDASD'
    ValueType = 'String'
    Key       = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
    ValueData = '0' # 0=Administrators
  }

  xRegistry '3.5 - Local Policy | User Account Control: Virtualize file and registry write failures to per-user locations' {
    Force     = $true
    ValueName = 'EnableVirtualization'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
    ValueData = 1 # 1=Enabled
  }

  xRegistry '3.5 - Local Policy | Domain member: Digitally encrypt secure channel data (when possible)' {
    Force     = $true
    ValueName = 'sealsecurechannel'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters'
    ValueData = 1 # 1=Enabled
  }

  xRegistry '3.5 - Local Policy | Domain member: Disable machine account password changes' {
    Force     = $true
    ValueName = 'disablepasswordchange'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters'
    ValueData = 0 # 0=Disabled
  }

  xRegistry '3.5 - Local Policy | Interactive logon: Require Domain Controller authentication to unlock workstation' {
    Force     = $true
    ValueName = 'ForceUnlockLogon'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
    ValueData = 1 # 1=Enabled
  }

  xRegistry '3.5 - Local Policy | Interactive logon: Message text for users attempting to log on' {
    Force     = $true
    ValueName = 'LegalNoticeText'
    ValueType = 'String'
    Key       = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
    ValueData = 'This computer system (including all hardware software and peripheral equipment) is the property of Ernst & Young. Use of this computer system is restricted to official Ernst & Young business. Ernst & Young reserves the right to monitor use of the computer system at any time. Use of this computer system constitutes consent to such monitoring. Any unauthorized access use or modification of the computer system can result in disciplinary action civil liability or criminal penalties.'
  }

  xRegistry '3.5 - Local Policy | MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)' {
    Force     = $true
    ValueName = 'DisableIPSourceRouting'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters'
    ValueData = 2 # 2=Highest protection, source routing is completely disabled
  }

  xRegistry '3.6 - Security Considerations for Network Attacks and Other Events | MSS: (SynAttackProtect) Syn attack protection level (protects against DoS)' {
    Force     = $true
    ValueName = 'SynAttackProtect'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters'
    ValueData = 1 # 1=Connections time out sooner if a SYN attack is detected
  }
  
  xRegistry '3.6 - Security Considerations for Network Attacks and Other Events | MSS: (TCPMaxConnectResponseRetransmissions) SYN-ACK retransmissions when a connection request is not acknowledged' {
    Force     = $true
    ValueName = 'TcpMaxConnectResponseRetransmissions'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters'
    ValueData = 2 # 2=3 & 6 seconds, half-open connections dropped after 21 seconds
  }

  xRegistry '3.6 - Security Considerations for Network Attacks and Other Events | MSS: (NoDefaultExempt) Configure IPSec exemptions for various types of network traffic' {
    Force     = $true
    ValueName = 'NoDefaultExempt'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Services\IPSEC'
    ValueData = 3 # 3=Only ISAKMP is exempt
  }
  
  xRegistry '3.6 - Security Considerations for Network Attacks and Other Events | MSS: (Hidden) Hide Computer From the Browse List (not recommended except for highly secure environments)' {
    Force     = $true
    ValueName = 'Hidden'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Services\Lanmanserver\Parameters'
    ValueData = 0 # 0=Disabled
  }

  xRegistry '3.6 - Security Considerations for Network Attacks and Other Events | MSS: (NtfsDisable8dot3NameCreation) Enable the computer to stop generating 8.3 style filenames' {
    Force     = $true
    ValueName = 'NtfsDisable8dot3NameCreation'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Control\FileSystem'
    ValueData = 1 # 1=Enabled
  }

  xRegistry '3.5 - Local Policy | Domain controller: LDAP server signing requirements' {
    Force     = $true
    ValueName = 'LDAPServerIntegrity'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Services\NTDS\Parameters'
    ValueData = 2 # 2=Require signing
  }

  xRegistry '3.5 - Local Policy | System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)' {
    Force     = $true
    ValueName = 'ProtectionMode'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Control\Session Manager'
    ValueData = 1 # 1=Enabled
  }

  xRegistry '3.5 - Local Policy | Network security: LAN Manager authentication level' {
    Force     = $true
    ValueName = 'LmCompatibilityLevel'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Control\Lsa'
    ValueData = 5 # 5=Send NTLMv2 response only. Refuse LM & NTLM
  }

  xRegistry '3.5 - Local Policy | Network access: Do not allow storage of passwords and credentials for network authentication' {
    Force     = $true
    ValueName = 'DisableDomainCreds'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Control\Lsa'
    ValueData = 0 # 0=Disabled
  }

  xRegistry '3.5 - Local Policy | Microsoft network client: Send unencrypted password to third-party SMB servers' {
    Force     = $true
    ValueName = 'EnablePlainTextPassword'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters'
    ValueData = 0 # 0=Disabled
  }

  xRegistry '3.5 - Local Policy | Accounts: Limit local account use of blank passwords to console logon only' {
    Force     = $true
    ValueName = 'LimitBlankPasswordUse'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Control\Lsa'
    ValueData = 1 # 1=Enabled
  }

  xRegistry '3.5 - Local Policy | Interactive logon: Number of previous logons to cache (in case domain controller is not available)' {
    Force     = $true
    ValueName = 'CachedLogonsCount'
    ValueType = 'String'
    Key       = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
    ValueData = '4'
  }

  xRegistry '3.5 - Local Policy | System cryptography: Force strong key protection for user keys stored on the computer' {
    Force     = $true
    ValueName = 'ForceKeyProtection'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Policies\Microsoft\Cryptography'
    ValueData = 1 # 1=User is prompted when the key is first used
  }

  xRegistry '3.5 - Local Policy | Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' {
    Force     = $true
    ValueName = 'NTLMMinClientSec'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0'
    ValueData = 537395200 # 537395200=Require NTLMv2 session security,Require 128-bit encryption
  }

  xRegistry '3.5 - Local Policy | User Account Control: Switch to the secure desktop when prompting for elevation' {
    Force     = $true
    ValueName = 'PromptOnSecureDesktop'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
    ValueData = 1 # 1=Enabled
  }

  xRegistry '3.5 - Local Policy | Interactive logon: Prompt user to change password before expiration' {
    Force     = $true
    ValueName = 'PasswordExpiryWarning'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
    ValueData = 14
  }

  xRegistry '3.5 - Local Policy | Devices: Allow Undock Without Having to Log On' {
    Force     = $true
    ValueName = 'UndockWithoutLogon'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
    ValueData = 0 # 0=Disabled
  }

  xRegistry '3.5 - Local Policy | System settings: Use Certificate Rules on Windows Executables for Software Restriction Policies' {
    Force     = $true
    ValueName = 'AuthenticodeEnabled'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers'
    ValueData = 1 # 1=Enabled
  }

  xRegistry '3.5 - Local Policy | Network security: LDAP client signing requirements' {
    Force     = $true
    ValueName = 'LDAPClientIntegrity'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Services\LDAP'
    ValueData = 1 # 1=Negotiate signing
  }

  xRegistry '3.5 - Local Policy | Domain controller: Allow server operators to schedule tasks' {
    Force     = $true
    ValueName = 'SubmitControl'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Control\Lsa'
    ValueData = 0 # 0=Disabled
  }

  xRegistry '3.5 - Local Policy | MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)' {
    Force     = $true
    ValueName = 'AutoAdminLogon'
    ValueType = 'String'
    Key       = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
    ValueData = '0' # 0=Disabled
  }

  xRegistry '3.5 - Local Policy | System cryptography: Use FIPS compliant algorithms for encryption, hashing, and signing' {
    Force     = $true
    ValueName = 'Enabled'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy'
    ValueData = 0 # 0=Disabled
  }

  xRegistry '3.5 - Local Policy | Domain Member: Digitally encrypt or sign secure channel data (always)' {
    Force     = $true
    ValueName = 'requiresignorseal'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters'
    ValueData = 1 # 1=Enabled
  }

  xRegistry '3.5 - Local Policy | Recovery console: Allow floppy copy and access to all drives and all folders' {
    Force     = $true
    ValueName = 'setcommand'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole'
    ValueData = 0 # 0=Disabled
  }

  xRegistry '3.5 - Local Policy | Shutdown: Allow system to be shut down without having to log on' {
    Force     = $true
    ValueName = 'ShutdownWithoutLogon'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
    ValueData = 0 # 0=Disabled
  }

  xRegistry '3.5 - Local Policy | Devices: Restrict CD-ROM access to locally logged-on user only' {
    Force     = $true
    ValueName = 'AllocateCDRoms'
    ValueType = 'String'
    Key       = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
    ValueData = '0' # 0=Disabled
  }

  xRegistry '3.5 - Local Policy | Microsoft network server: Amount of idle time required before suspending session' {
    Force     = $true
    ValueName = 'autodisconnect'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters'
    ValueData = 15
  }

  xRegistry '3.5 - Local Policy | Network security: Do not store LAN Manager hash value on next password change' {
    Force     = $true
    ValueName = 'NoLMHash'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Control\Lsa'
    ValueData = 1 # 1=Enabled
  }

  xRegistry '3.5 - Local Policy | MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning' {
    Force     = $true
    ValueName = 'WarningLevel'
    ValueType = 'Dword'
    Key       = 'HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security'
    ValueData = 80
  }

  xRegistry '3.5 - Local Policy | Recovery console: Allow automatic administrative logon' {
    Force     = $true
    ValueName = 'securitylevel'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole'
    ValueData = 0 # 0=Disabled
  }

  xRegistry '3.6 - Security Considerations for Network Attacks and Other Events | MSS: (EnableDeadGWDetect) Allow automatic detection of dead network gateways (could lead to DoS)' {
    Force     = $true
    ValueName = 'EnableDeadGWDetect'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters'
    ValueData = 0 # 0=Disabled
  }

  xRegistry '3.6 - Security Considerations for Network Attacks and Other Events | MSS: (EnablePMTUDiscovery) Allow automatic detection of MTU size (possible DoS by an attacker using a small MTU)' {
    Force     = $true
    ValueName = 'enablepmtudiscovery'
    ValueType = 'Dword'
    Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
    ValueData = '0' # 0=Disabled
  }

  xRegistry '3.5 - Local Policy | Network access: Do not allow anonymous enumeration of SAM accounts and shares' {
    Force     = $true
    ValueName = 'RestrictAnonymous'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Control\Lsa'
    ValueData = 1 # 1=Enabled
  }

  xRegistry '3.5 - Local Policy | MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers' {
    Force     = $true
    ValueName = 'NoNameReleaseOnDemand'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Services\Netbt\Parameters'
    ValueData = 1 # 1=Enabled
  }

  xRegistry '3.5 - Local Policy | Network security: Allow LocalSystem NULL session fallback' {
    Force     = $true
    ValueName = 'allownullsessionfallback'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0'
    ValueData = 0 # 0=Disabled
  }

  xRegistry '3.5 - Local Policy | Devices: Restrict floppy access to locally logged-on user only' {
    Force     = $true
    ValueName = 'AllocateFloppies'
    ValueType = 'String'
    Key       = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
    ValueData = '0' # 0=Disabled
  }

  xRegistry '3.5 - Local Policy | System objects: Require case insensitivity for non-Windows subsystems' {
    Force     = $true
    ValueName = 'ObCaseInsensitive'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Control\Session Manager\Kernel'
    ValueData = 1 # 1=Enabled
  }

  xRegistry '3.5 - Local Policy | User Account Control: Behavior of the elevation prompt for standard users' {
    Force     = $true
    ValueName = 'ConsentPromptBehaviorUser'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
    ValueData = 3 # 3=Prompt for credentials
  }

  xRegistry '3.5 - Local Policy | Interactive logon: Display user information when the session is locked' {
    Force     = $true
    ValueName = 'DontDisplayLockedUserId'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
    ValueData = 2 # 2=User display name only
  }

  UserRightsAssignment '3.11 - Settings for User Rights Policies | Load and unload device drivers' {
    Policy   = 'Load_and_unload_device_drivers'
    Identity = @('*S-1-5-32-544'
    ) # *S-1-5-32-544=Administrators
  }
    
  UserRightsAssignment '3.11 - Settings for User Rights Policies | Impersonate a client after authentication' {
    Policy   = 'Impersonate_a_client_after_authentication'
    Identity = @('*S-1-5-20', '*S-1-5-19', '*S-1-5-6', '*S-1-5-32-544'
    ) # *S-1-5-32-544=Administrators, *S-1-5-6=Service, *S-1-5-19=Local Service, *S-1-5-20=Network Service
  }

  UserRightsAssignment '3.11 - Settings for User Rights Policies | Change the system time' {
    Policy   = 'Change_the_system_time'
    Identity = @('*S-1-5-32-544', '*S-1-5-19'
    ) # *S-1-5-32-544=Administrators, *S-1-5-19=Local Service
  }

  UserRightsAssignment '3.11 - Settings for User Rights Policies | Take ownership of files or other objects' {
    Policy   = 'Take_ownership_of_files_or_other_objects'
    Identity = @('*S-1-5-32-544'
    ) # *S-1-5-32-544=Administrators
  }

  UserRightsAssignment '3.11 - Settings for User Rights Policies | Deny log on locally' {
    Policy   = 'Deny_log_on_locally'
    Identity = @('*S-1-5-32-546'
    ) # *S-1-5-32-546=Guests
  }

  UserRightsAssignment '3.11 - Settings for User Rights Policies | Deny log on as a batch job' {
    Policy   = 'Deny_log_on_as_a_batch_job'
    Identity = @('*S-1-5-32-546'
    ) # *S-1-5-32-546=Guests
  }
 
  UserRightsAssignment '3.11 - Settings for User Rights Policies | Deny Log on as a service' {
    Policy   = 'Deny_log_on_as_a_service'
    Identity = @(''
    ) # '' = No One
  }
    
  UserRightsAssignment '3.11 - Settings for User Rights Policies | Back up files and directories' {
    Policy   = 'Back_up_files_and_directories'
    Identity = @('*S-1-5-32-551', '*S-1-5-32-544'
    ) # *S-1-5-32-544=Administrators, *S-1-5-32-551=Backup Operators
  }

  UserRightsAssignment '3.11 - Settings for User Rights Policies | Access Credential Manager as a trusted caller' {
    Policy   = 'Access_Credential_Manager_as_a_trusted_caller'
    Identity = @(''
    ) # '' = No One
  }

  UserRightsAssignment '3.11 - Settings for User Rights Policies | Allow log on through Remote Desktop Services' {
    Policy   = 'Allow_log_on_through_Remote_Desktop_Services'
    Identity = @('*S-1-5-32-555', '*S-1-5-32-544'
    ) # *S-1-5-32-544=Administrators, *S-1-5-32-555=Remote Desktop Users
  }

  UserRightsAssignment '3.11 - Settings for User Rights Policies | Adjust memory quotas for a process' {
    Policy   = 'Adjust_memory_quotas_for_a_process'
    Identity = @('*S-1-5-20', '*S-1-5-19', '*S-1-5-32-544'
    ) # *S-1-5-32-544=Administrators, *S-1-5-19=Local Service, *S-1-5-20=Network Service
  }

  UserRightsAssignment '3.11 - Settings for User Rights Policies | Modify an object label' {
    Policy   = 'Modify_an_object_label'
    Identity = @(''
    ) # '' = No One
  }

  UserRightsAssignment '3.11 - Settings for User Rights Policies | Access this computer from the network' {
    Policy   = 'Access_this_computer_from_the_network'
    Identity = @('*S-1-5-11', '*S-1-5-32-544'
    ) # *S-1-5-32-544=Administrators, *S-1-5-11=Authenticated Users
  }

  UserRightsAssignment '3.11 - Settings for User Rights Policies | Debug programs' {
    Policy   = 'Debug_programs'
    Identity = @('*S-1-5-32-544'
    ) # *S-1-5-32-544=Administrators
  }

  UserRightsAssignment '3.11 - Settings for User Rights Policies | Deny log on through Remote Desktop Services' {
    Policy   = 'Deny_log_on_through_Remote_Desktop_Services'
    Identity = @('*S-1-5-32-546', '*S-1-5-20', '*S-1-5-19', '*S-1-5-6'
    ) # *S-1-5-32-546=Guests, *S-1-5-6=Service, *S-1-5-19=Local Service, *S-1-5-20=Network Service
  }

  UserRightsAssignment '3.11 - Settings for User Rights Policies | Increase a process working set' {
    Policy   = 'Increase_a_process_working_set'
    Identity = @('*S-1-5-19', '*S-1-5-32-544'
    ) # *S-1-5-32-544=Administrators, *S-1-5-19=Local Service
  }

  UserRightsAssignment '3.11 - Settings for User Rights Policies | Increase scheduling priority' {
    Policy   = 'Increase_scheduling_priority'
    Identity = @('*S-1-5-32-544'
    ) # *S-1-5-32-544=Administrators
  }

  UserRightsAssignment '3.11 - Settings for User Rights Policies | Add workstations to domain' {
    Policy   = 'Add_workstations_to_domain'
    Identity = @('*S-1-5-32-544'
    ) # *S-1-5-32-544=Administrators
  }

  UserRightsAssignment '3.11 - Settings for User Rights Policies | Remove computer from docking station' {
    Policy   = 'Remove_computer_from_docking_station'
    Identity = @('*S-1-5-32-544'
    ) # *S-1-5-32-544=Administrators
  }

  UserRightsAssignment '3.11 - Settings for User Rights Policies | Change the time zone' {
    Policy   = 'Change_the_time_zone'
    Identity = @('*S-1-5-32-544', '*S-1-5-19'
    ) # *S-1-5-32-544=Administrators, *S-1-5-19=Local Service
  }
    

  UserRightsAssignment '3.11 - Settings for User Rights Policies | Profile single process' {
    Policy   = 'Profile_single_process'
    Identity = @('*S-1-5-32-544'
    ) # *S-1-5-32-544=Administrators
  }

  UserRightsAssignment '3.11 - Settings for User Rights Policies | Replace a process level token' {
    Policy   = 'Replace_a_process_level_token'
    Identity = @('*S-1-5-20', '*S-1-5-19'
    ) # *S-1-5-19=Local Service, *S-1-5-20=Network Service

  }

  UserRightsAssignment '3.11 - Settings for User Rights Policies | Allow log on locally' {
    Policy   = 'Allow_log_on_locally'
    Identity = @('*S-1-5-32-544'
    ) # *S-1-5-32-544=Administrators
  }

  UserRightsAssignment '3.11 - Settings for User Rights Policies | Create a pagefile' {
    Policy   = 'Create_a_pagefile'
    Identity = @('*S-1-5-32-544'
    ) # *S-1-5-32-544=Administrators
  }

  UserRightsAssignment '3.11 - Settings for User Rights Policies | Restore files and directories' {
    Policy   = 'Restore_files_and_directories'
    Identity = @('*S-1-5-32-551', '*S-1-5-32-544'
    ) # *S-1-5-32-544=Administrators, *S-1-5-32-551=Backup Operators
  }

  UserRightsAssignment '3.11 - Settings for User Rights Policies | Create a token object' {
    Policy   = 'Create_a_token_object'
    Identity = @(''
    ) # '' = No One
  }

  UserRightsAssignment '3.11 - Settings for User Rights Policies | Create permanent shared objects' {
    Policy   = 'Create_permanent_shared_objects'
    Identity = @(''
    ) # '' = No One
  }

  UserRightsAssignment '3.11 - Settings for User Rights Policies | Profile system performance' {
    Policy   = 'Profile_system_performance'
    Identity = @('*S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420', '*S-1-5-32-544'
    ) # *S-1-5-32-544=Administrators, *S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420=WdiServiceHost
  }

  UserRightsAssignment '3.11 - Settings for User Rights Policies | Create global objects' {
    Policy   = 'Create_global_objects'
    Identity = @('*S-1-5-20', '*S-1-5-19', '*S-1-5-6', '*S-1-5-32-544'
    ) # *S-1-5-32-544=Administrators, *S-1-5-6=Service, *S-1-5-19=Local Service, *S-1-5-20=Network Service
  }

  UserRightsAssignment '3.11 - Settings for User Rights Policies | Deny access to this computer from the network' {
    Policy   = 'Deny_access_to_this_computer_from_the_network'
    Identity = @('*S-1-5-32-546', '*S-1-5-20', '*S-1-5-19', '*S-1-5-6'
    ) # *S-1-5-6=Service, *S-1-5-19=Local Service, *S-1-5-20=Network Service, *S-1-5-32-546=Guests,
  }

  UserRightsAssignment '3.11 - Settings for User Rights Policies | Enable computer and user accounts to be trusted for delegation' {
    Policy   = 'Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
    Identity = @(''
    ) # '' = No One
  }

  UserRightsAssignment '3.11 - Settings for User Rights Policies | Force shutdown from a remote system' {
    Policy   = 'Force_shutdown_from_a_remote_system'
    Identity = @('*S-1-5-32-544'
    ) # *S-1-5-32-544=Administrators
  }

  UserRightsAssignment '3.11 - Settings for User Rights Policies | Shut down the system' {
    Policy   = 'Shut_down_the_system'
    Identity = @('*S-1-5-32-544'
    ) # *S-1-5-32-544=Administrators
  }

  UserRightsAssignment '3.11 - Settings for User Rights Policies | Perform volume maintenance tasks' {
    Policy   = 'Perform_volume_maintenance_tasks'
    Identity = @('*S-1-5-32-544'
    ) # *S-1-5-32-544=Administrators
  }

  UserRightsAssignment '3.11 - Settings for User Rights Policies | Act as part of the operating system' {
    Policy   = 'Act_as_part_of_the_operating_system'
    Identity = @(''
    ) # '' = No One
  }

  UserRightsAssignment '3.11 - Settings for User Rights Policies | Generate security audits' {
    Policy   = 'Generate_security_audits'
    Identity = @('*S-1-5-20', '*S-1-5-19'
    ) # *S-1-5-19=Local Service, *S-1-5-20=Network Service
  }

  UserRightsAssignment '3.11 - Settings for User Rights Policies | Lock pages in memory' {
    Policy   = 'Lock_pages_in_memory'
    Identity = @(''
    ) # '' = No One
  }

  UserRightsAssignment '3.11 - Settings for User Rights Policies | Create symbolic links' {
    Policy   = 'Create_symbolic_links'
    Identity = @('*S-1-5-32-544'
    ) # *S-1-5-32-544=Administrators
  }

  UserRightsAssignment '3.11 - Settings for User Rights Policies | Modify firmware environment values' {
    Policy   = 'Modify_firmware_environment_values'
    Identity = @('*S-1-5-32-544'
    ) # *S-1-5-32-544=Administrators
  }

  UserRightsAssignment '3.11 - Settings for User Rights Policies | Manage auditing and security log' {
    Policy   = 'Manage_auditing_and_security_log'
    Identity = @('*S-1-5-32-544'
    ) # *S-1-5-32-544=Administrators
  }

  UserRightsAssignment '3.11 - Settings for User Rights Policies | Bypass traverse checking' {
    Policy   = 'Bypass_traverse_checking'
    Identity = @('*S-1-5-20', '*S-1-5-19', '*S-1-5-32-551', '*S-1-5-11', '*S-1-5-32-544'
    ) # *S-1-5-32-544=Administrators, *S-1-5-19=Local Service, *S-1-5-20=Network Service, *S-1-5-32-551=Backup Operators, *S-1-5-11=Authenticated Users
  }

  SecurityOption '3.5 - Local Policy | Network access: Allow anonymous SID/Name translation' {
    Name                                                = 'Network_access_Allow_anonymous_SID_Name_translation'
    Network_access_Allow_anonymous_SID_Name_translation = 'Disabled'
  }

  SecurityOption '3.5 - Local Policy | Network security: Force logoff when logon hours expire' {
    Name                                                  = 'Network_security_Force_logoff_when_logon_hours_expire'
    Network_security_Force_logoff_when_logon_hours_expire = 'Enabled'
  }

  SecurityOption '3.5 - Local Policy | Accounts: Guest account status' {
    Accounts_Guest_account_status = 'Disabled'
    Name                          = 'Accounts_Guest_account_status'
  }

  AccountPolicy '3.2.1 - Password Policy | Enforce password history' {
    Name                     = 'Enforce_password_history'
    Enforce_password_history = 24
  }

  AccountPolicy '3.2.1 - Password Policy | Maximum password age' {
    Name                 = 'Maximum_password_age'
    Maximum_password_age = 60
  }

  AccountPolicy '3.2.1 - Password Policy | Minimum password age' {
    Name                 = 'Minimum_password_age'
    Minimum_password_age = 0
  }

  AccountPolicy '3.2.1 - Password Policy | Password must meet complexity requirements' {
    Name                                       = 'Password_must_meet_complexity_requirements'
    Password_must_meet_complexity_requirements = 'Enabled'
  }
  
  AccountPolicy '3.2.1 - Password Policy | Store passwords using reversible encryption' {
    Name                                        = 'Store_passwords_using_reversible_encryption'
    Store_passwords_using_reversible_encryption = 'Disabled'
  }
  
  AccountPolicy '3.2.2 - Account Lockout Policy | Account lockout threshold' {
    Name                      = 'Account_lockout_threshold'
    Account_lockout_threshold = 5
  }

  AccountPolicy '3.2.2 - Account Lockout Policy | Reset account lockout counter after' {
    Name                                = 'Reset_account_lockout_counter_after'
    Reset_account_lockout_counter_after = 30
  }

  AccountPolicy '3.2.2 - Account Lockout Policy | Account lockout duration' {
    Name                     = 'Account_lockout_duration'
    Account_lockout_duration = 30
  }

  xRegistry '3.12 - Settings for Event Logs | Restrict guest access to application log' {
    Force     = $true
    ValueName = 'RestrictGuestAccess'
    ValueType = 'Dword'
    Key       = 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application'
    ValueData = 1 # 1=Enabled
  }

  xRegistry '3.12 - Settings for Event Logs | Restrict guest access to security log' {
    Force     = $true
    ValueName = 'RestrictGuestAccess'
    ValueType = 'Dword'
    Key       = 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security'
    ValueData = 1 # 1=Enabled
  }

  xRegistry '3.12 - Settings for Event Logs | Restrict guest access to system log' {
    Force     = $true
    ValueName = 'RestrictGuestAccess'
    ValueType = 'Dword'
    Key       = 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\System'
    ValueData = 1 # 1=Enabled
  }

  SecurityOption '3.5 - Local Policy | Accounts: Rename administrator account' {
    Accounts_Rename_administrator_account = 'BukowCh'
    Name                                  = 'Accounts_Rename_administrator_account'	
  }

  SecurityOption '3.5 - Local Policy | Accounts: Rename guest account' {
    Accounts_Rename_guest_account = 'NewGst'
    Name                          = 'Accounts_Rename_guest_account'
  }
}