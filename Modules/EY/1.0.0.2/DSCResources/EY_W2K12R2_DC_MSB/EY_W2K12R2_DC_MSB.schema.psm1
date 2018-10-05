Configuration EY_W2K12R2_DC_MSB
{
  Import-DSCResource -ModuleName 'xPSDesiredStateConfiguration'
  Import-DSCResource -ModuleName 'AuditPolicyDSC'
  Import-DSCResource -ModuleName 'SecurityPolicyDSC'
  
  $EnabledProtocols = @('TLS 1.1', 'TLS 1.2')
  $DisabledProtocols = @('Multi-Protocol Unified Hello', 'PCT 1.0', 'SSL 2.0', 'SSL 3.0', 'TLS 1.0')
  $EnabledCiphers = @('AES 128/128', 'AES 256/256')
  $DisabledCiphers = @('DES 56/56', 'RC2 40/128', 'RC4 40/128', 'RC4 128/128', 'RC4 56/128', 'Triple DES 168', 'Triple DES 168/168')
  $EnabledHashes = @('SHA')
  $DisabledHashes = @()
  $EnabledKeyExchangeAlgorithms = @('Diffie-Hellman', 'PKCS')
  $DisabledKeyExchangeAlgorithms = @()

  #region "GPO"
  xRegistry 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun' {
    Force     = $true
    ValueName = 'NoDriveTypeAutoRun'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    ValueData = 255
  }

  xRegistry 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\MSAOptional' {
    Force     = $true
    ValueName = 'MSAOptional'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
    ValueData = 1

  }

  xRegistry 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableAutomaticRestartSignOn' {
    Force     = $true
    ValueName = 'DisableAutomaticRestartSignOn'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
    ValueData = 1

  }

  xRegistry 'Registry(POL): HKLM:\Software\Policies\Microsoft\EMET\Defaults\LyncCommunicator' {
    Force     = $true
    ValueName = 'LyncCommunicator'
    ValueType = 'String'
    Key       = 'HKLM:\Software\Policies\Microsoft\EMET\Defaults'
    ValueData = '*\Microsoft Lync\communicator.exe'

  }

  xRegistry 'Registry(POL): HKLM:\Software\Policies\Microsoft\EMET\Defaults\jre6_javaw' {
    Force     = $true
    ValueName = 'jre6_javaw'
    ValueType = 'String'
    Key       = 'HKLM:\Software\Policies\Microsoft\EMET\Defaults'
    ValueData = '*\Java\jre6\bin\javaw.exe -HeapSpray'

  }

  xRegistry 'Registry(POL): HKLM:\Software\Policies\Microsoft\EMET\Defaults\jre7_java' {
    Force     = $true
    ValueName = 'jre7_java'
    ValueType = 'String'
    Key       = 'HKLM:\Software\Policies\Microsoft\EMET\Defaults'
    ValueData = '*\Java\jre7\bin\java.exe -HeapSpray'

  }

  xRegistry 'Registry(POL): HKLM:\Software\Policies\Microsoft\EMET\Defaults\jre6_java' {
    Force     = $true
    ValueName = 'jre6_java'
    ValueType = 'String'
    Key       = 'HKLM:\Software\Policies\Microsoft\EMET\Defaults'
    ValueData = '*\Java\jre6\bin\java.exe -HeapSpray'

  }

  xRegistry 'Registry(POL): HKLM:\Software\Policies\Microsoft\EMET\Defaults\Excel' {
    Force     = $true
    ValueName = 'Excel'
    ValueType = 'String'
    Key       = 'HKLM:\Software\Policies\Microsoft\EMET\Defaults'
    ValueData = '*\OFFICE1*\EXCEL.EXE'

  }

  xRegistry 'Registry(POL): HKLM:\Software\Policies\Microsoft\EMET\Defaults\InfoPath' {
    Force     = $true
    ValueName = 'InfoPath'
    ValueType = 'String'
    Key       = 'HKLM:\Software\Policies\Microsoft\EMET\Defaults'
    ValueData = '*\OFFICE1*\INFOPATH.EXE'

  }

  xRegistry 'Registry(POL): HKLM:\Software\Policies\Microsoft\EMET\Defaults\Outlook' {
    Force     = $true
    ValueName = 'Outlook'
    ValueType = 'String'
    Key       = 'HKLM:\Software\Policies\Microsoft\EMET\Defaults'
    ValueData = '*\OFFICE1*\OUTLOOK.EXE'

  }

  xRegistry 'Registry(POL): HKLM:\Software\Policies\Microsoft\EMET\Defaults\jre7_javaw' {
    Force     = $true
    ValueName = 'jre7_javaw'
    ValueType = 'String'
    Key       = 'HKLM:\Software\Policies\Microsoft\EMET\Defaults'
    ValueData = '*\Java\jre7\bin\javaw.exe -HeapSpray'

  }

  xRegistry 'Registry(POL): HKLM:\Software\Policies\Microsoft\EMET\Defaults\SkyDrive' {
    Force     = $true
    ValueName = 'SkyDrive'
    ValueType = 'String'
    Key       = 'HKLM:\Software\Policies\Microsoft\EMET\Defaults'
    ValueData = '*\SkyDrive\SkyDrive.exe'

  }

  xRegistry 'Registry(POL): HKLM:\Software\Policies\Microsoft\EMET\Defaults\PowerPoint' {
    Force     = $true
    ValueName = 'PowerPoint'
    ValueType = 'String'
    Key       = 'HKLM:\Software\Policies\Microsoft\EMET\Defaults'
    ValueData = '*\OFFICE1*\POWERPNT.EXE'

  }

  xRegistry 'Registry(POL): HKLM:\Software\Policies\Microsoft\EMET\Defaults\AcrobatReader' {
    Force     = $true
    ValueName = 'AcrobatReader'
    ValueType = 'String'
    Key       = 'HKLM:\Software\Policies\Microsoft\EMET\Defaults'
    ValueData = '*\Adobe\Reader*\Reader\AcroRd32.exe'

  }

  xRegistry 'Registry(POL): HKLM:\Software\Policies\Microsoft\EMET\Defaults\jre6_javaws' {
    Force     = $true
    ValueName = 'jre6_javaws'
    ValueType = 'String'
    Key       = 'HKLM:\Software\Policies\Microsoft\EMET\Defaults'
    ValueData = '*\Java\jre6\bin\javaws.exe -HeapSpray'

  }

  xRegistry 'Registry(POL): HKLM:\Software\Policies\Microsoft\EMET\Defaults\jre7_javaws' {
    Force     = $true
    ValueName = 'jre7_javaws'
    ValueType = 'String'
    Key       = 'HKLM:\Software\Policies\Microsoft\EMET\Defaults'
    ValueData = '*\Java\jre7\bin\javaws.exe -HeapSpray'

  }

  xRegistry 'Registry(POL): HKLM:\Software\Policies\Microsoft\EMET\Defaults\Access' {
    Force     = $true
    ValueName = 'Access'
    ValueType = 'String'
    Key       = 'HKLM:\Software\Policies\Microsoft\EMET\Defaults'
    ValueData = '*\OFFICE1*\MSACCESS.EXE'

  }

  xRegistry 'Registry(POL): HKLM:\Software\Policies\Microsoft\EMET\Defaults\Acrobat' {
    Force     = $true
    ValueName = 'Acrobat'
    ValueType = 'String'
    Key       = 'HKLM:\Software\Policies\Microsoft\EMET\Defaults'
    ValueData = '*\Adobe\Acrobat*\Acrobat\Acrobat.exe'

  }

  xRegistry 'Registry(POL): HKLM:\Software\Policies\Microsoft\EMET\Defaults\Visio' {
    Force     = $true
    ValueName = 'Visio'
    ValueType = 'String'
    Key       = 'HKLM:\Software\Policies\Microsoft\EMET\Defaults'
    ValueData = '*\OFFICE1*\VISIO.EXE'

  }

  xRegistry 'Registry(POL): HKLM:\Software\Policies\Microsoft\EMET\Defaults\PhotoGallery' {
    Force     = $true
    ValueName = 'PhotoGallery'
    ValueType = 'String'
    Key       = 'HKLM:\Software\Policies\Microsoft\EMET\Defaults'
    ValueData = '*\Windows Live\Photo Gallery\WLXPhotoGallery.exe'

  }

  xRegistry 'Registry(POL): HKLM:\Software\Policies\Microsoft\EMET\Defaults\Photoshop' {
    Force     = $true
    ValueName = 'Photoshop'
    ValueType = 'String'
    Key       = 'HKLM:\Software\Policies\Microsoft\EMET\Defaults'
    ValueData = '*\Adobe\Adobe Photoshop CS*\Photoshop.exe'

  }

  xRegistry 'Registry(POL): HKLM:\Software\Policies\Microsoft\EMET\Defaults\FoxitReader' {
    Force     = $true
    ValueName = 'FoxitReader'
    ValueType = 'String'
    Key       = 'HKLM:\Software\Policies\Microsoft\EMET\Defaults'
    ValueData = '*\Foxit Reader\Foxit Reader.exe'

  }

  xRegistry 'Registry(POL): HKLM:\Software\Policies\Microsoft\EMET\Defaults\Publisher' {
    Force     = $true
    ValueName = 'Publisher'
    ValueType = 'String'
    Key       = 'HKLM:\Software\Policies\Microsoft\EMET\Defaults'
    ValueData = '*\OFFICE1*\MSPUB.EXE'

  }

  xRegistry 'Registry(POL): HKLM:\Software\Policies\Microsoft\EMET\Defaults\Wordpad' {
    Force     = $true
    ValueName = 'Wordpad'
    ValueType = 'String'
    Key       = 'HKLM:\Software\Policies\Microsoft\EMET\Defaults'
    ValueData = '*\Windows NT\Accessories\wordpad.exe'

  }

  xRegistry 'Registry(POL): HKLM:\Software\Policies\Microsoft\EMET\Defaults\WindowsLiveMail' {
    Force     = $true
    ValueName = 'WindowsLiveMail'
    ValueType = 'String'
    Key       = 'HKLM:\Software\Policies\Microsoft\EMET\Defaults'
    ValueData = '*\Windows Live\Mail\wlmail.exe'

  }

  xRegistry 'Registry(POL): HKLM:\Software\Policies\Microsoft\EMET\Defaults\PPTViewer' {
    Force     = $true
    ValueName = 'PPTViewer'
    ValueType = 'String'
    Key       = 'HKLM:\Software\Policies\Microsoft\EMET\Defaults'
    ValueData = '*\OFFICE1*\PPTVIEW.EXE'

  }

  xRegistry 'Registry(POL): HKLM:\Software\Policies\Microsoft\EMET\Defaults\Word' {
    Force     = $true
    ValueName = 'Word'
    ValueType = 'String'
    Key       = 'HKLM:\Software\Policies\Microsoft\EMET\Defaults'
    ValueData = '*\OFFICE1*\WINWORD.EXE'

  }

  xRegistry 'Registry(POL): HKLM:\Software\Policies\Microsoft\EMET\Defaults\Picture Manager' {
    Force     = $true
    ValueName = 'Picture Manager'
    ValueType = 'String'
    Key       = 'HKLM:\Software\Policies\Microsoft\EMET\Defaults'
    ValueData = '*\OFFICE1*\OIS.EXE'

  }

  xRegistry 'Registry(POL): HKLM:\Software\Policies\Microsoft\EMET\Defaults\VisioViewer' {
    Force     = $true
    ValueName = 'VisioViewer'
    ValueType = 'String'
    Key       = 'HKLM:\Software\Policies\Microsoft\EMET\Defaults'
    ValueData = '*\OFFICE1*\VPREVIEW.EXE'

  }

  xRegistry 'Registry(POL): HKLM:\Software\Policies\Microsoft\EMET\SysSettings\ASLR' {
    Force     = $true
    ValueName = 'ASLR'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Policies\Microsoft\EMET\SysSettings'
    ValueData = 3

  }

  xRegistry 'Registry(POL): HKLM:\Software\Policies\Microsoft\EMET\SysSettings\DEP' {
    Force     = $true
    ValueName = 'DEP'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Policies\Microsoft\EMET\SysSettings'
    ValueData = 2

  }

  xRegistry 'Registry(POL): HKLM:\Software\Policies\Microsoft\EMET\SysSettings\SEHOP' {
    Force     = $true
    ValueName = 'SEHOP'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Policies\Microsoft\EMET\SysSettings'
    ValueData = 2

  }

  xRegistry 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\MinEncryptionLevel' {
    Force     = $true
    ValueName = 'MinEncryptionLevel'
    ValueType = 'Dword'
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    ValueData = 3

  }

  xRegistry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\EventLog\Application\MaxSize' {
    Force     = $true
    ValueName = 'MaxSize'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\Application'
    ValueData = 32768

  }

  xRegistry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security\MaxSize' {
    Force     = $true
    ValueName = 'MaxSize'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security'
    ValueData = 393216

  }

  xRegistry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\EventLog\System\MaxSize' {
    Force     = $true
    ValueName = 'MaxSize'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\System'
    ValueData = 32768

  }

  xRegistry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated' {
    Force     = $true
    ValueName = 'AlwaysInstallElevated'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\Installer'
    ValueData = 0

  }

  xRegistry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Personalization\NoLockScreenSlideshow' {
    Force     = $true
    ValueName = 'NoLockScreenSlideshow'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\Personalization'
    ValueData = 1

  }

  xRegistry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Personalization\NoLockScreenCamera' {
    Force     = $true
    ValueName = 'NoLockScreenCamera'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\Personalization'
    ValueData = 1

  }

  xRegistry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Skydrive\DisableLibrariesDefaultSaveToSkyDrive' {
    Force     = $true
    ValueName = 'DisableLibrariesDefaultSaveToSkyDrive'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\Skydrive'
    ValueData = 1

  }

  xRegistry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Skydrive\DisableMeteredNetworkFileSync' {
    Force     = $true
    ValueName = 'DisableMeteredNetworkFileSync'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\Skydrive'
    ValueData = 0

  }

  xRegistry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Skydrive\DisableFileSync' {
    Force     = $true
    ValueName = 'DisableFileSync'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\Skydrive'
    ValueData = 1

  }

  xRegistry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Exe\EnforcementMode' {
    Force     = $true
    ValueName = 'EnforcementMode'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Exe'
    ValueData = 1

  }

  xRegistry 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Exe\5e3ec135-b5af-4961-ae4d-cde98710afc9\Value' {
    Force     = $true
    ValueName = 'Value'
    ValueType = 'String'
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Exe\5e3ec135-b5af-4961-ae4d-cde98710afc9'
    ValueData = '<FilePublisherRule Id="5e3ec135-b5af-4961-ae4d-cde98710afc9" Name="Block Google Chrome" Description="" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePublisherCondition PublisherName="O=GOOGLE INC, L=MOUNTAIN VIEW, S=CALIFORNIA, C=US" ProductName="GOOGLE CHROME" BinaryName="CHROME.EXE"><BinaryVersionRange LowSection="*" HighSection="*"/></FilePublisherCondition></Conditions></FilePublisherRule>'

  }

  xRegistry 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Exe\6db6c8f3-cf7c-4754-a438-94c95345bb53\Value' {
    Force     = $true
    ValueName = 'Value'
    ValueType = 'String'
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Exe\6db6c8f3-cf7c-4754-a438-94c95345bb53'
    ValueData = '<FilePublisherRule Id="6db6c8f3-cf7c-4754-a438-94c95345bb53" Name="Block Mozilla Firefox" Description="" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePublisherCondition PublisherName="O=MOZILLA CORPORATION, L=MOUNTAIN VIEW, S=CA, C=US" ProductName="FIREFOX" BinaryName="FIREFOX.EXE"><BinaryVersionRange LowSection="*" HighSection="*"/></FilePublisherCondition></Conditions></FilePublisherRule>'

  }

  xRegistry 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Exe\881d54fe-3848-4d6a-95fd-42d48ebe60b8\Value' {
    Force     = $true
    ValueName = 'Value'
    ValueType = 'String'
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Exe\881d54fe-3848-4d6a-95fd-42d48ebe60b8'
    ValueData = '<FilePublisherRule Id="881d54fe-3848-4d6a-95fd-42d48ebe60b8" Name="Block Internet Explorer" Description="" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="INTERNET EXPLORER" BinaryName="IEXPLORE.EXE"><BinaryVersionRange LowSection="*" HighSection="*"/></FilePublisherCondition></Conditions></FilePublisherRule>'

  }

  xRegistry 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Exe\fd686d83-a829-4351-8ff4-27c7de5755d2\Value' {
    Force     = $true
    ValueName = 'Value'
    ValueType = 'String'
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Exe\fd686d83-a829-4351-8ff4-27c7de5755d2'
    ValueData = '<FilePathRule Id="fd686d83-a829-4351-8ff4-27c7de5755d2" Name="(Default Rule) All files" Description="Allows members of the local Administrators group to run all applications." UserOrGroupSid="S-1-5-32-544" Action="Allow"><Conditions><FilePathCondition Path="*"/></Conditions></FilePathRule>'

  }

  xRegistry 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\System\DontDisplayNetworkSelectionUI' {
    Force     = $true
    ValueName = 'DontDisplayNetworkSelectionUI'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\System'
    ValueData = 1

  }

  xRegistry 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search\AllowIndexingEncryptedStoresOrItems' {
    Force     = $true
    ValueName = 'AllowIndexingEncryptedStoresOrItems'
    ValueType = 'Dword'
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
    ValueData = 0

  }

  xRegistry 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\DefaultOutboundAction' {
    Force     = $true
    ValueName = 'DefaultOutboundAction'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
    ValueData = 0

  }

  xRegistry 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\AllowLocalIPsecPolicyMerge' {
    Force     = $true
    ValueName = 'AllowLocalIPsecPolicyMerge'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
    ValueData = 1

  }

  xRegistry 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\DefaultInboundAction' {
    Force     = $true
    ValueName = 'DefaultInboundAction'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
    ValueData = 1

  }

  xRegistry 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\AllowLocalPolicyMerge' {
    Force     = $true
    ValueName = 'AllowLocalPolicyMerge'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
    ValueData = 1

  }

  xRegistry 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\DisableNotifications' {
    Force     = $true
    ValueName = 'DisableNotifications'
    ValueType = 'Dword'
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
    ValueData = 1

  }

  xRegistry 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\DisableUnicastResponsesToMulticastBroadcast' {
    Force     = $true
    ValueName = 'DisableUnicastResponsesToMulticastBroadcast'
    ValueType = 'Dword'
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
    ValueData = 1

  }

  xRegistry 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\EnableFirewall' {
    Force     = $true
    ValueName = 'EnableFirewall'
    ValueType = 'Dword'
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
    ValueData = 0

  }

  xRegistry 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\DisableUnicastResponsesToMulticastBroadcast' {
    Force     = $true
    ValueName = 'DisableUnicastResponsesToMulticastBroadcast'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
    ValueData = 1

  }

  xRegistry 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\DisableNotifications' {
    Force     = $true
    ValueName = 'DisableNotifications'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
    ValueData = 0

  }

  xRegistry 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\AllowLocalIPsecPolicyMerge' {
    Force     = $true
    ValueName = 'AllowLocalIPsecPolicyMerge'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
    ValueData = 1

  }

  xRegistry 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\DefaultOutboundAction' {
    Force     = $true
    ValueName = 'DefaultOutboundAction'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
    ValueData = 0

  }

  xRegistry 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\DefaultInboundAction' {
    Force     = $true
    ValueName = 'DefaultInboundAction'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
    ValueData = 1

  }

  xRegistry 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\AllowLocalPolicyMerge' {
    Force     = $true
    ValueName = 'AllowLocalPolicyMerge'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
    ValueData = 1

  }

  xRegistry 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\EnableFirewall' {
    Force     = $true
    ValueName = 'EnableFirewall'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
    ValueData = 1

  }

  xRegistry 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\AllowLocalPolicyMerge' {
    Force     = $true
    ValueName = 'AllowLocalPolicyMerge'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
    ValueData = 1

  }

  xRegistry 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\DisableNotifications' {
    Force     = $true
    ValueName = 'DisableNotifications'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
    ValueData = 0

  }

  xRegistry 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\AllowLocalIPsecPolicyMerge' {
    Force     = $true
    ValueName = 'AllowLocalIPsecPolicyMerge'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
    ValueData = 1

  }

  xRegistry 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\DefaultOutboundAction' {
    Force     = $true
    ValueName = 'DefaultOutboundAction'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
    ValueData = 0

  }

  xRegistry 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\EnableFirewall' {
    Force     = $true
    ValueName = 'EnableFirewall'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
    ValueData = 1

  }

  xRegistry 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\DefaultInboundAction' {
    Force     = $true
    ValueName = 'DefaultInboundAction'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
    ValueData = 1

  }

  xRegistry 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\DisableUnicastResponsesToMulticastBroadcast' {
    Force     = $true
    ValueName = 'DisableUnicastResponsesToMulticastBroadcast'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
    ValueData = 1

  }

  xRegistry 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential' {
    Force     = $true
    ValueName = 'UseLogonCredential'
    ValueType = 'Dword'
    Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
    ValueData = 0

  }

  AuditPolicySubcategory 'Authentication Policy Change (Success) - Inclusion' {
    Name      = 'Authentication Policy Change'
    Ensure    = 'Present'
    AuditFlag = 'Success'

  }

  AuditPolicySubcategory 'Authentication Policy Change (Failure) - Inclusion' {
    Name      = 'Authentication Policy Change'
    Ensure    = 'Present'
    AuditFlag = 'Failure'

  }

  AuditPolicySubcategory 'Authorization Policy Change (Success) - Inclusion' {
    Name      = 'Authorization Policy Change'
    Ensure    = 'Present'
    AuditFlag = 'Success'

  }

  AuditPolicySubcategory 'Authorization Policy Change (Failure) - Inclusion' {
    Name      = 'Authorization Policy Change'
    Ensure    = 'Present'
    AuditFlag = 'Failure'

  }

  AuditPolicySubcategory 'Audit Policy Change (Success) - Inclusion' {
    Name      = 'Audit Policy Change'
    Ensure    = 'Present'
    AuditFlag = 'Success'

  }

  AuditPolicySubcategory 'Audit Policy Change (Failure) - Inclusion' {
    Name      = 'Audit Policy Change'
    Ensure    = 'Present'
    AuditFlag = 'Failure'

  }

  AuditPolicySubcategory 'IPsec Driver (Success) - Inclusion' {
    Name      = 'IPsec Driver'
    Ensure    = 'Present'
    AuditFlag = 'Success'

  }

  AuditPolicySubcategory 'IPsec Driver (Failure) - Inclusion' {
    Name      = 'IPsec Driver'
    Ensure    = 'Present'
    AuditFlag = 'Failure'

  }

  AuditPolicySubcategory 'Other System Events (Success) - Inclusion' {
    Name      = 'Other System Events'
    Ensure    = 'Present'
    AuditFlag = 'Success'

  }

  AuditPolicySubcategory 'Other System Events (Failure) - Inclusion' {
    Name      = 'Other System Events'
    Ensure    = 'Present'
    AuditFlag = 'Failure'

  }

  AuditPolicySubcategory 'System Integrity (Success) - Inclusion' {
    Name      = 'System Integrity'
    Ensure    = 'Present'
    AuditFlag = 'Success'

  }

  AuditPolicySubcategory 'System Integrity (Failure) - Inclusion' {
    Name      = 'System Integrity'
    Ensure    = 'Present'
    AuditFlag = 'Failure'

  }

  AuditPolicySubcategory 'Security State Change (Success) - Inclusion' {
    Name      = 'Security State Change'
    Ensure    = 'Present'
    AuditFlag = 'Success'

  }

  AuditPolicySubcategory 'Security State Change (Failure) - Inclusion' {
    Name      = 'Security State Change'
    Ensure    = 'Present'
    AuditFlag = 'Failure'

  }

  AuditPolicySubcategory 'Security System Extension (Success) - Inclusion' {
    Name      = 'Security System Extension'
    Ensure    = 'Present'
    AuditFlag = 'Success'

  }

  AuditPolicySubcategory 'Security System Extension (Failure) - Inclusion' {
    Name      = 'Security System Extension'
    Ensure    = 'Present'
    AuditFlag = 'Failure'

  }

  AuditPolicySubcategory 'Other Account Management Events (Success) - Inclusion' {
    Name      = 'Other Account Management Events'
    Ensure    = 'Present'
    AuditFlag = 'Success'

  }

  AuditPolicySubcategory 'Other Account Management Events (Failure) - Inclusion' {
    Name      = 'Other Account Management Events'
    Ensure    = 'Present'
    AuditFlag = 'Failure'

  }

  AuditPolicySubcategory 'Security Group Management (Success) - Inclusion' {
    Name      = 'Security Group Management'
    Ensure    = 'Present'
    AuditFlag = 'Success'

  }

  AuditPolicySubcategory 'Security Group Management (Failure) - Inclusion' {
    Name      = 'Security Group Management'
    Ensure    = 'Present'
    AuditFlag = 'Failure'

  }

  AuditPolicySubcategory 'Distribution Group Management (Success) - Inclusion' {
    Name      = 'Distribution Group Management'
    Ensure    = 'Present'
    AuditFlag = 'Success'

  }

  AuditPolicySubcategory 'Distribution Group Management (Failure) - Inclusion' {
    Name      = 'Distribution Group Management'
    Ensure    = 'Present'
    AuditFlag = 'Failure'

  }

  AuditPolicySubcategory 'Computer Account Management (Success) - Inclusion' {
    Name      = 'Computer Account Management'
    Ensure    = 'Present'
    AuditFlag = 'Success'

  }

  AuditPolicySubcategory 'Computer Account Management (Failure) - Inclusion' {
    Name      = 'Computer Account Management'
    Ensure    = 'Present'
    AuditFlag = 'Failure'

  }

  AuditPolicySubcategory 'User Account Management (Success) - Inclusion' {
    Name      = 'User Account Management'
    Ensure    = 'Present'
    AuditFlag = 'Success'

  }

  AuditPolicySubcategory 'User Account Management (Failure) - Inclusion' {
    Name      = 'User Account Management'
    Ensure    = 'Present'
    AuditFlag = 'Failure'

  }

  AuditPolicySubcategory 'Directory Service Changes (Success) - Inclusion' {
    Name      = 'Directory Service Changes'
    Ensure    = 'Present'
    AuditFlag = 'Success'

  }

  AuditPolicySubcategory 'Directory Service Changes (Failure) - Inclusion' {
    Name      = 'Directory Service Changes'
    Ensure    = 'Present'
    AuditFlag = 'Failure'

  }

  AuditPolicySubcategory 'Directory Service Access (Success) - Inclusion' {
    Name      = 'Directory Service Access'
    Ensure    = 'Present'
    AuditFlag = 'Success'

  }

  AuditPolicySubcategory 'Directory Service Access (Failure) - Inclusion' {
    Name      = 'Directory Service Access'
    Ensure    = 'Present'
    AuditFlag = 'Failure'

  }

  AuditPolicySubcategory 'Sensitive Privilege Use (Success) - Inclusion' {
    Name      = 'Sensitive Privilege Use'
    Ensure    = 'Present'
    AuditFlag = 'Success'

  }

  AuditPolicySubcategory 'Sensitive Privilege Use (Failure) - Inclusion' {
    Name      = 'Sensitive Privilege Use'
    Ensure    = 'Present'
    AuditFlag = 'Failure'

  }

  AuditPolicySubcategory 'Process Creation - Inclusion' {
    Name      = 'Process Creation'
    Ensure    = 'Present'
    AuditFlag = 'Success'

  }

  AuditPolicySubcategory 'Account Lockout - Inclusion' {
    Name      = 'Account Lockout'
    Ensure    = 'Present'
    AuditFlag = 'Success'

  }

  AuditPolicySubcategory 'Logon (Success) - Inclusion' {
    Name      = 'Logon'
    Ensure    = 'Present'
    AuditFlag = 'Success'

  }

  AuditPolicySubcategory 'Logon (Failure) - Inclusion' {
    Name      = 'Logon'
    Ensure    = 'Present'
    AuditFlag = 'Failure'

  }

  AuditPolicySubcategory 'Special Logon - Inclusion' {
    Name      = 'Special Logon'
    Ensure    = 'Present'
    AuditFlag = 'Success'

  }

  AuditPolicySubcategory 'Logoff - Inclusion' {
    Name      = 'Logoff'
    Ensure    = 'Present'
    AuditFlag = 'Success'

  }

  AuditPolicySubcategory 'Credential Validation (Success) - Inclusion' {
    Name      = 'Credential Validation'
    Ensure    = 'Present'
    AuditFlag = 'Success'

  }

  AuditPolicySubcategory 'Credential Validation (Failure) - Inclusion' {
    Name      = 'Credential Validation'
    Ensure    = 'Present'
    AuditFlag = 'Failure'

  }

  xService 'Services(INF): W32Time' {
    Name  = 'W32Time'
    State = 'Running'
    StartupType = 'Automatic'
  }

  # The Networking-MPSSVC-Svc component is part of Windows Firewall, which protects computers by preventing unauthorized users from gaining access through the Internet or a network.
  # https://docs.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/networking-mpssvc-svc
  xService 'Services(INF): MpsSvc' {
    Name  = 'MpsSvc'
    State = 'Running'
    StartupType = 'Automatic'

  }

  xServiceSet 'Disabled Services' {
    Name = @('AudioSrv','Themes','simptcp','tlntsvr','iisadmin','ftpsvc','w3svc','SharedAccess','AudioEndpointBuilder','smtpsvc')
    State = 'Stopped'
    StartupType = 'Disabled'
  }

  xRegistry 'Registry(INF): HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ScRemoveOption' {
    Force     = $true
    ValueName = 'ScRemoveOption'
    ValueType = 'String'
    Key       = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
    ValueData = '1'

  }

  xRegistry 'Registry(INF): HKLM:\System\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy' {
    Force     = $true
    ValueName = 'SCENoApplyLegacyAuditPolicy'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Control\Lsa'
    ValueData = 1

  }

  xRegistry 'Registry(INF): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\InactivityTimeoutSecs' {
    Force     = $true
    ValueName = 'InactivityTimeoutSecs'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
    ValueData = 900

  }

  xRegistry 'Registry(INF): HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature' {
    Force     = $true
    ValueName = 'RequireSecuritySignature'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters'
    ValueData = 1

  }

  xRegistry 'Registry(INF): HKLM:\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths\Machine' {
    Force     = $true
    ValueName = 'Machine'
    ValueType = 'MultiString'
    Key       = 'HKLM:\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths'
    ValueData = @('System\CurrentControlSet\Control\Print\Printers System\CurrentControlSet\Services\Eventlog Software\Microsoft\OLAP Server Software\Microsoft\Windows NT\CurrentVersion\Print Software\Microsoft\Windows NT\CurrentVersion\Windows System\CurrentControlSet\Control\ContentIndex System\CurrentControlSet\Control\Terminal Server System\CurrentControlSet\Control\Terminal Server\UserConfig System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration Software\Microsoft\Windows NT\CurrentVersion\Perflib System\CurrentControlSet\Services\SysmonLog'
    )

  }

  xRegistry 'Registry(INF): HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnableSecuritySignature' {
    Force     = $true
    ValueName = 'EnableSecuritySignature'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters'
    ValueData = 1

  }

  xRegistry 'Registry(INF): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle' {
    Force     = $true
    ValueName = 'EnableUIADesktopToggle'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
    ValueData = 0

  }

  xRegistry 'Registry(INF): HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters\requirestrongkey' {
    Force     = $true
    ValueName = 'requirestrongkey'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters'
    ValueData = 1

  }

  xRegistry 'Registry(INF): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeCaption' {
    Force     = $true
    ValueName = 'LegalNoticeCaption'
    ValueType = 'String'
    Key       = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
    ValueData = 'Ernst & Young Logon Disclaimer'

  }

  xRegistry 'Registry(INF): HKLM:\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths\Machine' {
    Force     = $true
    ValueName = 'Machine'
    ValueType = 'MultiString'
    Key       = 'HKLM:\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths'
    ValueData = @('System\CurrentControlSet\Control\ProductOptions System\CurrentControlSet\Control\Server Applications Software\Microsoft\Windows NT\CurrentVersion'
    )

  }

  xRegistry 'Registry(INF): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA' {
    Force     = $true
    ValueName = 'EnableLUA'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
    ValueData = 1

  }

  xRegistry 'Registry(INF): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop' {
    Force     = $true
    ValueName = 'PromptOnSecureDesktop'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
    ValueData = 1

  }

  xRegistry 'Registry(INF): HKLM:\System\CurrentControlSet\Control\Session Manager\Memory Management\ClearPageFileAtShutdown' {
    Force     = $true
    ValueName = 'ClearPageFileAtShutdown'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Control\Session Manager\Memory Management'
    ValueData = 0

  }

  xRegistry 'Registry(INF): HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinClientSec' {
    Force     = $true
    ValueName = 'NTLMMinClientSec'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0'
    ValueData = 537395200

  }

  xRegistry 'Registry(INF): HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters\signsecurechannel' {
    Force     = $true
    ValueName = 'signsecurechannel'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters'
    ValueData = 1

  }

  xRegistry 'Registry(INF): HKLM:\System\CurrentControlSet\Control\Lsa\CrashOnAuditFail' {
    Force     = $true
    ValueName = 'CrashOnAuditFail'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Control\Lsa'
    ValueData = 0

  }

  xRegistry 'Registry(INF): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken' {
    Force     = $true
    ValueName = 'FilterAdministratorToken'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
    ValueData = 1

  }

  xRegistry 'Registry(INF): HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters\enablesecuritysignature' {
    Force     = $true
    ValueName = 'enablesecuritysignature'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters'
    ValueData = 1

  }

  xRegistry 'Registry(INF): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin' {
    Force     = $true
    ValueName = 'ConsentPromptBehaviorAdmin'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
    ValueData = 5

  }

  xRegistry 'Registry(INF): HKLM:\System\CurrentControlSet\Control\Lsa\UseMachineId' {
    Force     = $true
    ValueName = 'UseMachineId'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Control\Lsa'
    ValueData = 1

  }

  xRegistry 'Registry(INF): HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters\requiresecuritysignature' {
    Force     = $true
    ValueName = 'requiresecuritysignature'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters'
    ValueData = 1

  }

  xRegistry 'Registry(INF): HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters\RefusePasswordChange' {
    Force     = $true
    ValueName = 'RefusePasswordChange'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters'
    ValueData = 0

  }

  xRegistry 'Registry(INF): HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters\RestrictNullSessAccess' {
    Force     = $true
    ValueName = 'RestrictNullSessAccess'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters'
    ValueData = 1

  }

  xRegistry 'Registry(INF): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableCAD' {
    Force     = $true
    ValueName = 'DisableCAD'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
    ValueData = 0

  }

  xRegistry 'Registry(INF): HKLM:\System\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM' {
    Force     = $true
    ValueName = 'RestrictAnonymousSAM'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Control\Lsa'
    ValueData = 1

  }

  xRegistry 'Registry(INF): HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters\DisableIPSourceRouting' {
    Force     = $true
    ValueName = 'DisableIPSourceRouting'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters'
    ValueData = 2

  }

  xRegistry 'Registry(INF): HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinServerSec' {
    Force     = $true
    ValueName = 'NTLMMinServerSec'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0'
    ValueData = 537395200

  }

  xRegistry 'Registry(INF): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLastUserName' {
    Force     = $true
    ValueName = 'DontDisplayLastUserName'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
    ValueData = 1

  }

  xRegistry 'Registry(INF): HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ScreenSaverGracePeriod' {
    Force     = $true
    ValueName = 'ScreenSaverGracePeriod'
    ValueType = 'String'
    Key       = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
    ValueData = '5'

  }

  xRegistry 'Registry(INF): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths' {
    Force     = $true
    ValueName = 'EnableSecureUIAPaths'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
    ValueData = 1

  }

  xRegistry 'Registry(INF): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\SupportedEncryptionTypes' {
    Force     = $true
    ValueName = 'SupportedEncryptionTypes'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'
    ValueData = 2147483644

  }

  xRegistry 'Registry(INF): HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters\enableforcedlogoff' {
    Force     = $true
    ValueName = 'enableforcedlogoff'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters'
    ValueData = 1

  }

  xRegistry 'Registry(INF): HKLM:\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers\AddPrinterDrivers' {
    Force     = $true
    ValueName = 'AddPrinterDrivers'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers'
    ValueData = 1

  }

  xRegistry 'Registry(INF): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection' {
    Force     = $true
    ValueName = 'EnableInstallerDetection'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
    ValueData = 1

  }

  xRegistry 'Registry(INF): HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters\maximumpasswordage' {
    Force     = $true
    ValueName = 'maximumpasswordage'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters'
    ValueData = 30

  }

  xRegistry 'Registry(INF): HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\SafeDllSearchMode' {
    Force     = $true
    ValueName = 'SafeDllSearchMode'
    ValueType = 'Dword'
    Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
    ValueData = 1

  }

  xRegistry 'Registry(INF): HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AllocateDASD' {
    Force     = $true
    ValueName = 'AllocateDASD'
    ValueType = 'String'
    Key       = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
    ValueData = '0'

  }

  xRegistry 'Registry(INF): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization' {
    Force     = $true
    ValueName = 'EnableVirtualization'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
    ValueData = 1

  }

  xRegistry 'Registry(INF): HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters\sealsecurechannel' {
    Force     = $true
    ValueName = 'sealsecurechannel'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters'
    ValueData = 1

  }

  xRegistry 'Registry(INF): HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters\disablepasswordchange' {
    Force     = $true
    ValueName = 'disablepasswordchange'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters'
    ValueData = 0

  }

  xRegistry 'Registry(INF): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeText' {
    Force     = $true
    ValueName = 'LegalNoticeText'
    ValueType = 'String'
    Key       = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
    ValueData = 'This computer system (including all hardware software and peripheral equipment) is the property of Ernst & Young. Use of this computer is restricted to official Ernst & Young business. Ernst & Young reserves the right to monitor use of the computer system at any time. Use of this computer system constitutes consent to such monitoring. Any unauthorized access use or modification of the computer system can result in disciplinary action civil liability or criminal penalties.'

  }

  xRegistry 'Registry(INF): HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\DisableIPSourceRouting' {
    Force     = $true
    ValueName = 'DisableIPSourceRouting'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters'
    ValueData = 2

  }

  xRegistry 'Registry(INF): HKLM:\System\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity' {
    Force     = $true
    ValueName = 'LDAPServerIntegrity'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Services\NTDS\Parameters'
    ValueData = 2

  }

  xRegistry 'Registry(INF): HKLM:\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel' {
    Force     = $true
    ValueName = 'LmCompatibilityLevel'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Control\Lsa'
    ValueData = 5

  }

  xRegistry 'Registry(INF): HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnablePlainTextPassword' {
    Force     = $true
    ValueName = 'EnablePlainTextPassword'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters'
    ValueData = 0

  }

  xRegistry 'Registry(INF): HKLM:\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse' {
    Force     = $true
    ValueName = 'LimitBlankPasswordUse'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Control\Lsa'
    ValueData = 1

  }

  xRegistry 'Registry(INF): HKLM:\System\CurrentControlSet\Control\Session Manager\ProtectionMode' {
    Force     = $true
    ValueName = 'ProtectionMode'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Control\Session Manager'
    ValueData = 1

  }

  xRegistry 'Registry(INF): HKLM:\System\CurrentControlSet\Control\Lsa\ForceGuest' {
    Force     = $true
    ValueName = 'ForceGuest'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Control\Lsa'
    ValueData = 0

  }

  xRegistry 'Registry(INF): HKLM:\System\CurrentControlSet\Control\Lsa\NoLMHash' {
    Force     = $true
    ValueName = 'NoLMHash'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Control\Lsa'
    ValueData = 1

  }

  xRegistry 'Registry(INF): HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\PasswordExpiryWarning' {
    Force     = $true
    ValueName = 'PasswordExpiryWarning'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
    ValueData = 14

  }

  xRegistry 'Registry(INF): HKLM:\Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers\AuthenticodeEnabled' {
    Force     = $true
    ValueName = 'AuthenticodeEnabled'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers'
    ValueData = 1

  }

  xRegistry 'Registry(INF): HKLM:\System\CurrentControlSet\Services\LDAP\LDAPClientIntegrity' {
    Force     = $true
    ValueName = 'LDAPClientIntegrity'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Services\LDAP'
    ValueData = 1

  }

  xRegistry 'Registry(INF): HKLM:\System\CurrentControlSet\Control\Lsa\SubmitControl' {
    Force     = $true
    ValueName = 'SubmitControl'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Control\Lsa'
    ValueData = 0

  }

  xRegistry 'Registry(INF): HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AutoAdminLogon' {
    Force     = $true
    ValueName = 'AutoAdminLogon'
    ValueType = 'String'
    Key       = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
    ValueData = '0'

  }

  xRegistry 'Registry(INF): HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters\requiresignorseal' {
    Force     = $true
    ValueName = 'requiresignorseal'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters'
    ValueData = 1

  }

  xRegistry 'Registry(INF): HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole\setcommand' {
    Force     = $true
    ValueName = 'setcommand'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole'
    ValueData = 0

  }

  xRegistry 'Registry(INF): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\ShutdownWithoutLogon' {
    Force     = $true
    ValueName = 'ShutdownWithoutLogon'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
    ValueData = 0

  }

  xRegistry 'Registry(INF): HKLM:\System\CurrentControlSet\Control\Lsa\FullPrivilegeAuditing' {
    Force     = $true
    ValueName = 'FullPrivilegeAuditing'
    ValueType = 'Binary'
    Key       = 'HKLM:\System\CurrentControlSet\Control\Lsa'
    ValueData = '1'

  }

  xRegistry 'Registry(INF): HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters\autodisconnect' {
    Force     = $true
    ValueName = 'autodisconnect'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters'
    ValueData = 15

  }

  xRegistry 'Registry(INF): HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0\allownullsessionfallback' {
    Force     = $true
    ValueName = 'allownullsessionfallback'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0'
    ValueData = 0

  }

  xRegistry 'Registry(INF): HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security\WarningLevel' {
    Force     = $true
    ValueName = 'WarningLevel'
    ValueType = 'Dword'
    Key       = 'HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security'
    ValueData = 90

  }

  xRegistry 'Registry(INF): HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole\securitylevel' {
    Force     = $true
    ValueName = 'securitylevel'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole'
    ValueData = 0

  }

  xRegistry 'Registry(INF): HKLM:\System\CurrentControlSet\Control\Lsa\RestrictAnonymous' {
    Force     = $true
    ValueName = 'RestrictAnonymous'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Control\Lsa'
    ValueData = 1

  }

  xRegistry 'Registry(INF): HKLM:\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous' {
    Force     = $true
    ValueName = 'EveryoneIncludesAnonymous'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Control\Lsa'
    ValueData = 0

  }

  xRegistry 'Registry(INF): HKLM:\System\CurrentControlSet\Control\Session Manager\Kernel\ObCaseInsensitive' {
    Force     = $true
    ValueName = 'ObCaseInsensitive'
    ValueType = 'Dword'
    Key       = 'HKLM:\System\CurrentControlSet\Control\Session Manager\Kernel'
    ValueData = 1

  }

  xRegistry 'Registry(INF): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser' {
    Force     = $true
    ValueName = 'ConsentPromptBehaviorUser'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
    ValueData = 3

  }

  UserRightsAssignment 'UserRightsAssignment(INF): Load_and_unload_device_drivers' {
    Policy   = 'Load_and_unload_device_drivers'
    Force    = $True
    Identity = @('*S-1-5-32-544'
    )

  }

  UserRightsAssignment 'UserRightsAssignment(INF): Impersonate_a_client_after_authentication' {
    Policy   = 'Impersonate_a_client_after_authentication'
    Force    = $True
    Identity = @('*S-1-5-32-544', '*S-1-5-6', '*S-1-5-19', '*S-1-5-20'
    )

  }

  UserRightsAssignment 'UserRightsAssignment(INF): Shut_down_the_system' {
    Policy   = 'Shut_down_the_system'
    Force    = $True
    Identity = @('*S-1-5-32-544'
    )

  }

  UserRightsAssignment 'UserRightsAssignment(INF): Take_ownership_of_files_or_other_objects' {
    Policy   = 'Take_ownership_of_files_or_other_objects'
    Force    = $True
    Identity = @('*S-1-5-32-544'
    )

  }

  UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_locally' {
    Policy   = 'Deny_log_on_locally'
    Force    = $True
    Identity = @('*S-1-5-32-546'
    )

  }

  UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_as_a_batch_job' {
    Policy   = 'Deny_log_on_as_a_batch_job'
    Force    = $True
    Identity = @('*S-1-5-32-546'
    )

  }

  UserRightsAssignment 'UserRightsAssignment(INF): Back_up_files_and_directories' {
    Policy   = 'Back_up_files_and_directories'
    Force    = $True
    Identity = @('*S-1-5-32-544'
    )

  }

  UserRightsAssignment 'UserRightsAssignment(INF): Access_Credential_Manager_as_a_trusted_caller' {
    Policy   = 'Access_Credential_Manager_as_a_trusted_caller'
    Force    = $True
    Identity = @(''
    )

  }

  UserRightsAssignment 'UserRightsAssignment(INF): Allow_log_on_through_Remote_Desktop_Services' {
    Policy   = 'Allow_log_on_through_Remote_Desktop_Services'
    Force    = $True
    Identity = @('*S-1-5-32-544', '*S-1-5-32-555'
    )

  }

  UserRightsAssignment 'UserRightsAssignment(INF): Modify_an_object_label' {
    Policy   = 'Modify_an_object_label'
    Force    = $True
    Identity = @(''
    )

  }

  UserRightsAssignment 'UserRightsAssignment(INF): Create_symbolic_links' {
    Policy   = 'Create_symbolic_links'
    Force    = $True
    Identity = @('*S-1-5-32-544'
    )

  }

  UserRightsAssignment 'UserRightsAssignment(INF): Change_the_system_time' {
    Policy   = 'Change_the_system_time'
    Force    = $True
    Identity = @('*S-1-5-19', '*S-1-5-32-544'
    )

  }

  UserRightsAssignment 'UserRightsAssignment(INF): Debug_programs' {
    Policy   = 'Debug_programs'
    Force    = $True
    Identity = @('*S-1-5-32-544'
    )

  }

  UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_through_Remote_Desktop_Services' {
    Policy   = 'Deny_log_on_through_Remote_Desktop_Services'
    Force    = $True
    Identity = @('*S-1-5-32-546', 'NT AUTHORITY\Local Account'
    )

  }

  UserRightsAssignment 'UserRightsAssignment(INF): Lock_pages_in_memory' {
    Policy   = 'Lock_pages_in_memory'
    Force    = $True
    Identity = @(''
    )

  }

  UserRightsAssignment 'UserRightsAssignment(INF): Manage_auditing_and_security_log' {
    Policy   = 'Manage_auditing_and_security_log'
    Force    = $True
    Identity = @('*S-1-5-32-544'
    )

  }

  UserRightsAssignment 'UserRightsAssignment(INF): Increase_scheduling_priority' {
    Policy   = 'Increase_scheduling_priority'
    Force    = $True
    Identity = @('*S-1-5-32-544'
    )

  }

  UserRightsAssignment 'UserRightsAssignment(INF): Change_the_time_zone' {
    Policy   = 'Change_the_time_zone'
    Force    = $True
    Identity = @('*S-1-5-19', '*S-1-5-32-544'
    )

  }

  UserRightsAssignment 'UserRightsAssignment(INF): Allow_log_on_locally' {
    Policy   = 'Allow_log_on_locally'
    Force    = $True
    Identity = @('*S-1-5-32-544'
    )

  }

  UserRightsAssignment 'UserRightsAssignment(INF): Create_a_pagefile' {
    Policy   = 'Create_a_pagefile'
    Force    = $True
    Identity = @('*S-1-5-32-544'
    )

  }

  UserRightsAssignment 'UserRightsAssignment(INF): Restore_files_and_directories' {
    Policy   = 'Restore_files_and_directories'
    Force    = $True
    Identity = @('*S-1-5-32-544', '*S-1-5-32-551'
    )

  }

  UserRightsAssignment 'UserRightsAssignment(INF): Create_a_token_object' {
    Policy   = 'Create_a_token_object'
    Force    = $True
    Identity = @(''
    )

  }

  UserRightsAssignment 'UserRightsAssignment(INF): Create_permanent_shared_objects' {
    Policy   = 'Create_permanent_shared_objects'
    Force    = $True
    Identity = @(''
    )

  }

  UserRightsAssignment 'UserRightsAssignment(INF): Profile_system_performance' {
    Policy   = 'Profile_system_performance'
    Force    = $True
    Identity = @('*S-1-5-32-544', 'NT SERVICE\WdiServiceHost'
    )

  }

  UserRightsAssignment 'UserRightsAssignment(INF): Create_global_objects' {
    Policy   = 'Create_global_objects'
    Force    = $True
    Identity = @('*S-1-5-32-544', '*S-1-5-6', '*S-1-5-19', '*S-1-5-20'
    )

  }

  UserRightsAssignment 'UserRightsAssignment(INF): Synchronize_directory_service_data' {
    Policy   = 'Synchronize_directory_service_data'
    Force    = $True
    Identity = @(''
    )

  }

  UserRightsAssignment 'UserRightsAssignment(INF): Adjust_memory_quotas_for_a_process' {
    Policy   = 'Adjust_memory_quotas_for_a_process'
    Force    = $True
    Identity = @('*S-1-5-32-544', '*S-1-5-19', '*S-1-5-20'
    )

  }

  UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_as_a_service' {
    Policy   = 'Deny_log_on_as_a_service'
    Force    = $True
    Identity = @('*S-1-5-32-546'
    )

  }

  UserRightsAssignment 'UserRightsAssignment(INF): Replace_a_process_level_token' {
    Policy   = 'Replace_a_process_level_token'
    Force    = $True
    Identity = @('*S-1-5-19', '*S-1-5-20'
    )

  }

  UserRightsAssignment 'UserRightsAssignment(INF): Enable_computer_and_user_accounts_to_be_trusted_for_delegation' {
    Policy   = 'Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
    Force    = $True
    Identity = @('*S-1-5-32-544'
    )

  }

  UserRightsAssignment 'UserRightsAssignment(INF): Force_shutdown_from_a_remote_system' {
    Policy   = 'Force_shutdown_from_a_remote_system'
    Force    = $True
    Identity = @('*S-1-5-32-544'
    )

  }

  UserRightsAssignment 'UserRightsAssignment(INF): Access_this_computer_from_the_network' {
    Policy   = 'Access_this_computer_from_the_network'
    Force    = $True
    Identity = @('*S-1-5-32-544', '*S-1-5-11', '*S-1-5-9'
    )

  }

  UserRightsAssignment 'UserRightsAssignment(INF): Deny_access_to_this_computer_from_the_network' {
    Policy   = 'Deny_access_to_this_computer_from_the_network'
    Force    = $True
    Identity = @('*S-1-5-32-546', 'NT AUTHORITY\Local Account'
    )

  }

  UserRightsAssignment 'UserRightsAssignment(INF): Perform_volume_maintenance_tasks' {
    Policy   = 'Perform_volume_maintenance_tasks'
    Force    = $True
    Identity = @('*S-1-5-32-544'
    )

  }

  UserRightsAssignment 'UserRightsAssignment(INF): Act_as_part_of_the_operating_system' {
    Policy   = 'Act_as_part_of_the_operating_system'
    Force    = $True
    Identity = @(''
    )

  }

  UserRightsAssignment 'UserRightsAssignment(INF): Generate_security_audits' {
    Policy   = 'Generate_security_audits'
    Force    = $True
    Identity = @('*S-1-5-19', '*S-1-5-20'
    )

  }

  UserRightsAssignment 'UserRightsAssignment(INF): Profile_single_process' {
    Policy   = 'Profile_single_process'
    Force    = $True
    Identity = @('*S-1-5-32-544'
    )

  }

  UserRightsAssignment 'UserRightsAssignment(INF): Modify_firmware_environment_values' {
    Policy   = 'Modify_firmware_environment_values'
    Force    = $True
    Identity = @('*S-1-5-32-544'
    )

  }

  UserRightsAssignment 'UserRightsAssignment(INF): Add_workstations_to_domain' {
    Policy   = 'Add_workstations_to_domain'
    Force    = $True
    Identity = @('*S-1-5-32-544'
    )

  }

  SecurityOption 'SecuritySetting(INF): NewAdministratorName' {
    Accounts_Rename_administrator_account = 'BukowCh'
    Name                                  = 'Accounts_Rename_administrator_account'

  }

  SecurityOption 'SecuritySetting(INF): LSAAnonymousNameLookup' {
    Name                                                = 'Network_access_Allow_anonymous_SID_Name_translation'
    Network_access_Allow_anonymous_SID_Name_translation = 'Disabled'

  }

  SecurityOption 'SecuritySetting(INF): ForceLogoffWhenHourExpire' {
    Name                                                  = 'Network_security_Force_logoff_when_logon_hours_expire'
    Network_security_Force_logoff_when_logon_hours_expire = 'Enabled'

  }

  AccountPolicy 'SecuritySetting(INF): LockoutBadCount' {
    Name                      = 'Account_lockout_threshold'
    Account_lockout_threshold = 10

  }

  SecurityOption 'SecuritySetting(INF): NewGuestName' {
    Accounts_Rename_guest_account = 'NewGst'
    Name                          = 'Accounts_Rename_guest_account'

  }

  SecurityOption 'SecuritySetting(INF): LANManagerAuthenticationLevel' {
    Network_security_LAN_Manager_authentication_level = 'Send NTLMv2 responses only. Refuse LM & NTLM'
    Name                          = 'Network_security_LAN_Manager_authentication_level'

  } 
  #endregion

  #region "Protocol/Ciphers/Hashes Configuration"
  ForEach ($Protocol In $DisabledProtocols) {
    xRegistry "Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocol\Server\Enabled" {
      Force     = $true
      ValueName = 'Enabled'
      ValueType = 'Dword'
      Key       = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocol\Server"
      ValueData = 0
    }

    xRegistry "Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocol\Server\DisabledByDefault" {
      Force     = $true
      ValueName = 'DisabledByDefault'
      ValueType = 'Dword'
      Key       = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocol\Server"
      ValueData = 1
    }
  }

  ForEach ($Protocol In $EnabledProtocols) {
    xRegistry "Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocol\Server\Enabled" {
      Force     = $true
      ValueName = 'Enabled'
      ValueType = 'Dword'
      Key       = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocol\Server"
      ValueData = "0xffffffff"
      Hex = $true
    }

    xRegistry "Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocol\Server\DisabledByDefault" {
      Force     = $true
      ValueName = 'DisabledByDefault'
      ValueType = 'Dword'
      Key       = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocol\Server"
      ValueData = 0
    }
  }

  ForEach ($Cipher In $DisabledCiphers) {
    xRegistry "Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$Cipher\Enabled" {
      Force     = $true
      ValueName = 'Enabled'
      ValueType = 'Dword'
      Key       = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$Cipher"
      ValueData = 0
    }
  }

  ForEach ($Cipher In $EnabledCiphers) {
    xRegistry "Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$Cipher\Enabled" {
      Force     = $true
      ValueName = 'Enabled'
      ValueType = 'Dword'
      Key       = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$Cipher"
      ValueData = "0xffffffff"
      Hex = $true
    }
  }

  ForEach ($Hash In $DisabledHashes) {
    xRegistry "Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\$Hash\Enabled" {
      Force     = $true
      ValueName = 'Enabled'
      ValueType = 'Dword'
      Key       = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\$Hash"
      ValueData = 0
    }
  }

  ForEach ($Hash In $EnabledHashes) {
    xRegistry "Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\$Hash\Enabled" {
      Force     = $true
      ValueName = 'Enabled'
      ValueType = 'Dword'
      Key       = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\$Hash"
      ValueData = "0xffffffff"
      Hex = $true
    }
  }

  ForEach ($KEA In $DisabledKeyExchangeAlgorithms) {
    xRegistry "Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\$KEA\Enabled" {
      Force     = $true
      ValueName = 'Enabled'
      ValueType = 'Dword'
      Key       = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\$KEA"
      ValueData = 0
    }
  }

  ForEach ($KEA In $EnabledKeyExchangeAlgorithms) {
    xRegistry "Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\$KEA\Enabled" {
      Force     = $true
      ValueName = 'Enabled'
      ValueType = 'Dword'
      Key       = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\$KEA"
      ValueData = "0xffffffff"
      Hex = $true
    }
  }

  xRegistry Crypto_SHA1_Flags {
    Ensure = "Present"
    Key = "HKLM:\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CertDllCreateCertificateChainEngine\Config"
    ValueName = "WeakSha1ThirdPartyFlags"
    ValueData = "0x80800000"
    ValueType = "Dword"
    Hex = $true
    Force = $true
  }

  xRegistry Crypto_SHA1_AfterTime {
    Ensure = "Present"
    Key = "HKLM:\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CertDllCreateCertificateChainEngine\Config"
    ValueName = "WeakSha1ThirdPartyAfterTime"
    ValueData = "0018df076244d101"
    ValueType = "Binary"
    Force = $true
  }
  #endregion

  #region "Limit Dynamic RPC port ranges to 49152-49651"
  xRegistry "Registry: HKLM:\Software\Microsoft\RPC\Internet\PortsInternetAvailable" {
    Force     = $true
    ValueName = 'PortsInternetAvailable'
    ValueType = 'String'
    Key       = "HKLM:\Software\Microsoft\RPC\Internet"
    ValueData = "Y"
  }

  xRegistry "Registry: HKLM:\Software\Microsoft\RPC\Internet\UseInternetPorts" {
    Force     = $true
    ValueName = 'UseInternetPorts'
    ValueType = 'String'
    Key       = "HKLM:\Software\Microsoft\RPC\Internet"
    ValueData = "Y"
  }

  xRegistry "Registry: HKLM:\Software\Microsoft\RPC\Internet\Ports" {
    Force     = $true
    ValueName = 'Ports'
    ValueType = 'MultiString'
    Key       = "HKLM:\Software\Microsoft\RPC\Internet"
    ValueData = @("49152-49651")
  }

  Script "Script: Set TCP Dynamic Port Range" {
    GetScript = {
      $NetTcpSetting = Get-NetTcpSetting -SettingName InternetCustom
      return @{
        "Result" = $NetTcpSetting.DynamicPortRangeStartPort -eq 49152 -and $NetTcpSetting.DynamicPortRangeNumberOfPorts -eq 500;
        "DynamicPortRangeStartPort" = $NetTcpSetting.DynamicPortRangeStartPort;
        "DynamicPortRangeNumberOfPorts" = $NetTcpSetting.DynamicPortRangeNumberOfPorts
      }
    }
    TestScript = {
      $NetTcpSetting = Get-NetTcpSetting -SettingName InternetCustom
      return $NetTcpSetting.DynamicPortRangeStartPort -eq 49152 -and $NetTcpSetting.DynamicPortRangeNumberOfPorts -eq 500
    }
    SetScript = {
      Set-NetTcpSetting -SettingName InternetCustom -DynamicPortRangeStartPort 49152 -DynamicPortRangeNumberOfPorts 500
    }
  }

  Script "Script: Set UDP Dynamic Port Range" {
    GetScript = {
      $NetUdpSetting = Get-NetUdpSetting
      return @{
        "Result" = $NetUdpSetting.DynamicPortRangeStartPort -eq 49152 -and $NetUdpSetting.DynamicPortRangeNumberOfPorts -eq 500;
        "DynamicPortRangeStartPort" = $NetUdpSetting.DynamicPortRangeStartPort;
        "DynamicPortRangeNumberOfPorts" = $NetUdpSetting.DynamicPortRangeNumberOfPorts
      }
    }
    TestScript = {
      $NetUdpSetting = Get-NetUdpSetting
      return $NetUdpSetting.DynamicPortRangeStartPort -eq 49152 -and $NetUdpSetting.DynamicPortRangeNumberOfPorts -eq 500
    }
    SetScript = {
      Set-NetUdpSetting -DynamicPortRangeStartPort 49152 -DynamicPortRangeNumberOfPorts 500
    }
  }
  #endregion

  #region "Set AD Port Standards"
  xRegistry "Registry: HKLM:\SYSTEM\CurrentControlSet\services\Netlogon\Parameters\DCTcpipPort" {
    Force     = $true
    ValueName = 'DCTcpipPort'
    ValueType = 'DWord'
    Key       = "HKLM:\SYSTEM\CurrentControlSet\services\Netlogon\Parameters"
    ValueData = 50005
  }

  xRegistry "Registry: HKLM:\SYSTEM\CurrentControlSet\services\NTDS\Parameters\TCP/IP Port" {
    Force     = $true
    ValueName = 'TCP/IP Port'
    ValueType = 'DWord'
    Key       = "HKLM:\SYSTEM\CurrentControlSet\services\NTDS\Parameters"
    ValueData = 50000
  }

  xRegistry "Registry: HKLM:\SYSTEM\CurrentControlSet\services\NtFrs\Parameters\RPC TCP/IP Port Assignment" {
    Force     = $true
    ValueName = 'RPC TCP/IP Port Assignment'
    ValueType = 'DWord'
    Key       = "HKLM:\SYSTEM\CurrentControlSet\services\NtFrs\Parameters"
    ValueData = 60000
  }
  #endregion

  #region "Extra Settings"
  xRegistry RDP_EnableConnections
  {
      Ensure = "Present"
      Key = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
      ValueName = "fDenyTSConnections"
      ValueData = "0"
      ValueType = "Dword"
      Force = $true
  }

  xRegistry RDP_SingleSessionPerUser
  {
      Ensure = "Present"
      Key = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
      ValueName = "fSingleSessionPerUser"
      ValueData = "0x1"
      ValueType = "Dword"
      Hex = $true
      Force = $true
  }

  xRegistry RDP_MinEncryptionLevel
  {
      Ensure = "Present"
      Key = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
      ValueName = "MinEncryptionLevel"
      ValueData = "0x3"
      ValueType = "Dword"
      Hex = $true
      Force = $true
  }

  xRegistry RDP_SecurityLayer
  {
      Ensure = "Present"
      Key = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
      ValueName = "SecurityLayer"
      ValueData = "0x2"
      ValueType = "Dword"
      Hex = $true
      Force = $true
  }

  xRegistry dotnet2_SchUseStrongCrypto_x64
  {
      Ensure = "Present"
      Key = "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727"
      ValueName = "SchUseStrongCrypto"
      ValueData = "0x1"
      ValueType = "Dword"
      Hex = $true
      Force = $true
  }

  xRegistry dotnet2_SchUseStrongCrypto_x86
  {
      Ensure = "Present"
      Key = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727"
      ValueName = "SchUseStrongCrypto"
      ValueData = "0x1"
      ValueType = "Dword"
      Hex = $true
      Force = $true
  }

  xRegistry dotnet4_SchUseStrongCrypto_x64
  {
      Ensure = "Present"
      Key = "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319"
      ValueName = "SchUseStrongCrypto"
      ValueData = "0x1"
      ValueType = "Dword"
      Hex = $true
      Force = $true
  }

  xRegistry dotnet4_SchUseStrongCrypto_x86
  {
      Ensure = "Present"
      Key = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319"
      ValueName = "SchUseStrongCrypto"
      ValueData = "0x1"
      ValueType = "Dword"
      Hex = $true
      Force = $true
  }
  #endregion

  # xWindowsOptionalFeatureSet RemoveGUI {
  #   Name = @('Server-Gui-Mgmt','Server-Gui-Shell')
  #   RemoveFilesOnDisable = $true
  #   Ensure = 'Absent'
  # }
}