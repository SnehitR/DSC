Configuration EY_W2K16_Member_ExtraSettings
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
  
  xRegistry "Registry(Reg) - HKLM:\Software\Policies\Microsoft\Windows\LanmanWorkstation\AllowInsecureGuestAuth " {
    ValueName = 'AllowInsecureGuestAuth'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\LanmanWorkstation'
    ValueData = 0 # 0=Disabled
    Force     = $true
  }

  xRegistry "Registry(Reg) - HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableAutomaticRestartSignOn " {
    ValueName = 'DisableAutomaticRestartSignOn'
    ValueType = 'Dword'
    Key       = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
    ValueData = 1 # 1=Disabled
    Force     = $true
  }

  $valueData = '00000002' #ValueData for HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains\localhost_*
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains\localhost_* " {
    Key       = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains\localhost'
    ValueName = '*'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  $valueData = '00000002' #ValueData for HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains\localhost_*
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains\localhost_* " {
    Key       = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains\localhost'
    ValueName = '*'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  $valueData = '00000002' #ValueData for HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\localhost_*
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\localhost_* " {
    Key       = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\localhost'
    ValueName = '*'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  $valueData = '00000002' #ValueData for HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\localhost_*
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\localhost_* " {
    Key       = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\localhost'
    ValueName = '*'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  $valueData = '00000001' #ValueData for HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat_DisablePropPage
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat_DisablePropPage " {
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat'
    ValueName = 'DisablePropPage' ## 
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  $valueData = '00000000' #ValueData for HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat_AITEnable
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat_AITEnable " {
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat'
    ValueName = 'AITEnable'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $false
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  $valueData = '00000001' #ValueData for HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat_DisablePCA
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat_DisablePCA " {
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat'
    ValueName = 'DisablePCA'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  $valueData = '00000001' #ValueData for HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat_DisableInventory
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat_DisableInventory " {
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat'
    ValueName = 'DisableInventory'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  $valueData = '00000001' #ValueData for HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization_NoLockScreenSlideshow
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization_NoLockScreenSlideshow " {
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization'
    ValueName = 'NoLockScreenSlideshow'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  $valueData = '00000001' #ValueData for HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization_NoLockScreenCamera
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization_NoLockScreenCamera " {
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization'
    ValueName = 'NoLockScreenCamera'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  $valueData = 'C:\\Windows\\Web\\Screen\\img100.jpg' #ValueData for HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization_LockScreenImage
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization_LockScreenImage " {
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization'
    ValueName = 'LockScreenImage'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $false
    ValueData = $valueData 
    ValueType = 'String'
  }

  $valueData = '00000000' #ValueData for HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization_NoChangingLockScreen
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization_NoChangingLockScreen " {
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization'
    ValueName = 'NoChangingLockScreen'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $false
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  $valueData = '00000001' #ValueData for HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging_EnableModuleLogging
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging_EnableModuleLogging " {
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
    ValueName = 'EnableModuleLogging'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  $valueData = '*' #ValueData for HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames_*
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames_* " {
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames'
    ValueName = '*'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $false
    ValueData = $valueData 
    ValueType = 'String'
  }

  $valueData = '00000001' #ValueData for HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging_EnableScriptBlockLogging
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging_EnableScriptBlockLogging " {
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    ValueName = 'EnableScriptBlockLogging'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  $valueData = '00000001' #ValueData for HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging_EnableScriptBlockInvocationLogging
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging_EnableScriptBlockInvocationLogging " {
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    ValueName = 'EnableScriptBlockInvocationLogging'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  $valueData = '00000001' #ValueData for HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription_EnableTranscripting
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription_EnableTranscripting " {
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
    ValueName = 'EnableTranscripting'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  $valueData = 'C:\\Windows\\Logs\\PowerShellTranscription' #ValueData for HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription_OutputDirectory
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription_OutputDirectory " {
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
    ValueName = 'OutputDirectory'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $false
    ValueData = $valueData 
    ValueType = 'String'
  }

  $valueData = '00000001' #ValueData for HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription_EnableInvocationHeader
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription_EnableInvocationHeader " {
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
    ValueName = 'EnableInvocationHeader'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  $valueData = '00000001' #ValueData for HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU_NoAutoUpdate
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU_NoAutoUpdate " {
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
    ValueName = 'NoAutoUpdate'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  $valueData = '00000001' #ValueData for HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU_NoAutoRebootWithLoggedOnUsers
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU_NoAutoRebootWithLoggedOnUsers " {
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
    ValueName = 'NoAutoRebootWithLoggedOnUsers'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  $valueData = '000000B4' #ValueData for HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU_Re-prompt for restart with scheduled installations
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU_Re-prompt for restart with scheduled installations " {
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
    ValueName = 'Re-prompt for restart with scheduled installations'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  #  -- OEM and Microsoft web links within the performance control panel page are not displayed. The administrative tools will not be affected. 
  $valueData = '00000000' #ValueData for HKLM:\Software\Policies\Microsoft\Windows\Control Panel\Performance Control Panel_UpsellEnabled
  xRegistry "Registry(Reg) - HKLM:\Software\Policies\Microsoft\Windows\Control Panel\Performance Control Panel_UpsellEnabled " {
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\Control Panel\Performance Control Panel'
    ValueName = 'UpsellEnabled'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $false
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  #  -- Removes access to the performance center control panel page. 
  $valueData = '00000000' #ValueData for HKLM:\Software\Policies\Microsoft\Windows\Control Panel\Performance Control Panel_PerfCplEnabled
  xRegistry "Registry(Reg) - HKLM:\Software\Policies\Microsoft\Windows\Control Panel\Performance Control Panel_PerfCplEnabled " {
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\Control Panel\Performance Control Panel'
    ValueName = 'PerfCplEnabled'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $false
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  #  -- Removes access to the performance center control panel solutions to performance problems.
  $valueData = '00000000' #ValueData for HKLM:\Software\Policies\Microsoft\Windows\Control Panel\Performance Control Panel_SolutionsEnabled
  xRegistry "Registry(Reg) - HKLM:\Software\Policies\Microsoft\Windows\Control Panel\Performance Control Panel_SolutionsEnabled " {
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\Control Panel\Performance Control Panel'
    ValueName = 'SolutionsEnabled'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $false
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  #  -- The handwriting recognition error reporting tool enables users to report errors encountered in Tablet PC Input Panel. The tool generates error reports and transmits them to Microsoft over a secure connection. Microsoft uses these error reports to improve handwriting recognition in future versions of Windows.
  $valueData = '00000001' #ValueData for HKLM:\Software\Policies\Microsoft\Windows\HandwritingErrorReports_PreventHandwritingErrorReports
  xRegistry "Registry(Reg) - HKLM:\Software\Policies\Microsoft\Windows\HandwritingErrorReports_PreventHandwritingErrorReports " {
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\HandwritingErrorReports'
    ValueName = 'PreventHandwritingErrorReports'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  $valueData = '00000000' #ValueData for HKLM:\SOFTWARE\Policies\Microsoft\Camera_AllowCamera
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Policies\Microsoft\Camera_AllowCamera " {
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Camera'
    ValueName = 'AllowCamera'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $false
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  $valueData = '00000001' #ValueData for HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent_DisableWindowsConsumerFeatures
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent_DisableWindowsConsumerFeatures " {
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
    ValueName = 'DisableWindowsConsumerFeatures'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  $valueData = '00000001' #ValueData for HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent_DisableSoftLanding
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent_DisableSoftLanding " {
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
    ValueName = 'DisableSoftLanding'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  $valueData = '00000001' #ValueData for HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting_Disabled
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting_Disabled " {
    Key       = 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting'
    ValueName = 'Disabled'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  $valueData = '00000001' #ValueData for HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting_DontSendAdditionalData
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting_DontSendAdditionalData " {
    Key       = 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting'
    ValueName = 'DontSendAdditionalData'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  $valueData = '00000001' #ValueData for HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting_DontShowUI
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting_DontShowUI " {
    Key       = 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting'
    ValueName = 'DontShowUI'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  $valueData = '00000000' #ValueData for HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameUX_DownloadGameInfo
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameUX_DownloadGameInfo " {
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameUX'
    ValueName = 'DownloadGameInfo'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $false
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  $valueData = '00000000' #ValueData for HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameUX_ListRecentlyPlayed
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameUX_ListRecentlyPlayed " {
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameUX'
    ValueName = 'ListRecentlyPlayed'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $false
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  $valueData = '00000001' #ValueData for HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main_DisableFirstRunCustomize
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main_DisableFirstRunCustomize " {
    Key       = 'HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main'
    ValueName = 'DisableFirstRunCustomize'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  $valueData = '00000000' #ValueData for HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace_AllowWindowsInkWorkspace
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace_AllowWindowsInkWorkspace " {
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace'
    ValueName = 'AllowWindowsInkWorkspace'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $false
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  $valueData = '00000001' #ValueData for HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\MobilityCenter_NoMobilityCenter
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\MobilityCenter_NoMobilityCenter " {
    Key       = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\MobilityCenter'
    ValueName = 'NoMobilityCenter'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  $valueData = '00000001' #ValueData for HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive_DisableFileSyncNGSC
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive_DisableFileSyncNGSC " {
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive'
    ValueName = 'DisableFileSyncNGSC'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  $valueData = '00000001' #ValueData for HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive_DisableFileSync
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive_DisableFileSync " {
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive'
    ValueName = 'DisableFileSync'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  $valueData = '00000000' #ValueData for HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Security Center_SecurityCenterInDomain
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Security Center_SecurityCenterInDomain " {
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Security Center'
    ValueName = 'SecurityCenterInDomain'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $false
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  $valueData = '00000001' #ValueData for HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync_EnableBackupForWin8Apps
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync_EnableBackupForWin8Apps " {
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync'
    ValueName = 'EnableBackupForWin8Apps'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  $valueData = '00000002' #ValueData for HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync_DisableSettingSync
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync_DisableSettingSync " {
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync'
    ValueName = 'DisableSettingSync'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  $valueData = '00000001' #ValueData for HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync_DisableSettingSyncUserOverride
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync_DisableSettingSyncUserOverride " {
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync'
    ValueName = 'DisableSettingSyncUserOverride'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  $valueData = '00000001' #ValueData for HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore_DisableSR
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore_DisableSR " {
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore'
    ValueName = 'DisableSR'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  $valueData = '00000001' #ValueData for HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore_DisableConfig
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore_DisableConfig " {
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore'
    ValueName = 'DisableConfig'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  $valueData = '00000001' #ValueData for HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Windows_TurnOffWinCal
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Windows_TurnOffWinCal " {
    Key       = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Windows'
    ValueName = 'TurnOffWinCal'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  $valueData = '00000001' #ValueData for HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\UI_DisableWcnUi
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\UI_DisableWcnUi " {
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\UI'
    ValueName = 'DisableWcnUi'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  $valueData = '00000000' #ValueData for HKLM:\SOFTWARE\Policies\Microsoft\Windows Mail_ManualLaunchAllowed
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Policies\Microsoft\Windows Mail_ManualLaunchAllowed " {
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Mail'
    ValueName = 'ManualLaunchAllowed'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $false
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  $valueData = '00000000' #ValueData for HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore_DisableStoreApps
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore_DisableStoreApps " {
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore'
    ValueName = 'DisableStoreApps'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $false
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  $valueData = '00000001' #ValueData for HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore_RemoveWindowsStore
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore_RemoveWindowsStore " {
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore'
    ValueName = 'RemoveWindowsStore'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  $valueData = '00000000' #ValueData for HKLM:\SOFTWARE\Microsoft\Internet Explorer\AdvancedOptions\CRYPTO\SSLREV_DefaultValue
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Microsoft\Internet Explorer\AdvancedOptions\CRYPTO\SSLREV_DefaultValue " {
    Key       = 'HKLM:\SOFTWARE\Microsoft\Internet Explorer\AdvancedOptions\CRYPTO\SSLREV'
    ValueName = 'DefaultValue'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $false
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  $valueData = 'no' #ValueData for HKLM:\SOFTWARE\Microsoft\Internet Explorer\AdvancedOptions\BROWSE\FRIENDLY_ERRORS_DefaultValue
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Microsoft\Internet Explorer\AdvancedOptions\BROWSE\FRIENDLY_ERRORS_DefaultValue " {
    Key       = 'HKLM:\SOFTWARE\Microsoft\Internet Explorer\AdvancedOptions\BROWSE\FRIENDLY_ERRORS'
    ValueName = 'DefaultValue'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $false
    ValueData = $valueData 
    ValueType = 'String'
  }

  

  $valueData = '00000001' #ValueData for HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System_LocalAccountTokenFilterPolicy
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System_LocalAccountTokenFilterPolicy " {
    Key       = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    ValueName = 'LocalAccountTokenFilterPolicy'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  $valueData = '00000001' #ValueData for HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX_iexplore.exe
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX_iexplore.exe " {
    Key       = 'HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX'
    ValueName = 'iexplore.exe'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  $valueData = '00000001' #ValueData for HKLM:\SOFTWARE\Wow6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX_iexplore.exe
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Wow6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX_iexplore.exe " {
    Key       = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX'
    ValueName = 'iexplore.exe'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  $valueData = '00000000' #ValueData for HKLM:\Software\Policies\Microsoft\PCHealth\HelpSvc_Headlines
  xRegistry "Registry(Reg) - HKLM:\Software\Policies\Microsoft\PCHealth\HelpSvc_Headlines " {
    Key       = 'HKLM:\Software\Policies\Microsoft\PCHealth\HelpSvc'
    ValueName = 'Headlines'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $false
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  #  -- Specifies whether the Internet Connection Wizard can connect to Microsoft to download a list of Internet Service Providers (ISPs).
  $valueData = '00000001' #ValueData for HKLM:\Software\Policies\Microsoft\Windows\Internet Connection Wizard_ExitOnMSICW
  xRegistry "Registry(Reg) - HKLM:\Software\Policies\Microsoft\Windows\Internet Connection Wizard_ExitOnMSICW " {
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\Internet Connection Wizard'
    ValueName = 'ExitOnMSICW'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  #  -- Specifies whether to use the Microsoft Web service for finding an application to open a file with an unhandled file association.
  $valueData = '00000001' #ValueData for HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer_NoInternetOpenWith
  xRegistry "Registry(Reg) - HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer_NoInternetOpenWith " {
    Key       = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    ValueName = 'NoInternetOpenWith'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  #  -- Specifies whether the Windows Registration Wizard connects to Microsoft.com for online registration.
  $valueData = '00000001' #ValueData for HKLM:\Software\Policies\Microsoft\Windows\Registration Wizard Control_NoRegistration
  xRegistry "Registry(Reg) - HKLM:\Software\Policies\Microsoft\Windows\Registration Wizard Control_NoRegistration " {
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\Registration Wizard Control'
    ValueName = 'NoRegistration'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  #  -- Specifies whether the "Order Prints Online" task is available from Picture Tasks in Windows folders.
  $valueData = '00000001' #ValueData for HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer_NoOnlinePrintsWizard
  xRegistry "Registry(Reg) - HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer_NoOnlinePrintsWizard " {
    Key       = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    ValueName = 'NoOnlinePrintsWizard'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  $valueData = '00000001' #ValueData for HKLM:\SOFTWARE\Policies\Microsoft\Windows\HomeGroup_DisableHomeGroup
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Policies\Microsoft\Windows\HomeGroup_DisableHomeGroup " {
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\HomeGroup'
    ValueName = 'DisableHomeGroup'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  $valueData = '00000001' #ValueData for HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Security\ActiveX_BlockNonAdminActiveXInstall
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Security\ActiveX_BlockNonAdminActiveXInstall " {
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Security\ActiveX'
    ValueName = 'BlockNonAdminActiveXInstall'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  $valueData = '00000001' #ValueData for HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer_NoDisconnect
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer_NoDisconnect " {
    Key       = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    ValueName = 'NoDisconnect'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  $valueData = 'Open command window here - As Admin' #ValueData for HKCR:\Directory\shell\runas_
  xRegistry "Registry(Reg) - HKCR:\Directory\shell\runas_ " {
    Key       = 'HKCR:\Directory\shell\runas'
    ValueName = ''
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'String'
  }

  $valueData = '' #ValueData for HKCR:\Directory\shell\runas_Extended
  xRegistry "Registry(Reg) - HKCR:\Directory\shell\runas_Extended " {
    Key       = 'HKCR:\Directory\shell\runas'
    ValueName = 'Extended'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $false
    ValueData = $valueData 
    ValueType = 'String'
  }

  $valueData = '' #ValueData for HKCR:\Directory\shell\runas_NoWorkingDirectory
  xRegistry "Registry(Reg) - HKCR:\Directory\shell\runas_NoWorkingDirectory " {
    Key       = 'HKCR:\Directory\shell\runas'
    ValueName = 'NoWorkingDirectory'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $false
    ValueData = $valueData 
    ValueType = 'String'
  }

  $valueData = 'cmd.exe /s /k pushd \"%V\' #ValueData for HKCR:\Directory\shell\runas\command_
  xRegistry "Registry(Reg) - HKCR:\Directory\shell\runas\command_ " {
    Key       = 'HKCR:\Directory\shell\runas\command'
    ValueName = ''
    Ensure    = 'Present'
    Force     = $true
    Hex       = $false
    ValueData = $valueData 
    ValueType = 'String'
  }

  $valueData = 'Open command window here - As Admin' #ValueData for HKCR:\Directory\Background\shell\runas_
  xRegistry "Registry(Reg) - HKCR:\Directory\Background\shell\runas_ " {
    Key       = 'HKCR:\Directory\Background\shell\runas'
    ValueName = ''
    Ensure    = 'Present'
    Force     = $true
    Hex       = $false
    ValueData = $valueData 
    ValueType = 'String'
  }

  $valueData = '' #ValueData for HKCR:\Directory\Background\shell\runas_Extended
  xRegistry "Registry(Reg) - HKCR:\Directory\Background\shell\runas_Extended " {
    Key       = 'HKCR:\Directory\Background\shell\runas'
    ValueName = 'Extended'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $false
    ValueData = $valueData 
    ValueType = 'String'
  }

  $valueData = '' #ValueData for HKCR:\Directory\Background\shell\runas_NoWorkingDirectory
  xRegistry "Registry(Reg) - HKCR:\Directory\Background\shell\runas_NoWorkingDirectory " {
    Key       = 'HKCR:\Directory\Background\shell\runas'
    ValueName = 'NoWorkingDirectory'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $false
    ValueData = $valueData 
    ValueType = 'String'
  }

  $valueData = 'cmd.exe /s /k pushd \"%V\' #ValueData for HKCR:\Directory\Background\shell\runas\command_
  xRegistry "Registry(Reg) - HKCR:\Directory\Background\shell\runas\command_ " {
    Key       = 'HKCR:\Directory\Background\shell\runas\command'
    ValueName = ''
    Ensure    = 'Present'
    Force     = $true
    Hex       = $false
    ValueData = $valueData 
    ValueType = 'String'
  }

  $valueData = '00000001' #ValueData for HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters_MaxPacketSize
  xRegistry "Registry(Reg) - HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters_MaxPacketSize " {
    Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters'
    ValueName = 'MaxPacketSize'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  # 
  $valueData = '0000ffff' #ValueData for HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters_MaxTokenSize
  xRegistry "Registry(Reg) - HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters_MaxTokenSize " {
    Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters'
    ValueName = 'MaxTokenSize'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  $valueData = 'Ernst & Young' #ValueData for HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation_Manufacturer
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation_Manufacturer " {
    Key       = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation'
    ValueName = 'Manufacturer'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $false
    ValueData = $valueData 
    ValueType = 'String'
  }

  $valueData = 'C:\\Windows\\system32\\oemlogo.bmp' #ValueData for HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation_Logo
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation_Logo " {
    Key       = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation'
    ValueName = 'Logo'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $false
    ValueData = $valueData 
    ValueType = 'String'
  }

  #$valueData ='PowerShell.exe -NoExit -Command \"Set-Location $env:UserProfile\' #ValueData for HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\AlternateShells\AvailableShells_40000
  #xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\AlternateShells\AvailableShells_40000 "
  #{
  #    Key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\AlternateShells\AvailableShells'
  #    ValueName = '40000'
  #    Ensure = 'Present'
  #    Force = $true
  #    Hex = $false
  #    ValueData = $valueData 
  #    ValueType = 'String'
  #}

  $valueData = '00000000' #ValueData for HKLM:\Software\Microsoft\SQMClient\Windows_CEIPEnable
  xRegistry "Registry(Reg) - HKLM:\Software\Microsoft\SQMClient\Windows_CEIPEnable " {
    Key       = 'HKLM:\Software\Microsoft\SQMClient\Windows'
    ValueName = 'CEIPEnable'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $false
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  $valueData = '00000002' #ValueData for HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains\localhost_https
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains\localhost_https " {
    Key       = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains\localhost'
    ValueName = 'https'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  $valueData = '00000002' #ValueData for HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains\localhost_https
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains\localhost_https " {
    Key       = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains\localhost'
    ValueName = 'https'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  $valueData = '00000002' #ValueData for HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\localhost_https
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\localhost_https " {
    Key       = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\localhost'
    ValueName = 'https'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  $valueData = '00000002' #ValueData for HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\localhost_https
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\localhost_https " {
    Key       = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\localhost'
    ValueName = 'https'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  $valueData = 'edit' #ValueData for HKCR:\regfile\shell_
  xRegistry "Registry(Reg) - HKCR:\regfile\shell_ " {
    Key       = 'HKCR:\regfile\shell'
    ValueName = ''
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'String'
  }

  $valueData = 'Edit' #ValueData for HKCR:\VBSFile\Shell_
  xRegistry "Registry(Reg) - HKCR:\VBSFile\Shell_ " {
    Key       = 'HKCR:\VBSFile\Shell'
    ValueName = ''
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'String'
  }

  #  -- Disable all not required Windows Services
  $valueData = '00000004' #ValueData for HKLM:\SYSTEM\CurrentControlSet\Services\idsvc_Start
  xRegistry "Registry(Reg) - HKLM:\SYSTEM\CurrentControlSet\Services\idsvc_Start " {
    Key       = 'HKLM:\SYSTEM\CurrentControlSet\Services\idsvc'
    ValueName = 'Start'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  #$valueData ='00000004' #ValueData for HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend_Start
  #xRegistry "Registry(Reg) - HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend_Start "
  #{
  #    Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend'
  #    ValueName = 'Start'
  #    Ensure = 'Present'
  #    Force = $true
  #    Hex = $true
  #    ValueData = $valueData 
  #    ValueType = 'Dword'
  #}

  $valueData = '00000001' #ValueData for HKLM:\SYSTEM\CurrentControlSet\Services\WSearch_DelayedAutoStart
  xRegistry "Registry(Reg) - HKLM:\SYSTEM\CurrentControlSet\Services\WSearch_DelayedAutoStart " {
    Key       = 'HKLM:\SYSTEM\CurrentControlSet\Services\WSearch'
    ValueName = 'DelayedAutoStart'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  $valueData = '00000000' #ValueData for HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Privacy_EnableInPrivateBrowsing
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Privacy_EnableInPrivateBrowsing " {
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Privacy'
    ValueName = 'EnableInPrivateBrowsing'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $false
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  $valueData = '00000001' #ValueData for HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI_DisablePasswordReveal
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI_DisablePasswordReveal " {
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI'
    ValueName = 'DisablePasswordReveal'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  $valueData = '00000000' #ValueData for HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI_EnumerateAdministrators
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI_EnumerateAdministrators " {
    Key       = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI'
    ValueName = 'EnumerateAdministrators'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $false
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  $valueData = '00000001' #ValueData for HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System_EnableLinkedConnections
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System_EnableLinkedConnections " {
    Key       = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    ValueName = 'EnableLinkedConnections'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  $valueData = '00000001' #ValueData for HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings_Security_HKLM_Only
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings_Security_HKLM_Only " {
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
    ValueName = 'Security_HKLM_Only'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  $valueData = '00000001' #ValueData for HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings_Security_options_edit
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings_Security_options_edit " {
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
    ValueName = 'Security_options_edit'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  $valueData = '00000001' #ValueData for HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings_Security_zones_map_edit
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings_Security_zones_map_edit " {
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
    ValueName = 'Security_zones_map_edit'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  # Open files based on content, not file extension
  $valueData = '00000003' #ValueData for HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1_1601
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1_1601 " {
    Key       = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1'
    ValueName = '1601'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  # Submit non-encrypted form data  VAL: Enabled
  $valueData = '00000003' #ValueData for HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1_2100
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1_2100 " {
    Key       = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1'
    ValueName = '2100'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  $valueData = '00000001' #ValueData for HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Control Panel_FormSuggest Passwords
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Control Panel_FormSuggest Passwords " {
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Control Panel'
    ValueName = 'FormSuggest Passwords'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  #  -- Prevents Internet Explorer from checking whether a new version of the browser is available.
  $valueData = '00000001' #ValueData for HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Infodelivery\Restrictions_NoUpdateCheck
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Infodelivery\Restrictions_NoUpdateCheck " {
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Infodelivery\Restrictions'
    ValueName = 'NoUpdateCheck'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  #  -- Specifies that programs using the Microsoft Software Distribution Channel will not notify users when they install new components. The Software Distribution Channel is a means of updating software dynamically on users' computers by using Open Software Distribution (.osd) technologies.
  $valueData = '00000001' #ValueData for HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer_NoMSAppLogo5ChannelNotify
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer_NoMSAppLogo5ChannelNotify " {
    Key       = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    ValueName = 'NoMSAppLogo5ChannelNotify'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  #  -- Configures Internet Explorer to keep track of the pages viewed in the History List to 30 days.
  #  -- This setting specifies the number of days that Internet Explorer tracks views of pages in the History List. To access the Temporary Internet Files and History Settings dialog box, from the Menu bar, on the Tools menu, click Internet Options, click the General tab, and then click Settings under Browsing history. 
  $valueData = '00000001' #ValueData for HKLM:\Software\Policies\Microsoft\Internet Explorer\Control Panel_History
  xRegistry "Registry(Reg) - HKLM:\Software\Policies\Microsoft\Internet Explorer\Control Panel_History " {
    Key       = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Control Panel'
    ValueName = 'History'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  $valueData = '0000001e' #ValueData for HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Url History_DaysToKeep
  xRegistry "Registry(Reg) - HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Url History_DaysToKeep " {
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Url History'
    ValueName = 'DaysToKeep'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  #  -- This policy setting allows you to manage the crash detection feature of add-on Management.
  $valueData = 'no' #ValueData for HKLM:\Software\Microsoft\Internet Explorer\Main_Use FormSuggest
  xRegistry "Registry(Reg) - HKLM:\Software\Microsoft\Internet Explorer\Main_Use FormSuggest " {
    Key       = 'HKLM:\Software\Microsoft\Internet Explorer\Main'
    ValueName = 'Use FormSuggest'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $false
    ValueData = $valueData 
    ValueType = 'String'
  }

  $valueData = 'no' #ValueData for HKLM:\Software\Microsoft\Internet Explorer\Main_FormSuggest Passwords
  xRegistry "Registry(Reg) - HKLM:\Software\Microsoft\Internet Explorer\Main_FormSuggest Passwords " {
    Key       = 'HKLM:\Software\Microsoft\Internet Explorer\Main'
    ValueName = 'FormSuggest Passwords'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $false
    ValueData = $valueData 
    ValueType = 'String'
  }

  $valueData = 'no' #ValueData for HKLM:\Software\Microsoft\Internet Explorer\Main_FormSuggest PW Ask
  xRegistry "Registry(Reg) - HKLM:\Software\Microsoft\Internet Explorer\Main_FormSuggest PW Ask " {
    Key       = 'HKLM:\Software\Microsoft\Internet Explorer\Main'
    ValueName = 'FormSuggest PW Ask'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $false
    ValueData = $valueData 
    ValueType = 'String'
  }

  #  -- Allow the process to determine a file's type by examining its bit signature. Windows Internet Explorer uses this information to determine how to render the file. The FEATURE_MIME_SNIFFING feature, when enabled, allows to be set differently for each security zone by using the URLACTION_FEATURE_MIME_SNIFFING URL action flag.
  $valueData = '1' #ValueData for HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING_iexplore.exe
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING_iexplore.exe " {
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING'
    ValueName = 'iexplore.exe'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $false
    ValueData = $valueData 
    ValueType = 'String'
  }

  #  -- Block file downloads that navigate to a resource, that display a file download dialog box, or that are not initiated explicitly by a user action (for example, a mouse click or key press). This feature, when enabled, can be set differently for each security zone by using the URL action flag URLACTION_AUTOMATIC_DOWNLOAD_UI. 
  $valueData = '1' #ValueData for HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD__Reserved_
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD__Reserved_ " {
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD'
    ValueName = '(Reserved)'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $false
    ValueData = $valueData 
    ValueType = 'String'
  }

  $valueData = '1' #ValueData for HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD_iexplore.exe
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD_iexplore.exe " {
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD'
    ValueName = 'iexplore.exe'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $false
    ValueData = $valueData 
    ValueType = 'String'
  }

  #  -- Prevent non-user initiated navigation between a page in one zone to a page in a higher security zone. This feature, when enabled, can be set differently for each security zone by using the URL action flag URLACTION_FEATURE_ZONE_ELEVATION. 
  $valueData = '1' #ValueData for HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION__Reserved_
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION__Reserved_ " {
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION'
    ValueName = '(Reserved)'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $false
    ValueData = $valueData 
    ValueType = 'String'
  }

  $valueData = '1' #ValueData for HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION_explorer.exe
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION_explorer.exe " {
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION'
    ValueName = 'explorer.exe'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $false
    ValueData = $valueData 
    ValueType = 'String'
  }

  $valueData = '1' #ValueData for HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION_iexplore.exe
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION_iexplore.exe " {
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION'
    ValueName = 'iexplore.exe'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $false
    ValueData = $valueData 
    ValueType = 'String'
  }

  #  -- Configure the Allow software to run or install even if the signature is invalid setting to Disabled so that users cannot run unsigned ActiveX components.
  $valueData = '00000000' #ValueData for HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Download_RunInvalidSignatures
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Download_RunInvalidSignatures " {
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Download'
    ValueName = 'RunInvalidSignatures'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $false
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  #  -- Internet Explorer uses Multipurpose Internet Mail Extensions (MIME) data to determine file handling procedures for files that are received through a Web server. The Consistent MIME Handling setting determines whether Internet Explorer requires that all file type information that is provided by Web servers be consistent. For example, if the MIME type of a file is text/plain but the MIME data indicates that the file is really an executable file, Internet Explorer changes its extension to reflect this executable status. This capability helps ensure that executable code cannot masquerade as other types of data that may be trusted.
  $valueData = '1' #ValueData for HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING__Reserved_
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING__Reserved_ " {
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING'
    ValueName = '(Reserved)'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $false
    ValueData = $valueData 
    ValueType = 'String'
  }

  $valueData = '1' #ValueData for HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING_explorer.exe
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING_explorer.exe " {
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING'
    ValueName = 'explorer.exe'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $false
    ValueData = $valueData 
    ValueType = 'String'
  }

  $valueData = '1' #ValueData for HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING_iexplore.exe
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING_iexplore.exe " {
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING'
    ValueName = 'iexplore.exe'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $false
    ValueData = $valueData 
    ValueType = 'String'
  }

  #  -- Because the MK protocol is not widely used, it should be blocked wherever it is not needed.
  $valueData = '1' #ValueData for HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL__Reserved_
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL__Reserved_ " {
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL'
    ValueName = '(Reserved)'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $false
    ValueData = $valueData 
    ValueType = 'String'
  }

  $valueData = '1' #ValueData for HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL_explorer.exe
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL_explorer.exe " {
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL'
    ValueName = 'explorer.exe'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $false
    ValueData = $valueData 
    ValueType = 'String'
  }

  $valueData = '1' #ValueData for HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL_iexplore.exe
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL_iexplore.exe " {
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL'
    ValueName = 'iexplore.exe'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $false
    ValueData = $valueData 
    ValueType = 'String'
  }

  #  -- In certain circumstances, Web sites can initiate file download prompts without interaction from users. This technique can allow Web sites to put unauthorized files on a userâ€™s hard disk drive if they click the wrong button and accept the download.
  $valueData = '1' #ValueData for HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD_explorer.exe
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD_explorer.exe " {
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD'
    ValueName = 'explorer.exe'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $false
    ValueData = $valueData 
    ValueType = 'String'
  }

  #  -- Because Internet Explorer crash report information could contain sensitive information from the computer's memory, the Turn off Crash Detection setting is configured to Enabled
  $valueData = '00000001' #ValueData for HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Restrictions_NoCrashDetection
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Restrictions_NoCrashDetection " {
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Restrictions'
    ValueName = 'NoCrashDetection'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  #  -- MIME sniffing is a process that examines the content of a MIME file to determine its contextâ€”whether it is a data file, an executable file, or some other type of file. This policy setting configures Internet Explorer MIME sniffing to prevent promotion of a file of one type to a more dangerous file type.
  $valueData = '1' #ValueData for HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING__Reserved_
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING__Reserved_ " {
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING'
    ValueName = '(Reserved)'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $false
    ValueData = $valueData 
    ValueType = 'String'
  }

  $valueData = '1' #ValueData for HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING_explorer.exe
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING_explorer.exe " {
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING'
    ValueName = 'explorer.exe'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $false
    ValueData = $valueData 
    ValueType = 'String'
  }

  #  -- This policy setting specifies whether the tasks Publish this file to the Web, Publish this folder to the Web, and Publish the selected items to the Web are available from File and Folder Tasks in Windows folders.
  $valueData = '00000001' #ValueData for HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer_NoPublishingWizard
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer_NoPublishingWizard " {
    Key       = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    ValueName = 'NoPublishingWizard'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  #  -- This policy setting allows you to disable the client computerâ€™s ability to print over HTTP, which allows the computer to print to printers on the intranet as well as the Internet.
  $valueData = '00000001' #ValueData for HKLM:\Software\Policies\Microsoft\Windows NT\Printers_DisableHTTPPrinting
  xRegistry "Registry(Reg) - HKLM:\Software\Policies\Microsoft\Windows NT\Printers_DisableHTTPPrinting " {
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows NT\Printers'
    ValueName = 'DisableHTTPPrinting'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  #  -- This policy setting helps prevent Terminal Services clients from saving passwords on a computer.
  $valueData = '00000001' #ValueData for HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services_DisablePasswordSaving
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services_DisablePasswordSaving " {
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    ValueName = 'DisablePasswordSaving'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  #  -- Windows is prevented from downloading providers
  $valueData = '00000001' #ValueData for HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer_NoWebServices
  xRegistry "Registry(Reg) - HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer_NoWebServices " {
    Key       = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    ValueName = 'NoWebServices'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  #  -- Prevent the dial-up password from being saved
  $valueData = '00000001' #ValueData for HKLM:\SYSTEM\CurrentControlSet\Services\RasMan\Parameters_DisableSavePassword
  xRegistry "Registry(Reg) - HKLM:\SYSTEM\CurrentControlSet\Services\RasMan\Parameters_DisableSavePassword " {
    Key       = 'HKLM:\SYSTEM\CurrentControlSet\Services\RasMan\Parameters'
    ValueName = 'DisableSavePassword'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  #  -- Controls whether passwords can be saved on this computer from Remote Desktop Connection.
  #  -- Iit directs the RPC Runtime on an RPC server to restrict unauthenticated RPC clients connecting to RPC servers running on a machine. A client will be considered an authenticated client if it uses a named pipe to communicate with the server or if it uses RPC Security. RPC Interfaces that have specifically asked to be accessible by unauthenticated clients may be exempt from this restriction, depending on the selected value for this policy.
  #  -- This setting will cause RPC Clients that need to communicate with the Endpoint Mapper Service to not authenticate. The Endpoint Mapper Service on machines running Windows NT4 (all service packs) cannot process authentication information supplied in this manner. This means that enabling this setting on a client machine will prevent that client from communicating with a Windows NT4 server using RPC if endpoint resolution is needed.
  $valueData = '00000000' #ValueData for HKLM:\Software\Policies\Microsoft\Windows NT\Rpc_EnableAuthEpResolution
  xRegistry "Registry(Reg) - HKLM:\Software\Policies\Microsoft\Windows NT\Rpc_EnableAuthEpResolution " {
    Key       = 'HKLM:\Software\Policies\Microsoft\Windows NT\Rpc'
    ValueName = 'EnableAuthEpResolution'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $false
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  #  -- Allows you to disable Windows Messenger.
  $valueData = '00000001' #ValueData for HKLM:\SOFTWARE\Policies\Microsoft\Messenger\Client_PreventRun
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Policies\Microsoft\Messenger\Client_PreventRun " {
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Messenger\Client'
    ValueName = 'PreventRun'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

  $valueData = '00000001' #ValueData for HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender_DisableAntiSpyware
  xRegistry "Registry(Reg) - HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender_DisableAntiSpyware " {
    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
    ValueName = 'DisableAntiSpyware'
    Ensure    = 'Present'
    Force     = $true
    Hex       = $true
    ValueData = $valueData 
    ValueType = 'Dword'
  }

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
      Hex       = $true
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
      Hex       = $true
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
      Hex       = $true
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
      Hex       = $true
    }
  }

  xRegistry Crypto_SHA1_Flags {
    Ensure    = "Present"
    Key       = "HKLM:\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CertDllCreateCertificateChainEngine\Config"
    ValueName = "WeakSha1ThirdPartyFlags"
    ValueData = "0x80800000"
    ValueType = "Dword"
    Hex       = $true
    Force     = $true
  }

  xRegistry Crypto_SHA1_AfterTime {
    Ensure    = "Present"
    Key       = "HKLM:\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CertDllCreateCertificateChainEngine\Config"
    ValueName = "WeakSha1ThirdPartyAfterTime"
    ValueData = "0018df076244d101"
    ValueType = "Binary"
    Force     = $true
  }
  #endregion

  #region "Extra Settings"
  xRegistry RDP_EnableConnections {
    Ensure    = "Present"
    Key       = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
    ValueName = "fDenyTSConnections"
    ValueData = "0"
    ValueType = "Dword"
    Force     = $true
  }

  xRegistry RDP_SingleSessionPerUser {
    Ensure    = "Present"
    Key       = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
    ValueName = "fSingleSessionPerUser"
    ValueData = "0x1"
    ValueType = "Dword"
    Hex       = $true
    Force     = $true
  }

  xRegistry RDP_MinEncryptionLevel {
    Ensure    = "Present"
    Key       = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
    ValueName = "MinEncryptionLevel"
    ValueData = "0x3"
    ValueType = "Dword"
    Hex       = $true
    Force     = $true
  }

  xRegistry RDP_SecurityLayer {
    Ensure    = "Present"
    Key       = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
    ValueName = "SecurityLayer"
    ValueData = "0x2"
    ValueType = "Dword"
    Hex       = $true
    Force     = $true
  }

  xRegistry dotnet2_SchUseStrongCrypto_x64 {
    Ensure    = "Present"
    Key       = "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727"
    ValueName = "SchUseStrongCrypto"
    ValueData = "0x1"
    ValueType = "Dword"
    Hex       = $true
    Force     = $true
  }

  xRegistry dotnet2_SchUseStrongCrypto_x86 {
    Ensure    = "Present"
    Key       = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727"
    ValueName = "SchUseStrongCrypto"
    ValueData = "0x1"
    ValueType = "Dword"
    Hex       = $true
    Force     = $true
  }

  xRegistry dotnet4_SchUseStrongCrypto_x64 {
    Ensure    = "Present"
    Key       = "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319"
    ValueName = "SchUseStrongCrypto"
    ValueData = "0x1"
    ValueType = "Dword"
    Hex       = $true
    Force     = $true
  }

  xRegistry dotnet4_SchUseStrongCrypto_x86 {
    Ensure    = "Present"
    Key       = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319"
    ValueName = "SchUseStrongCrypto"
    ValueData = "0x1"
    ValueType = "Dword"
    Hex       = $true
    Force     = $true
  }
  #endregion
  
  xScript FinalReboot {
    GetScript = {
      return @{"Result" = (Test-Path "C:\WindowsAzure\Logs\EY\Done.lock")}
    }
    TestScript = {
      return Test-Path "C:\WindowsAzure\Logs\EY\Done.lock"
    }
    SetScript = {
      If(!(Test-Path "C:\WindowsAzure\Logs\EY")) {
        New-Item "C:\WindowsAzure\Logs\EY" -Type Directory
      }
      
      Set-Content "C:\WindowsAzure\Logs\EY\Done.lock" -Value "#Bootstraping completed"
      
      $global:DSCMachineStatus = 1
    }
  }
}
