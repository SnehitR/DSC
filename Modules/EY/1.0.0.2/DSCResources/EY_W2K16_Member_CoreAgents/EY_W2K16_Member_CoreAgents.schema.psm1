Configuration EY_W2K16_Member_CoreAgents
{
  Param(
    [Parameter(Mandatory)]
    [string]$SoftwareRepoUri,
    [string]$SoftwareRepoSASToken
  )

  Import-DscResource -ModuleName "xPSDesiredStateConfiguration"
  
  $PackagesFolder = "C:\Packages\EY"
  $QualysAgent = @{
    "Name" = "Qualys Cloud Security Agent"
    "ProductId" = ""
    "Installer" = "QualysCloudAgent.exe"
    "FileHash" = "153052F466334DAB5C0AC94F50A1F99864FD02B3FB1CD96313019D7D4811CF4C"
    "HashAlgorithm" = "SHA256"
    "DestinationPath" = "$PackagesFolder\QualysCloudAgent"
    "Arguments" = "CustomerId={BA0ABB1E-6647-8C5D-E040-10AC6B047499} ActivationId={96C3758B-A4DE-43FF-957F-AFBDD8E6F749}"
  }

  #region "Qualys Agent"
  xRemoteFile Download_QualysCloudAgent {
     DestinationPath = ("{0}\{1}" -f $QualysAgent.DestinationPath, $QualysAgent.Installer)
     Uri = ("{0}{1}{2}" -f $SoftwareRepoUri, $QualysAgent.Installer, $SoftwareRepoSASToken)
     MatchSource = $true
  }

  xPackage QualysCloudAgent {
    Ensure = "Present"
    Name = $QualysAgent.Name
    ProductId =  $QualysAgent.ProductId
    Path = ("{0}\{1}" -f $QualysAgent.DestinationPath, $QualysAgent.Installer)
    Arguments = $QualysAgent.Arguments
    FileHash = $QualysAgent.FileHash
    HashAlgorithm = $QualysAgent.HashAlgorithm
    DependsOn = "[xRemoteFile]Download_QualysCloudAgent"
  }
  #endregion
}