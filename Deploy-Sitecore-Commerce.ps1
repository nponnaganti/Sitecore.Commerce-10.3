#Requires -Version 3
param(
    # The root folder with WDP files.
    [string]$XCInstallRoot = "..",
    # The root folder of SIF.Sitecore.Commerce package.
    [string]$XCSIFInstallRoot = $PWD,
    # Specifies whether or not to bypass the installation of the default SXA Storefront. By default, the Sitecore XC installation script also deploys the SXA Storefront.
    [bool]$SkipInstallDefaultStorefront = $false,
    # Specifies whether or not to bypass the installation of the SXA Storefront packages.
    # If set to $true, $TasksToSkip parameter will be populated with the list of tasks to skip in order to bypass SXA Storefront packages installation.
    [bool]$SkipDeployStorefrontPackages = $false,

    # Path to the Master_SingleServer.json file provided in the SIF.Sitecore.Commerce package.
    [string]$Path = "$XCSIFInstallRoot\Configuration\Commerce\Master_SingleServer.json",
    # Path to the Commerce Solr schemas provided as part of the SIF.Sitecore.Commerce package.
    [string]$SolrSchemas = "$XCSIFInstallRoot\SolrSchemas",
    # Path to the SiteUtilityPages folder provided as part of the SIF.Sitecore.Commerce package.
    [string]$SiteUtilitiesSrc = "$XCSIFInstallRoot\SiteUtilityPages",
    # Path to the location where you downloaded the Microsoft.Web.XmlTransform.dll file.
    [string]$MergeToolFullPath = "$XCInstallRoot\MSBuild.Microsoft.VisualStudio.Web.targets*\tools\VSToolsPath\Web\Microsoft.Web.XmlTransform.dll",
    # Path to the Adventure Works Images.OnPrem SCWDP file
    [string]$AdventureWorksImagesWdpFullPath = "$XCInstallRoot\Adventure Works Images.OnPrem.scwdp.zip",
    # Path to the Sitecore Commerce Connect Core SCWDP file.
    [string]$CommerceConnectWdpFullPath = "$XCInstallRoot\Sitecore Commerce Connect Core*.scwdp.zip",
    # Path to the Sitecore Commerce Engine Connect OnPrem SCWDP file.
    [string]$CEConnectWdpFullPath = "$XCInstallRoot\Sitecore Commerce Engine Connect*.scwdp.zip",
    # Path to the Sitecore Commerce Experience Accelerator SCWDP file.
    [string]$SXACommerceWdpFullPath = "$XCInstallRoot\Sitecore Commerce Experience Accelerator*.scwdp.zip",
    # Path to the Sitecore Commerce Experience Accelerator Habitat Catalog SCWDP file.
    [string]$SXAStorefrontCatalogWdpFullPath = "$XCInstallRoot\Sitecore Commerce Experience Accelerator Habitat*.scwdp.zip",
    # Path to the Sitecore Commerce Experience Accelerator Storefront SCWDP file.
    [string]$SXAStorefrontWdpFullPath = "$XCInstallRoot\Sitecore Commerce Experience Accelerator Storefront*.scwdp.zip",
    # Path to the Sitecore Commerce Experience Accelerator Storefront Themes SCWDP file.
    [string]$SXAStorefrontThemeWdpFullPath = "$XCInstallRoot\Sitecore Commerce Experience Accelerator Storefront Themes*.scwdp.zip",
    # Path to the Sitecore Commerce Experience Analytics Core SCWDP file.
    [string]$CommercexAnalyticsWdpFullPath = "$XCInstallRoot\Sitecore Commerce ExperienceAnalytics Core*.scwdp.zip",
    # Path to the Sitecore Commerce Experience Profile Core SCWDP file.
    [string]$CommercexProfilesWdpFullPath = "$XCInstallRoot\Sitecore Commerce ExperienceProfile Core*.scwdp.zip",
    # Path to the Sitecore Commerce Marketing Automation Core SCWDP file.
    [string]$CommerceMAWdpFullPath = "$XCInstallRoot\Sitecore Commerce Marketing Automation Core*.scwdp.zip",
    # Path to the Sitecore Commerce Marketing Automation for AutomationEngine zip file.
    [string]$CommerceMAForAutomationEngineZIPFullPath = "$XCInstallRoot\Sitecore Commerce Marketing Automation for AutomationEngine*.zip",
    # Path to the Sitecore BizFx Server SCWDP file.
    [string]$BizFxPackage = "$XCInstallRoot\Sitecore.BizFx.OnPrem*scwdp.zip",
    # Path to the Commerce Engine Service SCWDP file.
    [string]$CommerceEngineWdpFullPath = "$XCInstallRoot\Sitecore.Commerce.Engine.OnPrem.Solr.*scwdp.zip",
    # Path to the Sitecore.Commerce.Habitat.Images.OnPrem SCWDP file.
    [string]$HabitatImagesWdpFullPath = "$XCInstallRoot\Sitecore.Commerce.Habitat.Images.OnPrem.scwdp.zip",

    # The prefix that will be used on SOLR, Website and Database instances. The default value matches the Sitecore XP default.
    [string]$SiteNamePrefix = "XP0",
    # The prefix to match Marketing Automation engine service name. Used in form "<MAEnginePrefix>_xconnect-MarketingAutomationService".
    [string]$MAEnginePrefix = $SiteNamePrefix,
    # The name of the Sitecore site instance.
    [string]$SiteName = "$SiteNamePrefix.sc",
    # Identity Server site name.
    [string]$IdentityServerSiteName = "$SiteNamePrefix.IdentityServer",
    # The url of the Sitecore Identity server.
    [string]$SitecoreIdentityServerUrl = "https://$IdentityServerSiteName",
    # The Commerce Engine Connect Client Id for the Sitecore Identity Server
    [string]$CommerceEngineConnectClientId = "CommerceEngineConnect",
    # The Commerce Engine Connect Client Secret for the Sitecore Identity Server
    [string]$CommerceEngineConnectClientSecret = "",
    # The host header name for the Sitecore storefront site.
    [string]$SiteHostHeaderName = "sxa.storefront.com",

    # The path of the Sitecore XP site.
    [string]$InstallDir = "$($Env:SYSTEMDRIVE)\inetpub\wwwroot\$SiteName",
    # The path of the Sitecore XConnect site.
    [string]$XConnectInstallDir = "$($Env:SYSTEMDRIVE)\inetpub\wwwroot\$SiteNamePrefix.xconnect",
    # The path to the inetpub folder where Commerce is installed.
    [string]$CommerceInstallRoot = "$($Env:SYSTEMDRIVE)\inetpub\wwwroot\",

    # The prefix for Sitecore core and master databases.
    [string]$SqlDbPrefix = $SiteNamePrefix,
    # The location of the database server where Sitecore XP databases are hosted. In case of named SQL instance, use "SQLServerName\\SQLInstanceName"
    [string]$SitecoreDbServer = $($Env:COMPUTERNAME),
    # The name of the Sitecore core database.
    [string]$SitecoreCoreDbName = "$($SqlDbPrefix)_Core",
    # A SQL user with sysadmin privileges.
    [string]$SqlUser = "sa",
    # The password for $SQLAdminUser.
    [string]$SqlPass = "12345",

    # The name of the Sitecore domain.
    [string]$SitecoreDomain = "sitecore",
    # The name of the Sitecore user account.
    [string]$SitecoreUsername = "admin",
    # The password for the $SitecoreUsername.
    [string]$SitecoreUserPassword = "b",

    # The prefix for the Search index. Using the SiteNamePrefix value for the prefix is recommended.
    [string]$SearchIndexPrefix = $SiteNamePrefix,
    # The URL of the Solr Server.
    [string]$SolrUrl = "https://localhost:8983/solr",
    # The folder that Solr has been installed to.
    [string]$SolrRoot = "$($Env:SYSTEMDRIVE)\solr-8.11.2",
    # The name of the Solr Service.
    [string]$SolrService = "solr-8.11.2",
    # The prefix for the Storefront index. The default value is the SiteNamePrefix.
    [string]$StorefrontIndexPrefix = $SiteNamePrefix,

    # The host name where Redis is hosted.
    [string]$RedisHost = "localhost",
    # The port number on which Redis is running.
    [string]$RedisPort = "6379",
    # The name of the Redis instance.
    [string]$RedisInstanceName = "Redis",
    # The path to the redis-cli executable.
    [string]$RedisCliPath = "$($Env:SYSTEMDRIVE)\Program Files\Redis\redis-cli.exe",

    # The location of the database server where Commerce databases should be deployed. In case of named SQL instance, use "SQLServerName\\SQLInstanceName"
    [string]$CommerceServicesDbServer = $($Env:COMPUTERNAME),
    # The name of the shared database for the Commerce Services.
    [string]$CommerceServicesDbName = "SitecoreCommerce_SharedEnvironments",
    # The name of the global database for the Commerce Services.
    [string]$CommerceServicesGlobalDbName = "SitecoreCommerce_Global",
    # The name of the archive database for the Commerce Services.
    [string]$CommerceServicesArchiveDbName = "SitecoreCommerce_ArchiveSharedEnvironments",    
    # The port for the Commerce Shops Service
    [string]$CommerceShopsServicesPort = "5005",
    # The port for the Commerce Authoring Service.
    [string]$CommerceAuthoringServicesPort = "5000",
    # The port for the Commerce Minions Service.
    [string]$CommerceMinionsServicesPort = "5010",
    # The postfix appended to Commerce services folders names and sitenames.
    # The postfix allows you to host more than one Commerce installment on one server.
    [string]$CommerceServicesPostfix = "Sc",
    # The postfix used as the root domain name (two-levels) to append as the hostname for Commerce services.
    # By default, all Commerce services are configured as sub-domains of the domain identified by the postfix.
    # Postfix validation enforces the following rules:
    # 1. The first level (TopDomainName) must be 2-7 characters in length and can contain alphabetical characters (a-z, A-Z) only. Numeric and special characters are not valid.
    # 2. The second level (DomainName) can contain alpha-numeric characters (a-z, A-Z,and 0-9) and can include one hyphen (-) character.
    # Special characters (wildcard (*)), for example, are not valid.
    [string]$CommerceServicesHostPostfix = "sc.com",

    # The name of the Sitecore XC Business Tools server.
    [string]$BizFxSiteName = "SitecoreBizFx",
    # The port of the Sitecore XC Business Tools server.
    [string]$BizFxPort = "4200",

    # The prefix used in the EnvironmentName setting in the config.json file for each Commerce Engine role.
    [string]$EnvironmentsPrefix = "Habitat",
    # The list of Commerce environment names. By default, the script deploys the AdventureWorks and the Habitat environments.
    [array]$Environments = @("AdventureWorksAuthoring", "HabitatAuthoring"),
    # Commerce environments GUIDs used to clean existing Redis cache during deployment. Default parameter values correspond to the default Commerce environment GUIDS.
    [array]$EnvironmentsGuids = @("78a1ea611f3742a7ac899a3f46d60ca5", "40e77b7b4be94186b53b5bfd89a6a83b"),
    # The environments running the minions service. (This is required, for example, for running indexing minions).
    [array]$MinionEnvironments = @("AdventureWorksMinions", "HabitatMinions"),
    # whether to deploy sample data for each environment.
    [bool]$DeploySampleData = $true,

    # The domain of the local account used for the various application pools created as part of the deployment.
    [string]$UserDomain = $Env:COMPUTERNAME,
    # The user name for a local account to be set up for the various application pools that are created as part of the deployment.
    [string]$UserName = "CSFndRuntimeUser",
    # The password for the $UserName.
    [string]$UserPassword = "q5Y8tA3FRMZf3xKN!",

    # The Braintree Merchant Id.
    [string]$BraintreeMerchantId = "",
    # The Braintree Public Key.
    [string]$BraintreePublicKey = "",
    # The Braintree Private Key.
    [string]$BraintreePrivateKey = "",
    # The Braintree Environment.
    [string]$BraintreeEnvironment = "",

    # List of comma-separated task names to skip during Sitecore XC deployment.
    [string]$TasksToSkip = ""
)

Function Resolve-ItemPath {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [string] $Path
    )
    process {
        if ([string]::IsNullOrWhiteSpace($Path)) {
            throw "Parameter could not be validated because it contains only whitespace. Please check script parameters."
        }
        $itemPath = Resolve-Path -Path $Path -ErrorAction SilentlyContinue | Select-Object -First 1
        if ([string]::IsNullOrEmpty($itemPath) -or (-not (Test-Path $itemPath))) {
            throw "Path [$Path] could not be resolved. Please check script parameters."
        }

        Write-Host "Found [$itemPath]."
        return $itemPath
    }
}

if (($SkipDeployStorefrontPackages -eq $true) -and ($SkipInstallDefaultStorefront -eq $false)) {
    throw "You cannot install the SXA Storefront without deploying necessary packages. If you want to install the SXA Storefront, set [SkipDeployStorefrontPackages] parameter to [false]."
}

if (($DeploySampleData -eq $false) -and ($SkipInstallDefaultStorefront -eq $false)) {
    throw "You cannot install the SXA Storefront without deploying sample data. If you want to install the SXA Storefront, set [DeploySampleData] parameter to [true]."
}

[string[]] $Skip = @()
if (-not ([string]::IsNullOrWhiteSpace($TasksToSkip))) {
    $TasksToSkip.Split(',') | ForEach-Object { $Skip += $_.Trim() }
}

Push-Location $PSScriptRoot

$modulesPath = ( Join-Path -Path $PWD -ChildPath "Modules" )
if ($env:PSModulePath -notlike "*$modulesPath*") {
    [Environment]::SetEnvironmentVariable("PSModulePath", "$env:PSModulePath;$modulesPath")
}

$deployCommerceParams = @{
    Path                                     = Resolve-ItemPath -Path $Path
    SolrSchemas                              = Resolve-ItemPath -Path $SolrSchemas
    SiteUtilitiesSrc                         = Resolve-ItemPath -Path $SiteUtilitiesSrc
    MergeToolFullPath                        = Resolve-ItemPath -Path $MergeToolFullPath
    AdventureWorksImagesWdpFullPath          = Resolve-ItemPath -Path $AdventureWorksImagesWdpFullPath
    CommerceConnectWdpFullPath               = Resolve-ItemPath -Path $CommerceConnectWdpFullPath
    CEConnectWdpFullPath                     = Resolve-ItemPath -Path $CEConnectWdpFullPath
    SXACommerceWdpFullPath                   = Resolve-ItemPath -Path $SXACommerceWdpFullPath
    SXAStorefrontCatalogWdpFullPath          = Resolve-ItemPath -Path $SXAStorefrontCatalogWdpFullPath
    SXAStorefrontWdpFullPath                 = Resolve-ItemPath -Path $SXAStorefrontWdpFullPath
    SXAStorefrontThemeWdpFullPath            = Resolve-ItemPath -Path $SXAStorefrontThemeWdpFullPath
    CommercexAnalyticsWdpFullPath            = Resolve-ItemPath -Path $CommercexAnalyticsWdpFullPath
    CommercexProfilesWdpFullPath             = Resolve-ItemPath -Path $CommercexProfilesWdpFullPath
    CommerceMAWdpFullPath                    = Resolve-ItemPath -Path $CommerceMAWdpFullPath
    CommerceMAForAutomationEngineZIPFullPath = Resolve-ItemPath -Path $CommerceMAForAutomationEngineZIPFullPath
    BizFxPackage                             = Resolve-ItemPath -Path $BizFxPackage
    CommerceEngineWdpFullPath                = Resolve-ItemPath -Path $CommerceEngineWdpFullPath
    HabitatImagesWdpFullPath                 = Resolve-ItemPath -Path $HabitatImagesWdpFullPath
    SiteName                                 = $SiteName
    MAEnginePrefix                           = $MAEnginePrefix
    SiteHostHeaderName                       = $SiteHostHeaderName
    InstallDir                               = Resolve-ItemPath -Path $InstallDir
    XConnectInstallDir                       = Resolve-ItemPath -Path $XConnectInstallDir
    CommerceInstallRoot                      = Resolve-ItemPath -Path $CommerceInstallRoot
    CommerceServicesDbServer                 = $CommerceServicesDbServer
    CommerceServicesDbName                   = $CommerceServicesDbName
    CommerceServicesGlobalDbName             = $CommerceServicesGlobalDbName
    CommerceServicesArchiveDbName            = $CommerceServicesArchiveDbName
    SitecoreDbServer                         = $SitecoreDbServer
    SitecoreCoreDbName                       = $SitecoreCoreDbName
    SqlDbPrefix                              = $SqlDbPrefix
    SqlAdminUser                             = $SqlUser
    SqlAdminPassword                         = $SqlPass
    SolrUrl                                  = $SolrUrl
    SolrRoot                                 = Resolve-ItemPath -Path $SolrRoot
    SolrService                              = $SolrService
    SearchIndexPrefix                        = $SearchIndexPrefix
    StorefrontIndexPrefix                    = $StorefrontIndexPrefix
    CommerceServicesPostfix                  = $CommerceServicesPostfix
    CommerceServicesHostPostfix              = $CommerceServicesHostPostfix
    EnvironmentsPrefix                       = $EnvironmentsPrefix
    Environments                             = $Environments
    EnvironmentsGuids                        = $EnvironmentsGuids
    MinionEnvironments                       = $MinionEnvironments    
    CommerceShopsServicesPort                = $CommerceShopsServicesPort
    CommerceAuthoringServicesPort            = $CommerceAuthoringServicesPort
    CommerceMinionsServicesPort              = $CommerceMinionsServicesPort
    RedisInstanceName                        = $RedisInstanceName
    RedisCliPath                             = $RedisCliPath
    RedisHost                                = $RedisHost
    RedisPort                                = $RedisPort
    UserDomain                               = $UserDomain
    UserName                                 = $UserName
    UserPassword                             = $UserPassword
    BraintreeMerchantId                      = $BraintreeMerchantId
    BraintreePublicKey                       = $BraintreePublicKey
    BraintreePrivateKey                      = $BraintreePrivateKey
    BraintreeEnvironment                     = $BraintreeEnvironment
    SitecoreDomain                           = $SitecoreDomain
    SitecoreUsername                         = $SitecoreUsername
    SitecoreUserPassword                     = $SitecoreUserPassword
    BizFxSiteName                            = $BizFxSiteName
    BizFxPort                                = $BizFxPort
    SitecoreIdentityServerApplicationName    = $IdentityServerSiteName
    SitecoreIdentityServerUrl                = $SitecoreIdentityServerUrl
    SkipInstallDefaultStorefront             = $SkipInstallDefaultStorefront
    SkipDeployStorefrontPackages             = $SkipDeployStorefrontPackages
    CommerceEngineConnectClientId            = $CommerceEngineConnectClientId
    CommerceEngineConnectClientSecret        = $CommerceEngineConnectClientSecret
    DeploySampleData                         = $DeploySampleData
}

if ($Skip.Count -eq 0) {
    Install-SitecoreConfiguration @deployCommerceParams -Verbose *>&1 | Tee-Object "$XCSIFInstallRoot\XC-Install.log"
}
else {
    Install-SitecoreConfiguration @deployCommerceParams -Skip $Skip -Verbose *>&1 | Tee-Object "$XCSIFInstallRoot\XC-Install.log"
}

# SIG # Begin signature block
# MIImLgYJKoZIhvcNAQcCoIImHzCCJhsCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDg+MZCNUhY3NNL
# 3f5CFBo0b9MWw9Jnje5eMHZgB9MkCqCCFBUwggWQMIIDeKADAgECAhAFmxtXno4h
# MuI5B72nd3VcMA0GCSqGSIb3DQEBDAUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNV
# BAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0xMzA4MDExMjAwMDBaFw0z
# ODAxMTUxMjAwMDBaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJ
# bmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0
# IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
# AL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3EMB/z
# G6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKyunWZ
# anMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsFxl7s
# Wxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU15zHL
# 2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJBMtfb
# BHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObURWBf3
# JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6nj3c
# AORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxBYKqx
# YxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5SUUd0
# viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+xq4aL
# T8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGjQjBAMA8GA1Ud
# EwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgGGMB0GA1UdDgQWBBTs1+OC0nFdZEzf
# Lmc/57qYrhwPTzANBgkqhkiG9w0BAQwFAAOCAgEAu2HZfalsvhfEkRvDoaIAjeNk
# aA9Wz3eucPn9mkqZucl4XAwMX+TmFClWCzZJXURj4K2clhhmGyMNPXnpbWvWVPjS
# PMFDQK4dUPVS/JA7u5iZaWvHwaeoaKQn3J35J64whbn2Z006Po9ZOSJTROvIXQPK
# 7VB6fWIhCoDIc2bRoAVgX+iltKevqPdtNZx8WorWojiZ83iL9E3SIAveBO6Mm0eB
# cg3AFDLvMFkuruBx8lbkapdvklBtlo1oepqyNhR6BvIkuQkRUNcIsbiJeoQjYUIp
# 5aPNoiBB19GcZNnqJqGLFNdMGbJQQXE9P01wI4YMStyB0swylIQNCAmXHE/A7msg
# dDDS4Dk0EIUhFQEI6FUy3nFJ2SgXUE3mvk3RdazQyvtBuEOlqtPDBURPLDab4vri
# RbgjU2wGb2dVf0a1TD9uKFp5JtKkqGKX0h7i7UqLvBv9R0oN32dmfrJbQdA75PQ7
# 9ARj6e/CVABRoIoqyc54zNXqhwQYs86vSYiv85KZtrPmYQ/ShQDnUBrkG5WdGaG5
# nLGbsQAe79APT0JsyQq87kP6OnGlyE0mpTX9iV28hWIdMtKgK1TtmlfB2/oQzxm3
# i0objwG2J5VT6LaJbVu8aNQj6ItRolb58KaAoNYes7wPD1N1KarqE3fk3oyBIa0H
# EEcRrYc9B9F1vM/zZn4wggawMIIEmKADAgECAhAIrUCyYNKcTJ9ezam9k67ZMA0G
# CSqGSIb3DQEBDAUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJ
# bmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0
# IFRydXN0ZWQgUm9vdCBHNDAeFw0yMTA0MjkwMDAwMDBaFw0zNjA0MjgyMzU5NTla
# MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UE
# AxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcgUlNBNDA5NiBTSEEz
# ODQgMjAyMSBDQTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDVtC9C
# 0CiteLdd1TlZG7GIQvUzjOs9gZdwxbvEhSYwn6SOaNhc9es0JAfhS0/TeEP0F9ce
# 2vnS1WcaUk8OoVf8iJnBkcyBAz5NcCRks43iCH00fUyAVxJrQ5qZ8sU7H/Lvy0da
# E6ZMswEgJfMQ04uy+wjwiuCdCcBlp/qYgEk1hz1RGeiQIXhFLqGfLOEYwhrMxe6T
# SXBCMo/7xuoc82VokaJNTIIRSFJo3hC9FFdd6BgTZcV/sk+FLEikVoQ11vkunKoA
# FdE3/hoGlMJ8yOobMubKwvSnowMOdKWvObarYBLj6Na59zHh3K3kGKDYwSNHR7Oh
# D26jq22YBoMbt2pnLdK9RBqSEIGPsDsJ18ebMlrC/2pgVItJwZPt4bRc4G/rJvmM
# 1bL5OBDm6s6R9b7T+2+TYTRcvJNFKIM2KmYoX7BzzosmJQayg9Rc9hUZTO1i4F4z
# 8ujo7AqnsAMrkbI2eb73rQgedaZlzLvjSFDzd5Ea/ttQokbIYViY9XwCFjyDKK05
# huzUtw1T0PhH5nUwjewwk3YUpltLXXRhTT8SkXbev1jLchApQfDVxW0mdmgRQRNY
# mtwmKwH0iU1Z23jPgUo+QEdfyYFQc4UQIyFZYIpkVMHMIRroOBl8ZhzNeDhFMJlP
# /2NPTLuqDQhTQXxYPUez+rbsjDIJAsxsPAxWEQIDAQABo4IBWTCCAVUwEgYDVR0T
# AQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUaDfg67Y7+F8Rhvv+YXsIiGX0TkIwHwYD
# VR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQDAgGGMBMG
# A1UdJQQMMAoGCCsGAQUFBwMDMHcGCCsGAQUFBwEBBGswaTAkBggrBgEFBQcwAYYY
# aHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAChjVodHRwOi8vY2Fj
# ZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNydDBDBgNV
# HR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRU
# cnVzdGVkUm9vdEc0LmNybDAcBgNVHSAEFTATMAcGBWeBDAEDMAgGBmeBDAEEATAN
# BgkqhkiG9w0BAQwFAAOCAgEAOiNEPY0Idu6PvDqZ01bgAhql+Eg08yy25nRm95Ry
# sQDKr2wwJxMSnpBEn0v9nqN8JtU3vDpdSG2V1T9J9Ce7FoFFUP2cvbaF4HZ+N3HL
# IvdaqpDP9ZNq4+sg0dVQeYiaiorBtr2hSBh+3NiAGhEZGM1hmYFW9snjdufE5Btf
# Q/g+lP92OT2e1JnPSt0o618moZVYSNUa/tcnP/2Q0XaG3RywYFzzDaju4ImhvTnh
# OE7abrs2nfvlIVNaw8rpavGiPttDuDPITzgUkpn13c5UbdldAhQfQDN8A+KVssIh
# dXNSy0bYxDQcoqVLjc1vdjcshT8azibpGL6QB7BDf5WIIIJw8MzK7/0pNVwfiThV
# 9zeKiwmhywvpMRr/LhlcOXHhvpynCgbWJme3kuZOX956rEnPLqR0kq3bPKSchh/j
# wVYbKyP/j7XqiHtwa+aguv06P0WmxOgWkVKLQcBIhEuWTatEQOON8BUozu3xGFYH
# Ki8QxAwIZDwzj64ojDzLj4gLDb879M4ee47vtevLt/B3E+bnKD+sEq6lLyJsQfmC
# XBVmzGwOysWGw/YmMwwHS6DTBwJqakAwSEs0qFEgu60bhQjiWQ1tygVQK+pKHJ6l
# /aCnHwZ05/LWUpD9r4VIIflXO7ScA+2GRfS0YW6/aOImYIbqyK+p/pQd52MbOoZW
# eE4wggfJMIIFsaADAgECAhAOWDArdt3BhOzKi4Ks/8bnMA0GCSqGSIb3DQEBCwUA
# MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UE
# AxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcgUlNBNDA5NiBTSEEz
# ODQgMjAyMSBDQTEwHhcNMjIxMDE3MDAwMDAwWhcNMjMxMTAzMjM1OTU5WjCBqTEL
# MAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDVNhbiBG
# cmFuY2lzY28xGzAZBgNVBAoTElNpdGVjb3JlIFVTQSwgSW5jLjELMAkGA1UECxMC
# SVQxGzAZBgNVBAMTElNpdGVjb3JlIFVTQSwgSW5jLjEmMCQGCSqGSIb3DQEJARYX
# aWx5YS5kaW1vdkBzaXRlY29yZS5jb20wggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAw
# ggIKAoICAQDSpDYiWgzsojERrPzBfBwEfHquos9XObg7LfQUlikKxMJzxWrxldMT
# 1Wo4VN7O6jB9A2BwxR7f/mLkUT9N8oTzP0VMxqs0S13tQpEZ/ZqlRtfBp9A+4Fp1
# mviP0GlYlZ1O4zkKBh/EfccNcKpemmexirs8bW/pvRal1hVKPL47R5Zs9UNsY3oT
# ocnbtSWb4CTKFupCi8jAFsKGluZTOLTZ1m3rXcYuYEVnsnaw04h1n1xABce/2Ajj
# TGFbN/j30dUVfHuIfAF45WQy70mPEksp/vKhbckUhJ9Jnuc3dP5x5WHz2WO7+zjt
# qLylI0Wz+DlL3UhNtgv1HOYL8vc8l1/NvKLhlIWODjmcyT9zza2LMapdC2KdncU7
# 5nvJbWGnSJDan6ego57mikUhmXGMJbPy4RdgJjTFhdzuRL89nf+TWZ0F85RAR/HM
# 4bMgjgYaxwKuxxM5Hb3L8X146gThR8QxVQSLpE1CJU86afELMbZTJiZ32k7jH1fl
# WoGwNwhc1KMCz1Y0cLEmIj8fmdHRVulZIOVxGxCfgSdeBoylUVUFkc9Mpm/Xilx7
# XRPRIu+Jp3nYW8gCK/aKSdoIyfAMNee7dmIFR0kjtpWnn33pu111mt6OtCF6XHE9
# kNRaY+mL+q1WTuXme6H8jR3yjt35kjtKO1SH4OBBUZW2OWprzw6lNQIDAQABo4IC
# KjCCAiYwHwYDVR0jBBgwFoAUaDfg67Y7+F8Rhvv+YXsIiGX0TkIwHQYDVR0OBBYE
# FBAH6bDYbTkLp29ACivpdh6zuoSyMCIGA1UdEQQbMBmBF2lseWEuZGltb3ZAc2l0
# ZWNvcmUuY29tMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzCB
# tQYDVR0fBIGtMIGqMFOgUaBPhk1odHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGln
# aUNlcnRUcnVzdGVkRzRDb2RlU2lnbmluZ1JTQTQwOTZTSEEzODQyMDIxQ0ExLmNy
# bDBToFGgT4ZNaHR0cDovL2NybDQuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3Rl
# ZEc0Q29kZVNpZ25pbmdSU0E0MDk2U0hBMzg0MjAyMUNBMS5jcmwwPgYDVR0gBDcw
# NTAzBgZngQwBBAEwKTAnBggrBgEFBQcCARYbaHR0cDovL3d3dy5kaWdpY2VydC5j
# b20vQ1BTMIGUBggrBgEFBQcBAQSBhzCBhDAkBggrBgEFBQcwAYYYaHR0cDovL29j
# c3AuZGlnaWNlcnQuY29tMFwGCCsGAQUFBzAChlBodHRwOi8vY2FjZXJ0cy5kaWdp
# Y2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRDb2RlU2lnbmluZ1JTQTQwOTZTSEEz
# ODQyMDIxQ0ExLmNydDAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4ICAQC4
# FI/hctFLM03rjO/8b1+Z6PCFlXFz/Tsdx/d7b9Gwn+z1fpuhZ5WCURExoPRJdjMr
# qCOoG/qdtXptPHpZvYLgELSlHh/oGJqbybeF5DUIaqvCswEgMgS/TnkhE4miXU7H
# YTxLXfLzHvPxsCWoWK+tVfq6/qGxecjj0yov2MXFjCSEBFoNrX33BlwK8z+G6ZeX
# DFue8XGrb/hz3jfw0B/TN6LWmNqgfwpBJOsbLWogz5Fvoh3B1M1Z1FcrtVKI9ffZ
# MaV64xKntFzGF0dc3XN3G/3pFCZlXEA2e61Pia6Zm8DzeVa0SKE4dHUunE6CXyKO
# iKL/dgNxxTkHgzyMKXT9oZcN/8lLatew/OUP0fi7XHWqulkMKnPhiDT0hLHXbdaq
# Q+9W838rG5Fj2xwK/wv5DFbVl2/BieGjYAqA2mrNvrcChpy/G9kkrpDvTPaXJ8GK
# sCOrRbpLxVkkf6Hl/IWPdvy0NwprFELZSzAbPQCfSDMWhM1GI5dACs3YcfRtrtzC
# /Ght0L8U7SKVG0A+yinkQ5h2IikQetxojALQArf/+0XDZXXu4h1B1Lp6WgGvzUyV
# C3SuE4ssMGLinXKDXy2P90dGBCuCqSXxANFBL3Iqg/E7s4CXslp3Sy0z5Pg0Ov2u
# TEAu7PvqNtqUpO5tS6yjDFNy4ZP2c3iXbUWODwqTYjGCEW8wghFrAgEBMH0waTEL
# MAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhE
# aWdpQ2VydCBUcnVzdGVkIEc0IENvZGUgU2lnbmluZyBSU0E0MDk2IFNIQTM4NCAy
# MDIxIENBMQIQDlgwK3bdwYTsyouCrP/G5zANBglghkgBZQMEAgEFAKCBhDAYBgor
# BgEEAYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEE
# MBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCAF
# 04/IpHZQzo78g92yC/ZIim7cOx31sI1f69PaI5rMvzANBgkqhkiG9w0BAQEFAASC
# AgCkMv/vYbCj3UNLRUKPTeTOuRsWStBOSPLOd96yYqMX69JbxYN83KxQq4AHYXqR
# DT7wz8LNeQOixqspkvlawB6h6TVn8kMhkQx4X97+xg416/De5zKPyTYZPEbobbmK
# 5PMcAyaIMYYZvZZKUzAW4t89LUN2YggWXJAlEmSycfx2U1Q30v420Z26W0tkCbvC
# tnOVrX6iL/tWB0dO+gv2qfFUxgtd0x6jVaL94Uf1fjHmesU4H/1Uge/TAwBlpSUR
# 3IVD5IQFULefNvv+H4YOnOpQvHyBTQOSRzsVZx+GH25gb+NGWwt6hdF7UoHHYWxV
# 7mh7lX5bO/oCAuRrq6SKWR1dGdOkmsQhaaizTWGxwpzRsbsYCAkA0Q9yPMEINs/e
# VBrr0MUjbYY1jPKPc4pgDZMFUMZc/YxZWP0xzS6T24xMJ7eiNkIIEojB0XW44zOQ
# z7L4ytBXx+Ija3YWIzoWXjqHiR/uXo7S74fRcBTBRk0N1YvyTkJAVTFhHjL7XMA3
# HEOIz1rFWvtpAYssPDZiYwjaBeHT8s5sWyUDokT6050rVFevEiacqXDIhSR2uf+A
# aYzRqVpbUmlRrbhOisqVdjQPTFpYtIwrvPxHQY1sYUGwPra0yjdmenZmqAzns0Oi
# jMBJLdelETiZBi/cj3CZiz+qa7f9AD4C8ny3KBwwEYITk6GCDjwwgg44BgorBgEE
# AYI3AwMBMYIOKDCCDiQGCSqGSIb3DQEHAqCCDhUwgg4RAgEDMQ0wCwYJYIZIAWUD
# BAIBMIIBDgYLKoZIhvcNAQkQAQSggf4EgfswgfgCAQEGC2CGSAGG+EUBBxcDMDEw
# DQYJYIZIAWUDBAIBBQAEIHsXFtdnJO2P3S8sXVb0Gxb0+9ttiG5f9qC32YyffPZe
# AhQSStfFJopFE0FpOFPA3RUz7luQghgPMjAyMjEyMDExMjMyNTZaMAMCAR6ggYak
# gYMwgYAxCzAJBgNVBAYTAlVTMR0wGwYDVQQKExRTeW1hbnRlYyBDb3Jwb3JhdGlv
# bjEfMB0GA1UECxMWU3ltYW50ZWMgVHJ1c3QgTmV0d29yazExMC8GA1UEAxMoU3lt
# YW50ZWMgU0hBMjU2IFRpbWVTdGFtcGluZyBTaWduZXIgLSBHM6CCCoswggU4MIIE
# IKADAgECAhB7BbHUSWhRRPfJidKcGZ0SMA0GCSqGSIb3DQEBCwUAMIG9MQswCQYD
# VQQGEwJVUzEXMBUGA1UEChMOVmVyaVNpZ24sIEluYy4xHzAdBgNVBAsTFlZlcmlT
# aWduIFRydXN0IE5ldHdvcmsxOjA4BgNVBAsTMShjKSAyMDA4IFZlcmlTaWduLCBJ
# bmMuIC0gRm9yIGF1dGhvcml6ZWQgdXNlIG9ubHkxODA2BgNVBAMTL1ZlcmlTaWdu
# IFVuaXZlcnNhbCBSb290IENlcnRpZmljYXRpb24gQXV0aG9yaXR5MB4XDTE2MDEx
# MjAwMDAwMFoXDTMxMDExMTIzNTk1OVowdzELMAkGA1UEBhMCVVMxHTAbBgNVBAoT
# FFN5bWFudGVjIENvcnBvcmF0aW9uMR8wHQYDVQQLExZTeW1hbnRlYyBUcnVzdCBO
# ZXR3b3JrMSgwJgYDVQQDEx9TeW1hbnRlYyBTSEEyNTYgVGltZVN0YW1waW5nIENB
# MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1mdWVVPnYxyXRqBoutV
# 87ABrTxxrDKPBWuGmicAMpdqTclkFEspu8LZKbku7GOz4c8/C1aQ+GIbfuumB+Le
# f15tQDjUkQbnQXx5HMvLrRu/2JWR8/DubPitljkuf8EnuHg5xYSl7e2vh47Ojcdt
# 6tKYtTofHjmdw/SaqPSE4cTRfHHGBim0P+SDDSbDewg+TfkKtzNJ/8o71PWym0vh
# iJka9cDpMxTW38eA25Hu/rySV3J39M2ozP4J9ZM3vpWIasXc9LFL1M7oCZFftYR5
# NYp4rBkyjyPBMkEbWQ6pPrHM+dYr77fY5NUdbRE6kvaTyZzjSO67Uw7UNpeGeMWh
# NwIDAQABo4IBdzCCAXMwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8C
# AQAwZgYDVR0gBF8wXTBbBgtghkgBhvhFAQcXAzBMMCMGCCsGAQUFBwIBFhdodHRw
# czovL2Quc3ltY2IuY29tL2NwczAlBggrBgEFBQcCAjAZGhdodHRwczovL2Quc3lt
# Y2IuY29tL3JwYTAuBggrBgEFBQcBAQQiMCAwHgYIKwYBBQUHMAGGEmh0dHA6Ly9z
# LnN5bWNkLmNvbTA2BgNVHR8ELzAtMCugKaAnhiVodHRwOi8vcy5zeW1jYi5jb20v
# dW5pdmVyc2FsLXJvb3QuY3JsMBMGA1UdJQQMMAoGCCsGAQUFBwMIMCgGA1UdEQQh
# MB+kHTAbMRkwFwYDVQQDExBUaW1lU3RhbXAtMjA0OC0zMB0GA1UdDgQWBBSvY9bK
# o06FcuCnvEHzKaI4f4B1YjAfBgNVHSMEGDAWgBS2d/ppSEefUxLVwuoHMnYH0ZcH
# GTANBgkqhkiG9w0BAQsFAAOCAQEAdeqwLdU0GVwyRf4O4dRPpnjBb9fq3dxP86HI
# gYj3p48V5kApreZd9KLZVmSEcTAq3R5hF2YgVgaYGY1dcfL4l7wJ/RyRR8ni6I0D
# +8yQL9YKbE4z7Na0k8hMkGNIOUAhxN3WbomYPLWYl+ipBrcJyY9TV0GQL+EeTU7c
# yhB4bEJu8LbF+GFcUvVO9muN90p6vvPN/QPX2fYDqA/jU/cKdezGdS6qZoUEmbf4
# Blfhxg726K/a7JsYH6q54zoAv86KlMsB257HOLsPUqvR45QDYApNoP4nbRQy/D+X
# QOG/mYnb5DkUvdrk08PqK1qzlVhVBH3HmuwjA42FKtL/rqlhgTCCBUswggQzoAMC
# AQICEHvU5a+6zAc/oQEjBCJBTRIwDQYJKoZIhvcNAQELBQAwdzELMAkGA1UEBhMC
# VVMxHTAbBgNVBAoTFFN5bWFudGVjIENvcnBvcmF0aW9uMR8wHQYDVQQLExZTeW1h
# bnRlYyBUcnVzdCBOZXR3b3JrMSgwJgYDVQQDEx9TeW1hbnRlYyBTSEEyNTYgVGlt
# ZVN0YW1waW5nIENBMB4XDTE3MTIyMzAwMDAwMFoXDTI5MDMyMjIzNTk1OVowgYAx
# CzAJBgNVBAYTAlVTMR0wGwYDVQQKExRTeW1hbnRlYyBDb3Jwb3JhdGlvbjEfMB0G
# A1UECxMWU3ltYW50ZWMgVHJ1c3QgTmV0d29yazExMC8GA1UEAxMoU3ltYW50ZWMg
# U0hBMjU2IFRpbWVTdGFtcGluZyBTaWduZXIgLSBHMzCCASIwDQYJKoZIhvcNAQEB
# BQADggEPADCCAQoCggEBAK8Oiqr43L9pe1QXcUcJvY08gfh0FXdnkJz93k4Cnkt2
# 9uU2PmXVJCBtMPndHYPpPydKM05tForkjUCNIqq+pwsb0ge2PLUaJCj4G3JRPcgJ
# iCYIOvn6QyN1R3AMs19bjwgdckhXZU2vAjxA9/TdMjiTP+UspvNZI8uA3hNN+RDJ
# qgoYbFVhV9HxAizEtavybCPSnw0PGWythWJp/U6FwYpSMatb2Ml0UuNXbCK/VX9v
# ygarP0q3InZl7Ow28paVgSYs/buYqgE4068lQJsJU/ApV4VYXuqFSEEhh+XetNMm
# sntAU1h5jlIxBk2UA0XEzjwD7LcA8joixbRv5e+wipsCAwEAAaOCAccwggHDMAwG
# A1UdEwEB/wQCMAAwZgYDVR0gBF8wXTBbBgtghkgBhvhFAQcXAzBMMCMGCCsGAQUF
# BwIBFhdodHRwczovL2Quc3ltY2IuY29tL2NwczAlBggrBgEFBQcCAjAZGhdodHRw
# czovL2Quc3ltY2IuY29tL3JwYTBABgNVHR8EOTA3MDWgM6Axhi9odHRwOi8vdHMt
# Y3JsLndzLnN5bWFudGVjLmNvbS9zaGEyNTYtdHNzLWNhLmNybDAWBgNVHSUBAf8E
# DDAKBggrBgEFBQcDCDAOBgNVHQ8BAf8EBAMCB4AwdwYIKwYBBQUHAQEEazBpMCoG
# CCsGAQUFBzABhh5odHRwOi8vdHMtb2NzcC53cy5zeW1hbnRlYy5jb20wOwYIKwYB
# BQUHMAKGL2h0dHA6Ly90cy1haWEud3Muc3ltYW50ZWMuY29tL3NoYTI1Ni10c3Mt
# Y2EuY2VyMCgGA1UdEQQhMB+kHTAbMRkwFwYDVQQDExBUaW1lU3RhbXAtMjA0OC02
# MB0GA1UdDgQWBBSlEwGpn4XMG24WHl87Map5NgB7HTAfBgNVHSMEGDAWgBSvY9bK
# o06FcuCnvEHzKaI4f4B1YjANBgkqhkiG9w0BAQsFAAOCAQEARp6v8LiiX6KZSM+o
# J0shzbK5pnJwYy/jVSl7OUZO535lBliLvFeKkg0I2BC6NiT6Cnv7O9Niv0qUFeaC
# 24pUbf8o/mfPcT/mMwnZolkQ9B5K/mXM3tRr41IpdQBKK6XMy5voqU33tBdZkkHD
# tz+G5vbAf0Q8RlwXWuOkO9VpJtUhfeGAZ35irLdOLhWa5Zwjr1sR6nGpQfkNeTip
# oQ3PtLHaPpp6xyLFdM3fRwmGxPyRJbIblumFCOjd6nRgbmClVnoNyERY3Ob5SBSe
# 5b/eAL13sZgUchQk38cRLB8AP8NLFMZnHMweBqOQX1xUiz7jM1uCD8W3hgJOcZ/p
# ZkU/djGCAlowggJWAgEBMIGLMHcxCzAJBgNVBAYTAlVTMR0wGwYDVQQKExRTeW1h
# bnRlYyBDb3Jwb3JhdGlvbjEfMB0GA1UECxMWU3ltYW50ZWMgVHJ1c3QgTmV0d29y
# azEoMCYGA1UEAxMfU3ltYW50ZWMgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQe9Tl
# r7rMBz+hASMEIkFNEjALBglghkgBZQMEAgGggaQwGgYJKoZIhvcNAQkDMQ0GCyqG
# SIb3DQEJEAEEMBwGCSqGSIb3DQEJBTEPFw0yMjEyMDExMjMyNTZaMC8GCSqGSIb3
# DQEJBDEiBCDoi4hTP12H8cNqr8fuonyUeZLostcoNxCDP5hjpyCcqTA3BgsqhkiG
# 9w0BCRACLzEoMCYwJDAiBCDEdM52AH0COU4NpeTefBTGgPniggE8/vZT7123H99h
# +DALBgkqhkiG9w0BAQEEggEAJj5YjhQFv83XgaGAEMIBACxmBaFOdFNBhhy5HTML
# CA8HYoTlXkkwDG38WYPc6abXGh85kdu06EBXYCpVSA5U2MCNxL8tHkkFh1nehDZs
# FWtibbfBSyj8Cs5/mnZQiisMp6NZ5Kuy9TZouuZ9mfjZDVuingTERI3OVdTRBz7F
# t5zaegthQ0VS6IO8DcG6n+SLDfjMCF4HFJ5ieezLamg6hQd/xIhQbCvfuRS8OQku
# tlGiGJ0mce/jHtpFwF+TJ96ExuWVbZyrQ38zcIaso8gjJwABB0pJxAAz6RxJl5Bq
# h3CyjwshR/QkFbNn6L75IwPKAd1T/2be1FjRMJycUPMmqA==
# SIG # End signature block
