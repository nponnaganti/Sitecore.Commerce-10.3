Function Invoke-CreateCustomPatchTask {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$EngineConnectIncludeDir
    )
	
	$pathToSource = $(Join-Path -Path $EngineConnectIncludeDir -ChildPath "\Sitecore.Commerce.Engine.Connect.config")
	$sourceXml = [xml](Get-Content $pathToSource) 

	$pathToConfig = $(Join-Path -Path $EngineConnectIncludeDir -ChildPath "\CustomCommerce")
	New-Item -Path $pathToConfig -ItemType Directory -Force

    $pathToConfig = $(Join-Path -Path $EngineConnectIncludeDir -ChildPath "\CustomCommerce\Custom.Commerce.Engine.Connect.config")
    Copy-Item $pathToSource $pathToConfig

    $newXml = [xml](Get-Content $pathToConfig) 

    $childNodes = $newXml.SelectNodes('//configuration//sitecore/child::*')   

    foreach($child in $childNodes){
        if (!$child.Name.StartsWith('commerce')) {
            [void]$child.ParentNode.RemoveChild($child)
        }

        elseif (!$child.Name.StartsWith('commerceEngine')) {
            $subNotes = $newXml.SelectNodes('//configuration//sitecore//commerceEngineConfiguration/child::*') 
            foreach($subChild in $subNotes) {
                if (!$subChild.Name.StartsWith('commerce') -and !$subChild.Name.EndsWith('Url') -and !$subChild.Name.EndsWith('Hash') -or $subChild.Name.EndsWith('Timeout')) {
                    [void]$subChild.ParentNode.RemoveChild($subChild)
                }
            }

            $subNotes = $newXml.SelectNodes("//configuration//sitecore//commerceEngineConfiguration//comment()");
            foreach($subChild in $subNotes) {
                [void]$subChild.ParentNode.RemoveChild($subChild)                
            }
        }

        elseif (!$child.Name.StartsWith('commerceCaching')) {
            $subNotes = $newXml.SelectNodes('//configuration//sitecore//commerceCachingConfiguration/child::*') 
            foreach($subChild in $subNotes) {
                if ($subChild.Name -ne 'cachingSettings') {
                    [void]$subChild.ParentNode.RemoveChild($subChild)
                } else {
                     $subSubNotes = $newXml.SelectNodes('//configuration//sitecore//commerceCachingConfiguration//cachingSettings/child::*')
                      foreach($subSubChild in $subSubNotes) {
                        if ($subSubChild.Name -ne 'redis') {
                            [void]$subSubChild.ParentNode.RemoveChild($subSubChild)
                        } else {
                            $ssSubNotes = $newXml.SelectNodes('//configuration//sitecore//commerceCachingConfiguration//cachingSettings//redis/child::*')
                            foreach($ssChild in $ssSubNotes) {
                                if ($ssChild.Name -ne 'options') {
                                    [void]$ssChild.ParentNode.RemoveChild($ssChild)
                                } 
                            }
                        }
                    }
                }
            }
        }
    }

    $newXml.Save($pathToConfig)
}

Function Invoke-UpdateRedisConnectionTask {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$EngineConnectIncludeDir,
        [Parameter(Mandatory = $true)]
        [string]$RedisConnection
    )

   $pathToConfig = $(Join-Path -Path $EngineConnectIncludeDir -ChildPath "\CustomCommerce\Custom.Commerce.Engine.Connect.config")

    $xml = [xml](Get-Content $pathToConfig)

    $subNotes = $xml.SelectNodes('//configuration//sitecore//commerceCachingConfiguration//cachingSettings//redis//options/child::*', $ns)
    foreach($childNode in $subNotes) {
        if ($childNode.Name -eq 'configuration') {          
            $attr = $childNode.SetAttributeNode("instead", "http://www.sitecore.net/xmlconfig/")
            $attr.Value="configuration"
            $childNode.InnerXml = $childNode.InnerXml -replace "localhost", "$RedisConnection" 
        } else {
            [void]$childNode.ParentNode.RemoveChild($childNode)
        }
    }
    
    $xml.Save($pathToConfig)
}

Function Invoke-UpdateHostnamesTask {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$EngineConnectIncludeDir,
        [Parameter(Mandatory = $true)]
        [string]$CommerceServicesHostPostfix
    )

    $pathToConfig = $(Join-Path -Path $EngineConnectIncludeDir -ChildPath "\CustomCommerce\Custom.Commerce.Engine.Connect.config")

    $xml = [xml](Get-Content $pathToConfig)
    $node = $xml.configuration.sitecore.commerceEngineConfiguration
    $node.shopsServiceUrl = $node.shopsServiceUrl -replace "localhost:5000", "commerceauthoring.$CommerceServicesHostPostfix"
    $node.commerceOpsServiceUrl = $node.commerceOpsServiceUrl -replace "localhost:5000", "commerceauthoring.$CommerceServicesHostPostfix"
    $node.commerceMinionsServiceUrl = $node.commerceMinionsServiceUrl -replace "localhost:5000", "commerceminions.$CommerceServicesHostPostfix"

    $subNotes = $xml.SelectNodes('//configuration//sitecore//commerceEngineConfiguration/child::*', $ns)
    foreach($childNode in $subNotes) {
        if ($childNode.Name.EndsWith('ServiceUrl')) { 
            if ($childNode.Attributes -eq $null -or $childNode.Attributes["patch:instead"] -eq $null) {         
                $attr = $childNode.SetAttributeNode("instead", "http://www.sitecore.net/xmlconfig/")
                $attr.Value= $childNode.Name 
            }           
        } 
    }

    $xml.Save($pathToConfig)
}

Function Invoke-UpdateIdServerSettingsTask {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$EngineConnectIncludeDir,
        [Parameter(Mandatory = $true)]
        [string]$SitecoreIdentityServerUrl,
        [Parameter(Mandatory = $true)]
        [string]$CommerceEngineConnectClientId,
        [Parameter(Mandatory = $true)]
        [string]$CommerceEngineConnectClientSecret
    )

    $pathToConfig = $(Join-Path -Path $EngineConnectIncludeDir -ChildPath "\CustomCommerce\Custom.Commerce.Engine.Connect.config")

    $xml = [xml](Get-Content $pathToConfig)
    $node = $xml.configuration.sitecore.commerceEngineConfiguration
    $node.sitecoreIdentityServerUrl = $SitecoreIdentityServerUrl
    $node.commerceEngineConnectClientId = $CommerceEngineConnectClientId
    $node.clientSecretHash = $CommerceEngineConnectClientSecret

    $subNotes = $xml.SelectNodes('//configuration//sitecore//commerceEngineConfiguration/child::*', $ns)
    foreach($childNode in $subNotes) {
        if ($childNode.Name -eq 'sitecoreIdentityServerUrl' -or $childNode.Name -eq 'commerceEngineConnectClientId' -or $childNode.Name -eq 'clientSecretHash') { 
            $attr = $childNode.SetAttributeNode("instead", "http://www.sitecore.net/xmlconfig/")
            $attr.Value= $childNode.Name                    
        } 
    }

    $xml.Save($pathToConfig)
}

Function Invoke-UpdatePortsTask {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$EngineConnectIncludeDir,
        [Parameter(Mandatory = $true)]
        [string]$CommerceAuthoringServicesPort,
        [Parameter(Mandatory = $true)]
        [string]$CommerceMinionsServicesPort
    )

    $pathToConfig = $(Join-Path -Path $EngineConnectIncludeDir -ChildPath "\CustomCommerce\Custom.Commerce.Engine.Connect.config")

    $xml = [xml](Get-Content $pathToConfig)
    $node = $xml.configuration.sitecore.commerceEngineConfiguration
    $node.shopsServiceUrl = $node.shopsServiceUrl -replace "5000", $CommerceAuthoringServicesPort
    $node.commerceOpsServiceUrl = $node.commerceOpsServiceUrl -replace "5000", $CommerceAuthoringServicesPort
    $node.commerceMinionsServiceUrl = $node.commerceMinionsServiceUrl -replace "5000", $CommerceMinionsServicesPort

    $subNotes = $xml.SelectNodes('//configuration//sitecore//commerceEngineConfiguration/child::*', $ns)
    foreach($childNode in $subNotes) {
        if ($childNode.Name.EndsWith('ServiceUrl')) { 
            if ($childNode.Attributes -eq $null -or $childNode.Attributes["patch:instead"] -eq $null) {         
                $attr = $childNode.SetAttributeNode("instead", "http://www.sitecore.net/xmlconfig/")
                $attr.Value= $childNode.Name 
            }           
        } 
    }

    $xml.Save($pathToConfig)
}

Function Invoke-GetIdServerTokenTask {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [psobject[]]$SitecoreAdminAccount,
        [Parameter(Mandatory = $true)]
        [string]$UrlIdentityServerGetToken
    )

    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Content-Type", 'application/x-www-form-urlencoded')
    $headers.Add("Accept", 'application/json')

    $body = @{
        password   = $SitecoreAdminAccount.password
        grant_type = 'password'
        username   = $SitecoreAdminAccount.userName
        client_id  = 'postman-api'
        scope      = 'openid EngineAPI postman_api'
    }

    Write-Host "Get Token From Sitecore.IdentityServer" -ForegroundColor Green
    $response = Invoke-RestMethod $UrlIdentityServerGetToken -Method Post -Body $body -Headers $headers
    Write-Host "Bearer {0} "$response.access_token -ForegroundColor Green

    $global:sitecoreIdToken = "Bearer {0}" -f $response.access_token
}

Function Invoke-BootStrapCommerceServicesTask {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$UrlCommerceOpsServicesBootstrap
    )
    Write-Host "BootStrapping Commerce Services: $($UrlCommerceOpsServicesBootstrap)" -ForegroundColor Yellow
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", $global:sitecoreIdToken)
    Invoke-RestMethod $UrlCommerceOpsServicesBootstrap -TimeoutSec 1200 -Method POST -Headers $headers
    Write-Host "Commerce Services BootStrapping completed" -ForegroundColor Green
}

Function Invoke-InitializeCommerceServicesTask {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$UrlInitializeEnvironment,
        [Parameter(Mandatory = $true)]
        [string]$UrlCheckCommandStatus,
        [Parameter(Mandatory = $true)]
        [string[]]$Environments,
        [Parameter(Mandatory = $false)]
        [boolean]$DeploySampleData = $true)

    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", $global:sitecoreIdToken);

    foreach ($env in $Environments) {
        Write-Host "Initializing $($env) ..." -ForegroundColor Yellow

        $initializeUrl = $UrlInitializeEnvironment

        $payload = @{
            "environment" = $env;
            "sampleData" = $DeploySampleData;
        }

        $result = Invoke-RestMethod $initializeUrl -TimeoutSec 1200 -Method POST -Body ($payload | ConvertTo-Json) -Headers $headers -ContentType "application/json"
        $checkUrl = $UrlCheckCommandStatus -replace "taskIdValue", $result.TaskId

        $sw = [system.diagnostics.stopwatch]::StartNew()
        $tp = New-TimeSpan -Minute 10
        do {
            Start-Sleep -s 30
            Write-Host "Checking if $($checkUrl) has completed ..." -ForegroundColor White
            $result = Invoke-RestMethod $checkUrl -TimeoutSec 1200 -Method Get -Headers $headers -ContentType "application/json"

            if ($result.ResponseCode -ne "Ok") {
                $(throw Write-Host "Initialize environment $($env) failed, please check Engine service logs for more info." -Foregroundcolor Red)
            }
        } while ($result.Status -ne "RanToCompletion" -and $sw.Elapsed -le $tp)

        if ($result.Status -ne "RanToCompletion") {
            $(throw Write-Host "Initialize environment $($env) timed out, please check Engine service logs for more info." -Foregroundcolor Red)
        }

        Write-Host "Initialization for $($env) completed ..." -ForegroundColor Green
    }

    Write-Host "Initialization completed ..." -ForegroundColor Green
}

Function Invoke-IndexEngineItemsTask {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ListToWatch,
        [Parameter(Mandatory = $true)]
        [string]$UrlRunMinion,
        [Parameter(Mandatory = $true)]
        [string[]]$MinionEnvironments,
        [Parameter(Mandatory = $true)]
        [string]$UrlCheckCommandStatus)

    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", $global:sitecoreIdToken);

    foreach ($env in $MinionEnvironments) {
        Write-Host "Indexing $($env) ..." -ForegroundColor Yellow
        Write-Host "ListToWatch: $($ListToWatch) ..." -ForegroundColor Yellow

        $payload = @{
            'minionFullName'  = 'Sitecore.Commerce.Plugin.Search.FullIndexMinion, Sitecore.Commerce.Plugin.Search';
            'environmentName' = $env;
            'policies'        = @(@{
                    '@odata.type'     = '#Sitecore.Commerce.Core.RunMinionPolicy';
                    'WithListToWatch' = "$ListToWatch";
                })
        }

        $result = Invoke-RestMethod $UrlRunMinion -TimeoutSec 1200 -Method POST -Body ($payload | ConvertTo-Json) -Headers $headers -ContentType "application/json"
        $checkUrl = $UrlCheckCommandStatus -replace "taskIdValue", $result.TaskId

        $sw = [system.diagnostics.stopwatch]::StartNew()
        $tp = New-TimeSpan -Minute 10
        do {
            Start-Sleep -s 30
            Write-Host "Checking if $($checkUrl) has completed ..." -ForegroundColor White
            $result = Invoke-RestMethod $checkUrl -TimeoutSec 1200 -Method Get -Headers $headers -ContentType "application/json"

            if ($result.ResponseCode -ne "Ok") {
                $(throw Write-Host "Indexing catalog items for $($env) failed, please check Engine service logs for more info." -Foregroundcolor Red)
            }
        } while ($result.Status -ne "RanToCompletion" -and $sw.Elapsed -le $tp)

        Write-Host "Indexing for $($env) completed ..." -ForegroundColor Green
    }

    Write-Host "Indexing completed ..." -ForegroundColor Green
}

Function Invoke-EnableCsrfValidationTask {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$CommerceServicesPathCollection
    )

    foreach ($path in $CommerceServicesPathCollection) {
        $pathToJson = $(Join-Path -Path $path -ChildPath "wwwroot\config.json")
        $originalJson = Get-Content $pathToJson -Raw | ConvertFrom-Json
        $originalJson.AppSettings.AntiForgeryEnabled = $true
        $originalJson | ConvertTo-Json -Depth 100 | set-content $pathToJson
    }
}

Function Invoke-DisableCsrfValidationTask {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$CommerceServicesPathCollection
    )
    foreach ($path in $CommerceServicesPathCollection) {
        $pathToJson = $(Join-Path -Path $path -ChildPath "wwwroot\config.json")
        $originalJson = Get-Content $pathToJson -Raw | ConvertFrom-Json
        $originalJson.AppSettings.AntiForgeryEnabled = $false
        $originalJson | ConvertTo-Json -Depth 100 | set-content $pathToJson
    }
}

Function Invoke-UpdateCeConnectClientId {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$CommerceServicesPathCollection,
        [Parameter(Mandatory = $true)]
        [string]$CommerceEngineConnectClientId
    )
    foreach ($path in $CommerceServicesPathCollection) {
        $pathToJson = $(Join-Path -Path $path -ChildPath "wwwroot\config.json")
        $originalJson = Get-Content $pathToJson -Raw | ConvertFrom-Json
        $originalJson.CommerceConnector.ClientId = $CommerceEngineConnectClientId
        $originalJson | ConvertTo-Json -Depth 100 | set-content $pathToJson
    }
}

Function Invoke-EnsureSyncDefaultContentPathsTask {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$UrlEnsureSyncDefaultContentPaths,
        [Parameter(Mandatory = $true)]
        [string]$UrlCheckCommandStatus,
        [Parameter(Mandatory = $true)]
        [string[]]$Environments)

    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", $global:sitecoreIdToken);

    foreach ($env in $Environments) {
        Write-Host "Ensure/Sync default content paths for: $($env)" -ForegroundColor Yellow

        $ensureUrl = $UrlEnsureSyncDefaultContentPaths -replace "envNameValue", $env
        $payload = @{
            "environment" = $env;
            "shopName"    = "CommerceEngineDefaultStorefront";
        }
        $result = Invoke-RestMethod $ensureUrl -TimeoutSec 1200 -Method POST -Body ($payload | ConvertTo-Json)  -Headers $headers  -ContentType "application/json"
        $checkUrl = $UrlCheckCommandStatus -replace "taskIdValue", $result.TaskId

        $sw = [system.diagnostics.stopwatch]::StartNew()
        $tp = New-TimeSpan -Minute 10
        do {
            Start-Sleep -s 30
            Write-Host "Checking if $($checkUrl) has completed ..." -ForegroundColor White
            $result = Invoke-RestMethod $checkUrl -TimeoutSec 1200 -Method Get -Headers $headers -ContentType "application/json"

            if ($result.ResponseCode -ne "Ok") {
                $(throw Write-Host "Ensure/Sync default content paths for environment $($env) failed, please check Engine service logs for more info." -Foregroundcolor Red)
            }

        } while ($result.Status -ne "RanToCompletion" -and $sw.Elapsed -le $tp)

        if ($result.Status -ne "RanToCompletion") {
            $(throw Write-Host "Ensure/Sync default content paths for environment $($env) timed out, please check Engine service logs for more info." -Foregroundcolor Red)
        }

        Write-Host "Ensure/Sync default content paths for $($env) completed ..." -ForegroundColor Green
    }

    Write-Host "Ensure/Sync default content paths completed ..." -ForegroundColor Green
}

Register-SitecoreInstallExtension -Command Invoke-CreateCustomPatchTask -As CreateCustomPatch -Type Task -Force

Register-SitecoreInstallExtension -Command Invoke-UpdateRedisConnectionTask -As UpdateRedisConnection -Type Task -Force

Register-SitecoreInstallExtension -Command Invoke-UpdateHostnamesTask -As UpdateHostnames -Type Task -Force

Register-SitecoreInstallExtension -Command Invoke-UpdateIdServerSettingsTask -As UpdateIdServerSettings -Type Task -Force

Register-SitecoreInstallExtension -Command Invoke-UpdatePortsTask -As UpdatePorts -Type Task -Force

Register-SitecoreInstallExtension -Command Invoke-GetIdServerTokenTask -As GetIdServerToken -Type Task -Force

Register-SitecoreInstallExtension -Command Invoke-BootStrapCommerceServicesTask -As BootStrapCommerceServices -Type Task -Force

Register-SitecoreInstallExtension -Command Invoke-InitializeCommerceServicesTask -As InitializeCommerceServices -Type Task -Force

Register-SitecoreInstallExtension -Command Invoke-IndexEngineItemsTask -As IndexEngineItems -Type Task -Force

Register-SitecoreInstallExtension -Command Invoke-EnableCsrfValidationTask -As EnableCsrfValidation -Type Task -Force

Register-SitecoreInstallExtension -Command Invoke-DisableCsrfValidationTask -As DisableCsrfValidation -Type Task -Force

Register-SitecoreInstallExtension -Command Invoke-EnsureSyncDefaultContentPathsTask -As EnsureSyncDefaultContentPaths -Type Task -Force

Register-SitecoreInstallExtension -Command Invoke-UpdateCeConnectClientId -As UpdateCeConnectClientId -Type Task -Force

# SIG # Begin signature block
# MIImLgYJKoZIhvcNAQcCoIImHzCCJhsCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCnw0nU8FoVN2VU
# 7V5LDNGARbsqdMF9exVfZy7x13nfCaCCFBUwggWQMIIDeKADAgECAhAFmxtXno4h
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
# MBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBH
# 4XfE5u/oEcrYhpCsYApEU/VdToOyKCULd5/mnR/fCzANBgkqhkiG9w0BAQEFAASC
# AgCHELzn4biGSBn49R5M/Ep2jbGye1WwcSDcUzd68ynSJfz0Nh75OVqGaks6s5AJ
# 63tN38t2s8J7HBIweDgyfBx8qNAYIfprdPeFkmZ9Gi0EQhqPkTfCmHBVF34kfPSg
# Fw1d1MqQ4zMlghtXDDOwijxcEOuiLBBUfiTFnRTooKxc4Ag+nHiYww05a+KqMZtW
# YK3Tc6NeZh+SoZbF1B7zfQMms1bLcezxwfahZMUAZKB1ykMn29+1XV9/vMxBqWhr
# qSd5vIrsT+7xP15R2gX4bLCprceiQ+gLg7fAhN918WlqlRuSQvBOlGOu6LedhweM
# dlD9SDm4KBQPDA8EizfO1MHAnCkv+RzjQuRhq0NaUTQ+afwatc9s6g+ZpUVdvBrK
# ge+BSKf8uJ3gpYCJ7vInN6D3ZDDF2OJPp0jng7Hwnp10wS57xOZC5J+V6xXbcqcd
# AH3qpcAzqGXc6B/V62ICeoFdsH/PQ6NBmym06Vu5BIMxTXoH9NnBVOrX2FUuyJpL
# 6lLg4/R9f4FnPRiiUouizlodbww1nYnp0ksW1boBuNjP82Rnlj4DnITqCehkjmHJ
# u9yMvFBIU9vZCh7kISN1LHOJn+KOVGeoIlTT8SH0WA/dJy2+WEDa8ut0BDLFrHjy
# DUPAEgXCKamYPT1eU+aw/tN5bHowvFGlSX4865Wdty8iBKGCDjwwgg44BgorBgEE
# AYI3AwMBMYIOKDCCDiQGCSqGSIb3DQEHAqCCDhUwgg4RAgEDMQ0wCwYJYIZIAWUD
# BAIBMIIBDgYLKoZIhvcNAQkQAQSggf4EgfswgfgCAQEGC2CGSAGG+EUBBxcDMDEw
# DQYJYIZIAWUDBAIBBQAEIIW1kihY1t/ckhKD83c3YxUgd5k1TQhOvDBLJfSLy5Ou
# AhRJ3RyjSsqM3Hx6bEqdmU7ID8TCAxgPMjAyMjEyMDExMjMzMDJaMAMCAR6ggYak
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
# SIb3DQEJEAEEMBwGCSqGSIb3DQEJBTEPFw0yMjEyMDExMjMzMDJaMC8GCSqGSIb3
# DQEJBDEiBCChlNeQMw7bEuicJIg/uFOTNWdHC7W4vzjLINasmj68DzA3BgsqhkiG
# 9w0BCRACLzEoMCYwJDAiBCDEdM52AH0COU4NpeTefBTGgPniggE8/vZT7123H99h
# +DALBgkqhkiG9w0BAQEEggEAfXKpGm0JgapJZC5dG7WRYYOORI/vIP5jmoNjwnHs
# 1SDCWSsgkyzeAE7zPEupGkRZvPmoBXwgDu+Z3Y0bgXyQxv49oZN1D0jvcFhEQ5nQ
# utaCTNloEwl1BZ44Dnyi+D7+lkXsxDEGNiEvg9dnbln3d7mCJCPml1wnF8OJCSe3
# gAtPkWj0RITvB46pdeCjjpnze4nSbRiDCqFd9xL8SxI775kfvGQxXd+di6wrFl+Z
# 93xXj8i7v7oeTkNjnVOxbioO9Uo+pxKuGxqIiuC7m+1XjZ0/kXqPAADLkDLXvphX
# hS4Z7RNwWpVx+VrHVBv6lvmmbwY4e4FM8fdqSi20MZfkwA==
# SIG # End signature block
