Function Invoke-InstallModuleTask {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ModuleFullPath,
        [Parameter(Mandatory = $true)]
        [string]$ModulesDirDst,
        [Parameter(Mandatory = $true)]
        [string]$BaseUrl
    )

    Copy-Item $ModuleFullPath -destination $ModulesDirDst -force

    $moduleToInstall = Split-Path -Path $ModuleFullPath -Leaf -Resolve

    Write-Host "Installing module: " $moduleToInstall -ForegroundColor Green
    $urlInstallModules = $BaseUrl + "/InstallModules.aspx?modules=" + $moduleToInstall
    Write-Host $urlInstallModules
    Invoke-RestMethod $urlInstallModules -TimeoutSec 1200
}

Function Invoke-CreateDefaultStorefrontTask {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BaseUrl,
        [Parameter(Mandatory = $false)]
        [string]$scriptName = "CreateDefaultStorefrontTenantAndSite",
        [Parameter(Mandatory = $false)]
        [string]$siteName = "",
        [Parameter(Mandatory = $true)]
        [string]$sitecoreUsername,
        [Parameter(Mandatory = $true)]
        [string]$sitecoreUserPassword
    )

    if ($siteName -ne "") {
        Write-Host "Restarting the website and application pool for $siteName ..." -ForegroundColor Green
        Import-Module WebAdministration

        Stop-WebSite $siteName

        if ((Get-WebAppPoolState $siteName).Value -ne 'Stopped') {
            Stop-WebAppPool -Name $siteName
        }

        Start-WebAppPool -Name $siteName
        Start-WebSite $siteName
        Write-Host "Restarting the website and application pool for $siteName complete..." -ForegroundColor Green
    }

    Write-Host "Creating the default storefront..." -ForegroundColor Green

    #Added Try catch to avoid deployment failure due to an issue in SPE 4.7.1 - Once fixed, we can remove this
    Try {
        $urlPowerShellScript = $BaseUrl + "/-/script/v2/master/$($scriptName)?user=$($sitecoreUsername)&password=$($sitecoreUserPassword)"
        Invoke-RestMethod $urlPowerShellScript -TimeoutSec 1200
    }
    Catch {
        $errorMessage = $_.Exception.Message
        Write-Host "Error occured: $errorMessage ..." -ForegroundColor Red
    }

    Write-Host "Creating the default storefront complete..." -ForegroundColor Green
}

Function Invoke-DisableConfigFilesTask {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ConfigDir,
        [parameter(Mandatory = $true)]
        [string[]]$ConfigFileList
    )

    foreach ($configFileName in $ConfigFileList) {
        Write-Host "Disabling config file: $configFileName" -ForegroundColor Green
        $configFilePath = Join-Path $ConfigDir -ChildPath $configFileName
        $disabledFilePath = "$configFilePath.disabled"

        if (Test-Path $configFilePath) {
            Rename-Item -Path $configFilePath -NewName $disabledFilePath
            Write-Host "  successfully disabled $configFilePath"
        }
        else {
            Write-Host "  configuration file not found." -ForegroundColor Red
        }
    }
}

Function Invoke-EnableConfigFilesTask {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ConfigDir,
        [parameter(Mandatory = $true)]
        [string[]]$ConfigFileList
    )

    foreach ($configFileName in $ConfigFileList) {
        Write-Host "Enabling config file: $configFileName" -ForegroundColor Green
        $configFilePath = Join-Path $ConfigDir -ChildPath $configFileName
        $disabledFilePath = "$configFilePath.disabled"
        $exampleFilePath = "$configFilePath.example"

        if (Test-Path $configFilePath) {
            Write-Host "  config file is already enabled..."
        }
        elseif (Test-Path $disabledFilePath) {
            Rename-Item -Path $disabledFilePath -NewName $configFileName
            Write-Host "  successfully enabled $disabledFilePath"
        }
        elseif (Test-Path $exampleFilePath) {
            Rename-Item -Path $exampleFilePath -NewName $configFileName
            Write-Host "  successfully enabled $exampleFilePath"
        }
        else {
            Write-Host "  configuration file not found." -ForegroundColor Red
        }
    }
}

Function Invoke-ExpandArchive {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SourceZip,
        [parameter(Mandatory = $true)]
        [string]$DestinationPath
    )

    Expand-Archive $SourceZip -DestinationPath $DestinationPath -Force
}

Function Invoke-NewCommerceSignedCertificateTask {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param
    (
        [Parameter(Mandatory)]
        [ValidateScript( { $_.HasPrivateKey -eq $true })]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Signer,
        [ValidateScript( { $_.StartsWith("Cert:\", "CurrentCultureIgnoreCase") })]
        [ValidateScript( { Test-Path $_ -Type Container })]
        [string]$CertStoreLocation = 'Cert:\LocalMachine\My',
        [ValidateNotNullOrEmpty()]
        [string]$DnsName = '127.0.0.1',
        [ValidateNotNullOrEmpty()]
        [string]$FriendlyName = "Sitecore Commerce Services SSL Certificate",
        [ValidateScript( { Test-Path $_ -Type Container })]
        [string]$Path,
        [string]$Name = 'localhost'
    )
    Write-Host "Creating self-signed certificate for $Name" -ForegroundColor Yellow
    $params = @{
        CertStoreLocation = $CertStoreLocation.Split('\')[1]
        DnsNames          = $DnsName
        FriendlyName      = $FriendlyName
        Signer            = $Signer
    }
    # Get or create self-signed certificate for localhost
    $certificates = Get-ChildItem -Path $CertStoreLocation -DnsName $DnsName | Where-Object { $_.FriendlyName -eq $FriendlyName }
    if ($certificates.Length -eq 0) {
        Write-Host "Create new self-signed certificate"
        NewCertificate @params
    }
    else {
        Write-Host "Reuse existing self-signed certificate"
    }
    Write-Host "Created self-signed certificate for $Name" -ForegroundColor Green
}

# This function is a complete copy from SIF/Private/Certificates.ps1 and should be removed together with Invoke-NewCommerceSignedCertificateTask later.
function NewCertificate {
    param(
        [string]$FriendlyName = "Sitecore Install Framework",
        [string[]]$DNSNames = "127.0.0.1",
        [ValidateSet("LocalMachine", "CurrentUser")]
        [string]$CertStoreLocation = "LocalMachine",
        [ValidateScript( { $_.HasPrivateKey })]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Signer
    )
    # DCOM errors in System Logs are by design.
    # https://support.microsoft.com/en-gb/help/4022522/dcom-event-id-10016-is-logged-in-windows-10-and-windows-server-2016
    $date = Get-Date
    $certificateLocation = "Cert:\\$CertStoreLocation\My"
    $rootCertificateLocation = "Cert:\\$CertStoreLocation\Root"
    # Certificate Creation Location.
    $location = @{ }
    if ($CertStoreLocation -eq "LocalMachine") {
        $location.MachineContext = $true
        $location.Value = 2 # Machine Context
    }
    else {
        $location.MachineContext = $false
        $location.Value = 1 # User Context
    }
    # RSA Object
    $rsa = New-Object -ComObject X509Enrollment.CObjectId
    $rsa.InitializeFromValue(([Security.Cryptography.Oid]"RSA").Value)
    # SHA256 Object
    $sha256 = New-Object -ComObject X509Enrollment.CObjectId
    $sha256.InitializeFromValue(([Security.Cryptography.Oid]"SHA256").Value)
    # Subject
    $subject = "CN=$($DNSNames[0]), O=DO_NOT_TRUST, OU=Created by https://www.sitecore.com"
    $subjectDN = New-Object -ComObject X509Enrollment.CX500DistinguishedName
    $subjectDN.Encode($Subject, 0x0)
    # Subject Alternative Names
    $san = New-Object -ComObject X509Enrollment.CX509ExtensionAlternativeNames
    $names = New-Object -ComObject X509Enrollment.CAlternativeNames
    foreach ($sanName in $DNSNames) {
        $name = New-Object -ComObject X509Enrollment.CAlternativeName
        $name.InitializeFromString(3, $sanName)
        $names.Add($name)
    }
    $san.InitializeEncode($names)
    # Private Key
    $privateKey = New-Object -ComObject X509Enrollment.CX509PrivateKey
    $privateKey.ProviderName = "Microsoft Enhanced RSA and AES Cryptographic Provider"
    $privateKey.Length = 2048
    $privateKey.ExportPolicy = 1 # Allow Export
    $privateKey.KeySpec = 1
    $privateKey.Algorithm = $rsa
    $privateKey.MachineContext = $location.MachineContext
    $privateKey.Create()
    # Certificate Object
    $certificate = New-Object -ComObject X509Enrollment.CX509CertificateRequestCertificate
    $certificate.InitializeFromPrivateKey($location.Value, $privateKey, "")
    $certificate.Subject = $subjectDN
    $certificate.NotBefore = ($date).AddDays(-1)
    if ($Signer) {
        # WebServer Certificate
        # WebServer Extensions
        $usage = New-Object -ComObject X509Enrollment.CObjectIds
        $keys = '1.3.6.1.5.5.7.3.2', '1.3.6.1.5.5.7.3.1' #Client Authentication, Server Authentication
        foreach ($key in $keys) {
            $keyObj = New-Object -ComObject X509Enrollment.CObjectId
            $keyObj.InitializeFromValue($key)
            $usage.Add($keyObj)
        }
        $webserverEnhancedKeyUsage = New-Object -ComObject X509Enrollment.CX509ExtensionEnhancedKeyUsage
        $webserverEnhancedKeyUsage.InitializeEncode($usage)
        $webserverBasicKeyUsage = New-Object -ComObject X509Enrollment.CX509ExtensionKeyUsage
        $webserverBasicKeyUsage.InitializeEncode([Security.Cryptography.X509Certificates.X509KeyUsageFlags]"DataEncipherment")
        $webserverBasicKeyUsage.Critical = $true
        # Signing CA cert needs to be in MY Store to be read as we need the private key.
        Move-Item -Path $Signer.PsPath -Destination $certificateLocation -Confirm:$false
        $signerCertificate = New-Object -ComObject X509Enrollment.CSignerCertificate
        $signerCertificate.Initialize($location.MachineContext, 0, 0xc, $Signer.Thumbprint)
        # Return the signing CA cert to the original location.
        Move-Item -Path "$certificateLocation\$($Signer.PsChildName)" -Destination $Signer.PSParentPath -Confirm:$false
        # Set issuer to root CA.
        $issuer = New-Object -ComObject X509Enrollment.CX500DistinguishedName
        $issuer.Encode($signer.Issuer, 0)
        $certificate.Issuer = $issuer
        $certificate.SignerCertificate = $signerCertificate
        $certificate.NotAfter = ($date).AddDays(36500)
        $certificate.X509Extensions.Add($webserverEnhancedKeyUsage)
        $certificate.X509Extensions.Add($webserverBasicKeyUsage)
    }
    else {
        # Root CA
        # CA Extensions
        $rootEnhancedKeyUsage = New-Object -ComObject X509Enrollment.CX509ExtensionKeyUsage
        $rootEnhancedKeyUsage.InitializeEncode([Security.Cryptography.X509Certificates.X509KeyUsageFlags]"DigitalSignature,KeyEncipherment,KeyCertSign")
        $rootEnhancedKeyUsage.Critical = $true
        $basicConstraints = New-Object -ComObject X509Enrollment.CX509ExtensionBasicConstraints
        $basicConstraints.InitializeEncode($true, -1)
        $basicConstraints.Critical = $true
        $certificate.Issuer = $subjectDN #Same as subject for root CA
        $certificate.NotAfter = ($date).AddDays(36500)
        $certificate.X509Extensions.Add($rootEnhancedKeyUsage)
        $certificate.X509Extensions.Add($basicConstraints)
    }
    $certificate.X509Extensions.Add($san) # Add SANs to Certificate
    $certificate.SignatureInformation.HashAlgorithm = $sha256
    $certificate.AlternateSignatureAlgorithm = $false
    $certificate.Encode()
    # Insert Certificate into Store
    $enroll = New-Object -ComObject X509Enrollment.CX509enrollment
    $enroll.CertificateFriendlyName = $FriendlyName
    $enroll.InitializeFromRequest($certificate)
    $certificateData = $enroll.CreateRequest(1)
    $enroll.InstallResponse(2, $certificateData, 1, "")
    # Retrieve thumbprint from $certificateData
    $certificateByteData = [System.Convert]::FromBase64String($certificateData)
    $createdCertificate = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2
    $createdCertificate.Import($certificateByteData)
    # Locate newly created certificate.
    $newCertificate = Get-ChildItem -Path $certificateLocation | Where-Object { $_.Thumbprint -Like $createdCertificate.Thumbprint }
    # Move CA to root store.
    if (!$Signer) {
        Move-Item -Path $newCertificate.PSPath -Destination $rootCertificateLocation
        $newCertificate = Get-ChildItem -Path $rootCertificateLocation | Where-Object { $_.Thumbprint -Like $createdCertificate.Thumbprint }
    }
    return $newCertificate
}

Function Invoke-OpenConnectionTask {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ConnString
    )

    try {
        $global:SqlConnection = New-Object System.Data.SqlClient.SqlConnection
        $global:SqlConnection.ConnectionString = $ConnString.Replace('\\', '\')
        $global:SqlConnection.Open()
        $global:SqlTransaction = $global:SqlConnection.BeginTransaction()
    }
    catch {
        Write-Host "An error happened in OpenConnection, transaction will be rollbacked..." -ForegroundColor Red
        $global:SqlTransaction.Rollback()
        foreach ( $errorRecord in $Error ) {
            Write-Host -Object $errorRecord -ForegroundColor Red
            Write-Host -Object $errorRecord.InvocationInfo.PositionMessage -ForegroundColor Red
        }
    }
}

Function Invoke-CloseConnectionTask {
    $global:SqlTransaction.Commit();
    $global:SqlConnection.Close();
}

Function Invoke-CreateRoleTask {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ConnString,
        [Parameter(Mandatory = $true)]
        [string]$RoleName,
        [string]$ApplicationName = "sitecore"
    )

    Write-Host "Create Role $RoleName" -ForegroundColor Green
    try {
        Invoke-OpenConnectionTask $ConnString

        $SqlCommand = $global:SqlConnection.CreateCommand()
        $SqlCommand.Transaction = $global:SqlTransaction
        $SqlCommand.CommandText = "[dbo].[aspnet_Roles_CreateRole]"
        $SqlCommand.CommandType = [System.Data.CommandType]::StoredProcedure
        $SqlCommand.Parameters.AddWithValue("@ApplicationName", $ApplicationName) | Out-Null
        $SqlCommand.Parameters.AddWithValue("@RoleName", $RoleName) | Out-Null
        $SqlCommand.ExecuteNonQuery()
    }
    catch {
        Write-Host "An error happened, transaction will be rollbacked..." -ForegroundColor Red
        $global:SqlTransaction.Rollback()
        foreach ( $errorRecord in $Error ) {
            Write-Host -Object $errorRecord -ForegroundColor Red
            Write-Host -Object $errorRecord.InvocationInfo.PositionMessage -ForegroundColor Red
        }
    }
    finally {
        Invoke-CloseConnectionTask
    }
}

Function Invoke-AddRolesToUserTask {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ConnString,
        [Parameter(Mandatory = $true)]
        [string]$UserName,
        [Parameter(Mandatory = $true)]
        [string]$RoleNames,
        [string]$ApplicationName = "sitecore"
    )

    Write-Host "Add user $UserName to roles $RoleNames" -ForegroundColor Green
    try {
        Invoke-OpenConnectionTask $ConnString

        $SqlCommand = $global:SqlConnection.CreateCommand()
        $SqlCommand.Transaction = $global:SqlTransaction
        $SqlCommand.CommandText = "[dbo].[aspnet_UsersInRoles_AddUsersToRoles]"
        $SqlCommand.CommandType = [System.Data.CommandType]::StoredProcedure
        $SqlCommand.Parameters.AddWithValue("@ApplicationName", $ApplicationName) | Out-Null
        $SqlCommand.Parameters.AddWithValue("@UserNames", $UserName) | Out-Null
        $SqlCommand.Parameters.AddWithValue("@RoleNames", $RoleNames) | Out-Null
        $SqlCommand.Parameters.AddWithValue("@CurrentTimeUtc", (Get-Date)) | Out-Null
        $SqlCommand.ExecuteNonQuery();
    }
    catch {
        Write-Host "An error happened, transaction will be rollbacked..." -ForegroundColor Red
        $global:SqlTransaction.Rollback()
        foreach ( $errorRecord in $Error ) {
            Write-Host -Object $errorRecord -ForegroundColor Red
            Write-Host -Object $errorRecord.InvocationInfo.PositionMessage -ForegroundColor Red
        }
    }
    finally {
        Invoke-CloseConnectionTask
    }
}

Function Invoke-AddRoleToRoleTask {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ConnString,
        [Parameter(Mandatory = $true)]
        [string]$MemberRoleName,
        [Parameter(Mandatory = $true)]
        [string]$TargetRoleName,
        [string]$ApplicationName = ""
    )

    Write-Host "Add member role $MemberRoleName to target role $TargetRoleName" -ForegroundColor Green
    try {
        Invoke-OpenConnectionTask $ConnString

        $SqlCommand = $global:SqlConnection.CreateCommand()
        $SqlCommand.Transaction = $global:SqlTransaction
        $SqlCommand.CommandText = "INSERT INTO RolesInRoles (MemberRoleName, TargetRoleName, ApplicationName, Created) VALUES (@MemberRoleName, @TargetRoleName, @ApplicationName, @CurrentTimeUtc)"
        $SqlCommand.Parameters.AddWithValue("@MemberRoleName", $MemberRoleName) | Out-Null
        $SqlCommand.Parameters.AddWithValue("@TargetRoleName", $TargetRoleName) | Out-Null
        $SqlCommand.Parameters.AddWithValue("@ApplicationName", $ApplicationName) | Out-Null
        $SqlCommand.Parameters.AddWithValue("@CurrentTimeUtc", (Get-Date)) | Out-Null
        $SqlCommand.ExecuteNonQuery()
    }
    catch {
        Write-Host "An error happened, transaction will be rollbacked..." -ForegroundColor Red
        $global:SqlTransaction.Rollback()
        foreach ( $errorRecord in $Error ) {
            Write-Host -Object $errorRecord -ForegroundColor Red
            Write-Host -Object $errorRecord.InvocationInfo.PositionMessage -ForegroundColor Red
        }
    }
    finally {
        Invoke-CloseConnectionTask
    }
}

Function Invoke-ClearRedisTask {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RedisCliPath,
        [Parameter(Mandatory = $true)]
        [string]$RedisHost,
        [Parameter(Mandatory = $true)]
        [string]$RedisPort,
        [Parameter(Mandatory = $true)]
        [string[]]$EnvironmentsGuids
    )

    if (!(Test-Path $RedisCliPath -PathType leaf)) {
        Write-Host "Redis cache was not flushed. Redis-cli executable was not found." -ForegroundColor Red
        return
    }

    Write-Host "Using Redis on [$RedisHost`:$RedisPort]"

    foreach ($envGuid in $EnvironmentsGuids) {
        Write-Host "Clean Redis * $envGuid *" -ForegroundColor Green

        $keys = & $RedisCliPath -h $RedisHost -p $RedisPort KEYS "*$envGuid*"
        if (-Not ([string]::IsNullOrEmpty($keys))) {
            $keys | ForEach-Object { & $RedisCliPath -h $RedisHost -p $RedisPort DEL $_ } | Out-Null
        }

        Write-Host "Clean Redis * $envGuid * ... done" -ForegroundColor Green
    }
}

Function Invoke-ReplaceConfigFunction {
    param(
        [Parameter(Mandatory)] [String]$String,
        [Parameter(Mandatory)] [String]$OldValue,
        [Parameter(Mandatory)] [String]$NewValue
    )

    Write-Verbose -Message $PSCmdlet.MyInvocation.MyCommand
    Write-Verbose -Message "String $String will have by $OldValue replaced by $NewValue"

    $result = ($String).Replace($OldValue, $NewValue)

    Write-Verbose "Result: $result"
    return $result
}

Register-SitecoreInstallExtension -Command Invoke-NewCommerceSignedCertificateTask -As NewCommerceSignedCertificate -Type Task -Force
Register-SitecoreInstallExtension -Command Invoke-InstallModuleTask -As InstallModule -Type Task -Force
Register-SitecoreInstallExtension -Command Invoke-EnableConfigFilesTask -As EnableConfigFiles -Type Task -Force
Register-SitecoreInstallExtension -Command Invoke-DisableConfigFilesTask -As DisableConfigFiles -Type Task -Force
Register-SitecoreInstallExtension -Command Invoke-CreateDefaultStorefrontTask -As CreateDefaultStorefront -Type Task -Force
Register-SitecoreInstallExtension -Command Invoke-ExpandArchive -As ExpandArchive -Type Task -Force
Register-SitecoreInstallExtension -Command Invoke-OpenConnectionTask -As OpenConnection -Type Task -Force
Register-SitecoreInstallExtension -Command Invoke-CloseConnectionTask -As CloseConnection -Type Task -Force
Register-SitecoreInstallExtension -Command Invoke-CreateRoleTask -As CreateRole -Type Task -Force
Register-SitecoreInstallExtension -Command Invoke-AddRolesToUserTask -As AddRolesToUser -Type Task -Force
Register-SitecoreInstallExtension -Command Invoke-AddRoleToRoleTask -As AddRoleToRole -Type Task -Force
Register-SitecoreInstallExtension -Command Invoke-ClearRedisTask -As ClearRedis -Type Task -Force
Register-SitecoreInstallExtension -Command Invoke-ReplaceConfigFunction -As replace -Type ConfigFunction -Force

# SIG # Begin signature block
# MIImLgYJKoZIhvcNAQcCoIImHzCCJhsCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBPBsNWTYg7w7r9
# l5YZ0cZFp1tuYyTHy94sVhUygM1ZoqCCFBUwggWQMIIDeKADAgECAhAFmxtXno4h
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
# MBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCB9
# 2Sb0b+PQNqoJ6kkH5ZUHL0j/Zl03/lgjOcyLyJaP7DANBgkqhkiG9w0BAQEFAASC
# AgCBHKDykFr26HY4agJ6V5E/Us31m+ignNICt4Y7La2fpOwLEP6iQfSFT0u1rSDq
# g6z5bBL54T5/HvMzWUhS+OiGBN1+Wbb59fs9x+AQ//gRZqG7HgM+eKfwjD+LDmOt
# fPAd4tHw5rq99S0DOiR3CcQcI1ABLX0dMAqDZAJ5muyhuFYPLfTp/FWrrLqOgme/
# H1GpJPuZMCOx2Y8u1mXa7t++J6hILHk+jJqR097BdqDHJQ0vQcwYYFhuSSKVrNW7
# bGhdxPrq7dEiA2HNayC/RgLSG/QemDMOxyzB/JRJ7L4cIQk+eebqbq6uoflMOqD9
# 4fvrLCEafstKRLkeVeI2X4/4TeJvnhQB9ihkv88VvNBLPAX/Ene041GTSBffKSQP
# iZ5V/Fqr30KyPb3kirP19Sg4U49RSZXYupHfaAu4XVvYsRKIuOTBxAjoalbmCesc
# FmqsIpAmMJbFAlK6MR+uh66wk0xgcjsgWHcfF420lRZFsznsKBWStQPJi7MRqphB
# dwqzMbSnZDJp+Ix2dK6wrZtiea737yBz2U5lSPCqyC2v1CjOfxA7lUsYnQ6VGwJd
# hz+2Oe7dOGIjgkUs/EZVNlewbS2ff+q8n5iDsGi9M4aKaM9UxCM0jYnJNF4Xp+T7
# 4EQ0ZtLS0R5JCOv1LrYVh+1+4Q/9Gg+1OKNRGUQhUfNWsqGCDjwwgg44BgorBgEE
# AYI3AwMBMYIOKDCCDiQGCSqGSIb3DQEHAqCCDhUwgg4RAgEDMQ0wCwYJYIZIAWUD
# BAIBMIIBDgYLKoZIhvcNAQkQAQSggf4EgfswgfgCAQEGC2CGSAGG+EUBBxcDMDEw
# DQYJYIZIAWUDBAIBBQAEIHDH+1rqT33o3mOmSef943Msxi1q/lLrczHG6cI7B62D
# AhRPvlN4l/bCVUYSK3sj6NnIUSIG4hgPMjAyMjEyMDExMjMzMDhaMAMCAR6ggYak
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
# SIb3DQEJEAEEMBwGCSqGSIb3DQEJBTEPFw0yMjEyMDExMjMzMDhaMC8GCSqGSIb3
# DQEJBDEiBCAyH4CTeUFY3XhqiQmCSXMMcKrghvw44/JbGvNjFQhsfDA3BgsqhkiG
# 9w0BCRACLzEoMCYwJDAiBCDEdM52AH0COU4NpeTefBTGgPniggE8/vZT7123H99h
# +DALBgkqhkiG9w0BAQEEggEAf8xdXJANQPR9VeWIXBfrXyBXgrcw1IQoQCHj35tB
# Egk5v/twYdvR3c4M4JGoi2bSlaRW6C39ldTdcLSAvh7Hk77RWjAAleaH7C0AfQD1
# pHWv3To76QQ4cnHNiabtI9J3h6BDgtA/mA64wo7oaPS8Ngh4+YODXLi/LN7Husa/
# kI8G/g+CA17LcKc+bKvmKhIqe1iMmMtmb1iCrKim3bgsey+GtEwTtII743Crxs3F
# Z61d/+kCsLgwn34QlElfnrJ2PrpdavL1cSopWj7lGF9NeMU8ohf1I7z9Kr6FSYSs
# pTtY1G/GhAMI0jDtBVHBKgd63Qz6uvB/gkLN4fCynTqBhA==
# SIG # End signature block
