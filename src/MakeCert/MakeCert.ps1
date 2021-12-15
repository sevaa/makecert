[CmdletBinding()]
param
(
    [string]$Server,

    [string]$DN,
    [string]$Lifetime,
    [string]$FriendlyName,
    [string]$SAN,

    [string]$Length,
    [string]$Exportable,

    [string]$KUKE, [string]$KUDE, [string]$KUDS, [string]$KUKCS, [string]$KUKA, [string]$KUCS, [string]$KUNR, [string]$KUEO, [string]$KUDO, [string]$KUCritical,
    [string]$EKUSA, [string]$EKUCA, [string]$EKUCS, [string]$EKUExtra, [string]$EKUCritical,
    [string]$StoreName
)

if($Server)
{
    $DNS = Resolve-DNSName $Server -ErrorAction SilentlyContinue
    if($DNS)
    {
        $CN = $DNS | ?{$_.Type -eq "CNAME"}
        if($CN)
        {
            $Server = $CN.NameHost
            Write-Host "Server name resolves to $Server"
        }
    }    
}

[int]$ExpirationDays = $Lifetime
[int]$n = $Length
[byte[]]$KeyLength = [BitConverter]::GetBytes($n) # little endian binary
$KeyName = [Guid]::NewGuid().ToString()
$KUIsCritical = $KUCritical -eq "true"
$Usage = [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::None
if($KUKE -eq "true") { $Usage += [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyEncipherment }
if($KUDS -eq "true") { $Usage += [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature }
if($KUDE -eq "true") { $Usage += [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DataEncipherment }
if($KUEO -eq "true") { $Usage += [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::EncipherOnly }
if($KUCS -eq "true") { $Usage += [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::CrlSign }
if($KUKCS -eq "true"){ $Usage += [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyCertSign }
if($KUKA -eq "true") { $Usage += [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyAgreement }
if($KUNR -eq "true") { $Usage += [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::NonRepudiation }
if($KUDO -eq "true") { $Usage += [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DecipherOnly }

[string[]]$ExtUsage = @()
$EKUIsCritical = $EKUCritical -eq "true"
if($EKUSA -eq "true") {$ExtUsage += "1.3.6.1.5.5.7.3.1"}
if($EKUCA -eq "true") {$ExtUsage += "1.3.6.1.5.5.7.3.2"}
if($EKUCS -eq "true") {$ExtUsage += "1.3.6.1.5.5.7.3.3"}
if($EKUExtra -ne "")
{
    foreach($OID in $EKUExtra -split "`r`n")
    {
        if($OID.Trim() -ne "")
        {
            $ExtUsage += $OID.Trim();
        }
    }
}

[string[]]$SANLines = @()
if($SAN -ne "")
{
    foreach($SANLine in $SAN -split "`r`n")
    {
        $s = $SANLine.Trim();
        if($s -ne "")
        {
            $a = $s -split "="
            if($a.Length -eq 2)
            {
                if($a[0] -eq 'DNS') { $SANLines += "d"+$a[1]}
                elseif($a[0] -eq 'IP') { $SANLines += "d"+$a[1]}
                elseif($a[0] -eq 'URI') { $SANLines += "u"+$a[1]}
                elseif($a[0] -eq 'Email') { $SANLines += "e"+$a[1]}
                elseif($a[0] -eq 'Name') { $SANLines += "n"+$a[1]}
                else {Write-Warning "SAN line ignored, unknown type: $s"}
            }
            else
                {Write-Warning "SAN line ignored, expected type=value: $s"}
        }
    }
}

$Cmds = {
    $Params = $args[0]
    $KeyLength = $Params["KeyLength"]
    $KeyName = $Params["KeyName"]
    $DN = $Params["DN"]
    $Exportable = $Params["Exportable"]
    $Usage = $Params["Usage"]
    $KUIsCritical = $Params["KUIsCritical"]
    $EKUIsCritical = $Params["EKUIsCritical"]
    $ExtUsage = $Params["ExtUsage"]
    $SANLines = $Params["SANLines"]
    $ExpirationDays = $Params["ExpirationDays"]
    $FriendlyName = $Params["FriendlyName"]
    $StoreName = $Params["StoreName"]
    $UseUserStore = $Params["UseUserStore"]

    # Create a RSA key pair
    $KeyParams = New-Object System.Security.Cryptography.CngKeyCreationParameters
    if($Exportable -eq "true")
    {
        $KeyParams.ExportPolicy = [System.Security.Cryptography.CngExportPolicies]::AllowExport
    }

    if(-not $UseUserStore)
    {    
        $KeyParams.KeyCreationOptions += [System.Security.Cryptography.CngKeyCreationOptions]::MachineKey
    }
    
    $KeyProp = New-Object System.Security.Cryptography.CngProperty -ArgumentList "Length",$KeyLength,0
    $KeyParams.Parameters.Add($KeyProp)
    
    $AlgName = [System.Security.Cryptography.CngAlgorithm]::Rsa
    $KeyPair = [System.Security.Cryptography.CngKey]::Create($AlgName, $KeyName, $KeyParams)
    $RSAKey = New-Object System.Security.Cryptography.RSACng -ArgumentList $KeyPair
    
    # Create a CSR with that key pair
    $DistName = New-Object System.Security.Cryptography.X509Certificates.X500DistinguishedName -ArgumentList $DN
    $HashAlg = [System.Security.Cryptography.HashAlgorithmName]::SHA256
    $Padding = [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
    $Request = New-Object System.Security.Cryptography.X509Certificates.CertificateRequest -ArgumentList $DistName,$RSAKey,$HashAlg,$Padding

    # Populate the extensions
    $Exts = $Request.CertificateExtensions

    # Key Usage
    if($Usage -ne [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::None)
    {
        $Ext = New-Object System.Security.Cryptography.X509Certificates.X509KeyUsageExtension -ArgumentList $Usage,$KUIsCritical
        $Exts.Add($Ext)
    }

    # Enhanced Key Usage - Server Auth, Client Auth
    if($ExtUsage.Length -ne 0)
    {
        $Oids = New-Object System.Security.Cryptography.OidCollection
        foreach($s in $ExtUsage)
        {
            $Oid = New-Object System.Security.Cryptography.Oid -ArgumentList $s
            $Oids.Add($Oid) | Out-Null
        }
        $Ext = New-Object System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension -ArgumentList $Oids,$EKUIsCritical
        $Exts.Add($Ext)
    }

    # Subject Alternative Name
    if($SANLines.Length -ne 0)
    {
        $SANBuilder = New-Object System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder
        foreach($kv in $SANLines)
        {
            $Type = $kv.Substring(0, 1);
            $Value = $kv.Substring(1);
            if($Type -eq "d"){$SANBuilder.AddDnsName($Value)}
            if($Type -eq "e"){$SANBuilder.AddEmailAddress($Value)}
            if($Type -eq "i"){$SANBuilder.AddIpAddress($Value)}
            if($Type -eq "u"){$SANBuilder.AddUri($Value)}
            if($Type -eq "n"){$SANBuilder.AddUserPrincipalName($Value)}
        }
        $Exts.Add($SANBuilder.Build())
    }

    # Create a self signed cert
    $Cert = $Request.CreateSelfSigned([DateTimeOffset]::UtcNow, [DateTimeOffset]::UtcNow.AddDays($ExpirationDays))
    if($FriendlyName -ne "")
    {
        $Cert.FriendlyName = $FriendlyName
    }
    if($UseUserStore)
    {
        $Location = [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
    }
    else
    {
        $Location = [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
    }
    $Store = New-Object System.Security.Cryptography.X509Certificates.X509Store -ArgumentList $StoreName,$Location
    $RW = [System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite
    $Store.Open($RW)
    $Store.Add($Cert)
    $Store.Close()

    # Display the public parts of the cert 
    $Thumbprint = $Cert.Thumbprint
    Write-Host "Thumbprint: $Thumbprint"
    #There is a class PemEncoding, but not in all flavors of .NET
    $Flags = [Base64FormattingOptions]::InsertLineBreaks
    $CertInPEM = "Save the following as a .CER file:`n`n-----BEGIN CERTIFICATE-----`n" + [Convert]::ToBase64String($Cert.GetRawCertData(), $Flags) +"`n-----END CERTIFICATE-----"
    Write-Host $CertInPEM

    $Cert.Dispose()
}

$Params = @{KeyLength = $KeyLength;
    KeyName = $KeyName;
    DN = $DN;
    Exportable = $Exportable;
    Usage = $Usage;
    KUIsCritical = $KUIsCritical;
    EKUIsCritical = $EKUIsCritical;
    ExtUsage = $ExtUsage;
    SANLines = $SANLines;
    ExpirationDays = $ExpirationDays;
    FriendlyName = $FriendlyName;
    StoreName = $StoreName;
    UseUserStore = $false}

if($Server)
{   
     Invoke-Command -ComputerName $Server -ScriptBlock $Cmds -ArgumentList $Params
}
else
{
        Invoke-Command -ScriptBlock $Cmds -ArgumentList $Params
}
