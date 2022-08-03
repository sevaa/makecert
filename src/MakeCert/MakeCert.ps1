[CmdletBinding()]
param
(
    [string]$Server,
    [string]$TargetType,

    [string]$DN,
    [string]$Lifetime,
    [string]$FriendlyName,
    [string]$Description,
    [string]$SAN,

    [string]$Length,
    [string]$Exportable,
    [string]$Permissions,

    [string]$KUKE, [string]$KUDE, [string]$KUDS, [string]$KUKCS, [string]$KUKA, [string]$KUCS, [string]$KUNR, [string]$KUEO, [string]$KUDO, [string]$KUCritical,
    [string]$EKUSA, [string]$EKUCA, [string]$EKUCS, [string]$EKUExtra, [string]$EKUCritical,
    [string]$BCPresent, [string]$BCIsAuthority, [string]$BCPathLength, [string]$BCCritical,
    [string]$StoreName,
    [string]$CSRFileName
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
                elseif($a[0] -eq 'Email') { $SANLines += "e"+$a[1]}
                elseif($a[0] -eq 'IP') { $SANLines += "i"+$a[1]}
                elseif($a[0] -eq 'URI') { $SANLines += "u"+$a[1]}
                elseif($a[0] -eq 'Name') { $SANLines += "n"+$a[1]}
                else {Write-Warning "SAN line ignored, unknown type: $s"}
            }
            else
                {Write-Warning "SAN line ignored, expected type=value: $s"}
        }
    }
}

$ACEs = @()
if($Permissions -ne "")
{
    foreach($User in $Permissions -split "`r`n")
    {
        $s = $User.Trim()
        if($s -ne "")
        {
            if($s[0] -eq "*") # Read only
            {
                $Rights = "0x80120089"
                $s = $s.Substring(1)
            }
            else # Full control
            {
                $Rights = "0xd01f01ff"
            }
            $a = $s -split "\\"
            $ACEs += @{DomainUser=$a; Rights=$Rights}
        }
    }
}

if($BCPresent -eq "true")
{
    $HasPath = ($BCPathLength -ne "")
    if($HasPath)
    {
        [int]$PathLen = $BCPathLength
    }
    else
    {
        [int]$PathLen = 0
    }
    $IsAuth = $BCIsAuthority -eq "true"
    $Crit = $BCCritical -eq "true"
    $BCParams = $IsAuth,$HasPath,$PathLen,$Crit
}
else
{
    $BCParams = $False
}

$Cmds = {
    $Params = $args[0]
    $MakeCSR = $Params["MakeCSR"]
    $KeyLength = $Params["KeyLength"]
    $KeyName = $Params["KeyName"]
    $DN = $Params["DN"]
    $Exportable = $Params["Exportable"]
    $Usage = $Params["Usage"]
    $KUIsCritical = $Params["KUIsCritical"]
    $EKUIsCritical = $Params["EKUIsCritical"]
    $ExtUsage = $Params["ExtUsage"]
    $SANLines = $Params["SANLines"]
    $BCParams = $Params["BCParams"]
    $ExpirationDays = $Params["ExpirationDays"]
    $FriendlyName = $Params["FriendlyName"]
    $Description = $Params["Description"]
    $StoreName = $Params["StoreName"]
    $UseUserStore = $Params["UseUserStore"]
    $ACEs = $Params["ACEs"]
    $CSRFileName = $Params["CSRFileName"]

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

    # Extra permissions
    $WellKnownSIDs = @("AA","AC","AN","AO","AP","AU","BA","BG","BO","BU","CA","CD","CG","CN","CO","CY",
        "DA","DC","DD","DG","DU","EA","ED","EK","ER","ES","HA","HI","IS","IU","KA","LA","LG","LS","LU",
        "LW","ME","MP","MU","NO","NS","NU","OW","PA","PO","PS","PU","RA","RC","RD","RE","RM","RO","RS",
        "RU","SA","SI","SO","SS","SU","SY","UD","WD","WR")
    # Source: https://docs.microsoft.com/en-us/windows/win32/secauthz/sid-strings
    if($ACEs.Length -gt 0)
    {
        $DACL = ("(A;OICI;0xd01f01ff;;;SY)","(A;OICI;0xd01f01ff;;;BA)")
        foreach($ACE in $ACEs)
        {
            if($ACE.DomainUser -in $WellKnownSIDs)
            {
                $SID = $ACE.DomainUser
                Write-Host $SID
            }
            else
            {
                try
                {
                    $User = New-Object System.Security.Principal.NTAccount -ArgumentList $ACE.DomainUser
                    $SID = $User.Translate([System.Security.Principal.SecurityIdentifier]).Value
                }
                catch
                {
                    $User = $ACE.DomainUser -join "\"
                    Write-Error "Error retrieving the user record for ${User}" 
                    exit 1
                }
            }
            $Rights = $ACE.Rights
            $DACL += "(A;OICI;${Rights};;;${SID})"
        }
        $SDDL = "D:" + ($DACL -join "")
        $SecDesc = New-Object System.Security.AccessControl.RawSecuritydescriptor -ArgumentList $SDDL
        $SecDescData = [byte[]]::new($SecDesc.BinaryLength)
        $SecDesc.GetBinaryForm($SecDescData, 0)
        $KeyProp = New-Object System.Security.Cryptography.CngProperty -ArgumentList "Security Descr",$SecDescData,4
        $KeyParams.Parameters.Add($KeyProp)
    }
    
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

    # Subject Key Identifier
    $PubKey = $Request.PublicKey
    $Ext = New-Object System.Security.Cryptography.X509Certificates.X509SubjectKeyIdentifierExtension -ArgumentList $PubKey,$false
    $Exts.Add($Ext)
    
    # Basic Constraints
    if($BCParams)
    {
        $Ext = New-Object System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension -ArgumentList $BCParams
        $Exts.Add($Ext)
    }

    # Friendly Name
    if($FriendlyName -ne "")
    {
        $Value = [System.Text.Encoding]::Unicode.GetBytes($FriendlyName + "`0")
        $Ext = New-Object System.Security.Cryptography.X509Certificates.X509Extension -ArgumentList "1.3.6.1.4.1.311.10.11.11",$Value,$false
        $Exts.Add($Ext)
    }

    # Description
    if($Description -ne "")
    {
        $Value = [System.Text.Encoding]::Unicode.GetBytes($Description + "`0")
        $Ext = New-Object System.Security.Cryptography.X509Certificates.X509Extension -ArgumentList "1.3.6.1.4.1.311.10.11.13",$Value,$false
        $Exts.Add($Ext)
    }    

    # Create a self signed cert (needed for CSR too)
    $Cert = $Request.CreateSelfSigned([DateTimeOffset]::UtcNow, [DateTimeOffset]::UtcNow.AddDays($ExpirationDays))
    if($UseUserStore)
    {
        $Location = [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
    }
    else
    {
        $Location = [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
    }
    if($MakeCSR)
    {
        $StoreName = "REQUEST"
    }
    $Store = New-Object System.Security.Cryptography.X509Certificates.X509Store -ArgumentList $StoreName,$Location
    $RW = [System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite
    $Store.Open($RW)
    $Store.Add($Cert)
    $Store.Close()

    $Flags = [Base64FormattingOptions]::InsertLineBreaks
    #There is a class PemEncoding, but not in all flavors of .NET
    if($MakeCSR)
    {
        $CSRData = $Request.CreateSigningRequest()
        $CSRDataInPEM = [Convert]::ToBase64String($CSRData, $Flags)
        $CSRInPEM = "-----BEGIN NEW CERTIFICATE REQUEST-----`r`n" + $CSRDataInPEM + "`r`n-----END NEW CERTIFICATE REQUEST-----"
        Write-Host "Send the the following to a certification authority:`n`n$CSRInPEM"
        if($CSRFileName -ne "")
        {
            $CSRInPEM | Set-Content $CSRFileName -Encoding ASCII
            Write-Host "Saved the CSR to $CSRFileName on $env:COMPUTERNAME."
        }
    }
    else
    {
        # Display the public parts of the cert 
        $Thumbprint = $Cert.Thumbprint
        Write-Host "Thumbprint: $Thumbprint"
        $CertInPEM = "Save the following as a .CER file:`n`n-----BEGIN CERTIFICATE-----`n" + [Convert]::ToBase64String($Cert.GetRawCertData(), $Flags) +"`n-----END CERTIFICATE-----"
        Write-Host $CertInPEM
    }

    $Cert.Dispose()
}

$Params = @{MakeCSR = $TargetType -eq "CSR";
    KeyLength = $KeyLength;
    KeyName = $KeyName;
    DN = $DN;
    Exportable = $Exportable;
    Usage = $Usage;
    KUIsCritical = $KUIsCritical;
    EKUIsCritical = $EKUIsCritical;
    ExtUsage = $ExtUsage;
    SANLines = $SANLines;
    BCParams = $BCParams;
    ExpirationDays = $ExpirationDays;
    FriendlyName = $FriendlyName;
    Description = $Description;
    StoreName = $StoreName;
    UseUserStore = $false;
    ACEs = $ACEs;
    CSRFileName = $CSRFileName}

if($Server)
{   
    Invoke-Command -ComputerName $Server -ScriptBlock $Cmds -ArgumentList $Params
}
else
{
    Invoke-Command -ScriptBlock $Cmds -ArgumentList $Params
}
