<#
.Synopsis
   Generates a self-signed certificate for local development with Sign-in with Apple
.DESCRIPTION
   Generates a self-signed certificate with a local address registered with Sign-in with Apple. Copies the certificate to a path in the users home directory, which is used by the code in development. Installs the certificate so it is trusted.
.PARAMETER url
    (optional) Specify the URL to be used as the CN on the certificate (rather than the default)
.PARAMETER certPassword
    (optional) Specify the password to be used for the certificate (rather than genrating a random one)
.EXAMPLE
   PS> .\Generate-LocalCert.ps1

   Generates the certificate with the default URL of local.applesign-in, installs the certificate, and copies it to the users home directory. Optionally adds an entry in the hosts file for local.applesign-in for localhost.
.EXAMPLE
    PS> .\Generate-LocalCert.ps1 -url "local.myapp.com"
    
    Generates the certificate with the specified URL, installs the certificate, and copies it to the users home directory. Optionally adds an entry in the hosts file for local.myapp.com for localhost.
.EXAMPLE
    PS> .\Generate-LocalCert.ps1 -certPassword "MyPassword"

    Generates the certificate with the default URL of local.applesign-in, installs the certificate, and copies it to the users home directory. Optionally adds an entry in the hosts file for local.applesign-in for localhost. Uses the specified password for the certificate.
#>

param (
    [Parameter(Mandatory=$false)]
    [string]$url = "local.applesign-in",

    [Parameter(Mandatory=$false)]
    [string]$certPassword = ""
)

if ($IsWindows) {
    if (-NOT ([System.Security.Principal.WindowsPrincipal] [System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Warning 'This script needs to be run with administrator privileges. Please re-run this script as an administrator.'
        exit
    }
} else {
    if ($env:USER -ne "root") {
        Write-Warning 'This script needs to be run with root privileges. Please re-run this script as root.'
        exit
    }
}

try {
    $version = & openssl version
    Write-Output "OpenSSL is installed: $version"
} catch {
    Write-Warning "OpenSSL is not installed. Please install it and run the script again."
    Write-Host "TIP: Try adding C:\Program Files\Git\usr\bin to your PATH if you have Git installed."
    exit
}

$userProfile = [Environment]::GetFolderPath("UserProfile")
$certFolderPath = Join-Path -Path $userProfile -ChildPath ".applesignin"

if ($certPassword -eq "") {
    $certPassword = -Join("ABCDEFGHIJKLMNOPQRSTUVWXYXabcdefghijklmnopqrstuvwxyz&@#$%1234".tochararray() | Get-Random -Count 10 | ForEach-Object {[char]$_})
}

if (-NOT (Test-Path -Path $certFolderPath)) {
    New-Item -Path $certFolderPath -ItemType Directory
}

$pemFilePath = Join-Path -Path $certFolderPath -ChildPath "local.applesign-in.pem"
$keyFilePath = Join-Path -Path $certFolderPath -ChildPath "local.applesign-in.key"
$pfxFilePath = Join-Path -Path $certFolderPath -ChildPath "local.applesign-in.pfx"
$crtFilePath = Join-Path -Path $certFolderPath -ChildPath "local.applesign-in.crt"

Write-Host "🔒 Generating certificate for $url"

openssl req -newkey rsa:4096 -nodes -keyout $keyFilePath -x509 -days 365 -out $pemFilePath -subj "/CN=$url" -addext "subjectAltName = DNS:$url"
openssl pkcs12 -export -out $pfxFilePath -inkey $keyFilePath -in $pemFilePath -password pass:$certPassword
openssl pkcs12 -in $pfxFilePath -out $crtFilePath -clcerts -nokeys -password pass:$certPassword

Write-Host "✅ Done"

Write-Host "🔒 Importing certificate"

if ($IsWindows) {
    Import-PfxCertificate -FilePath $pfxFilePath -CertStoreLocation Cert:\CurrentUser\My -Password (ConvertTo-SecureString -String $certPassword -Force -AsPlainText)
    Import-PfxCertificate -FilePath $pfxFilePath -CertStoreLocation Cert:\LocalMachine\Root -Password (ConvertTo-SecureString -String $certPassword -Force -AsPlainText)
} elseif ($IsMacOS) {
    security import $pfxFilePath -k ~/Library/Keychains/login.keychain-db -P $certPassword -T /usr/bin/codesign -A
} elseif ($IsLinux) {
    Write-Host "Importing the certificate will need to be done manually on Linux. Or you can just trust it in your browser."
}

Write-Host "✅ Done"

$hostsLine = "127.0.0.1 $url"
$confirmation = Read-Host -Prompt "Do you want add $url to your hosts file? (y/N)"

if ($confirmation -eq 'Y' -or $confirmation -eq 'y') {
    Write-Host "📝 Adding entry to hosts file"

    try {
        if ($IsWindows) {
            Add-Content -Path $env:windir\System32\drivers\etc\hosts -Value $hostsLine
        } elseif ($IsMacOS -or $IsLinux) {
            echo $hostsLine | sudo tee -a /etc/hosts
        }
    } catch {
        Write-Host "Failed to add entry to hosts file (this can be blocked by your anti-virus). You will need to manually add this hosts entry to your hosts file:"
        Write-Host $hostsLine
    }

    Write-Host "✅ Done"
} else {
    Write-Host "Skipping adding $url to hosts file"
    Write-Host "You will need to manually add this hosts entry to your hosts file:"
    Write-Host $hostsLine
}


Write-Host "Local developer certificates for sign-in with Apple have been generated and installed."
Write-Host "The certificate password is: $certPassword"
Write-Host ([Environment]::NewLine)
Write-Host "Set your redirect URI in Apple Developer to (e.g.) https://"+$url+"/auth/signin-apple/callback"
Write-Host ([Environment]::NewLine)
Write-Host "Configure your application to use the certificate for local development. E.g., for ASP.NET Core, use:"
Write-Host @"
if (Environment.IsDevelopment())
{
    // Load certificate password from secrets
    var certificatePassword = Configuration["appleCertPassword"];

    // Define the path to the certificate
    var homeDirectory = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
    var certificatePath = Path.Combine(homeDirectory, ".applesignin", "local.applesign-in.pfx");

    // Load the certificate
    var certificate = new X509Certificate2(certificatePath, certificatePassword);

    // Configure Kestrel to use the certificate
    services.Configure<KestrelServerOptions>(options =>
    {
        options.ConfigureHttpsDefaults(httpsOptions =>
        {
            httpsOptions.ServerCertificate = certificate;
        });
    });
}
"@

Write-Host ([Environment]::NewLine)
Write-Host "If you're using this approach, don't forget to add the cert password to user secrets."
Write-Host "🍎 Have fun! 👋"