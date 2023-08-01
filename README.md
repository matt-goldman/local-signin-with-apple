# Sign-In with Apple in your local developer environment

Sign-In with Apple is an awesome feature that can provide trust to your users as well as convenience. Unfortuantely, Apple doesn't allow using `localhost` as a callback URL.

There are workarounds for this, as [you can read about in my blog post here](https://goforgoldman.com/posts/2023-local-apple-signin/). This script automates the process of setting up these workarounds.
    
In a nutshell:
* Generates a self-signed certificate (`.pfx`, `.crt`, `.pem`, and `.key`) with an address you can use for testing locally (e.g. `local-apple-signin.mydomain.com`)
* Imports and trusts the certificate
* Adds a hosts file entry for the address

It places the certificate in a folder called `.applesignin` in your user profile, so all you need to do after running the script is [configure your application to use it](#configure-your-application-to-use-the-local-url-and-ssl-certificate).

# Prerequisites
The script has the following prerequisites:
* [PowerShell Core](https://github.com/PowerShell/PowerShell)
* [OpenSSL](https://www.openssl.org)


# Usage
It turns all the steps above into a one-liner:

```powershell
./Generate-LocalCert.ps1
```

This will use a default URL and will generate a certificate password for you, but these can be supplied as arguments too:

```powershell
./Generate-LocalCert.ps1 -url local.apple-signin.mydomain.com -certPassword myC00lp@55w%rd
```

With this simple script, you can solve all the pain of developing locally for Sign-In with Apple into a trivial one-liner.

# Other requirements
The script needs to be run with root or administrator privileges (this is required for writing to the hosts file and importing the certificate into the trusted root CA store).
    
Note that some anti-malware programs will block both writing to the hosts file and importing certificates, so you may need to disable this while you run the script.
