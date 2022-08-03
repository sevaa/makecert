# Description

This extension provides a build/release task for Azure DevOps pipelines
that creates a RSA private key in the machine store on a
specified target machine, and creates either a self-signed digital certificate
with that key, also in the local machine certificate store, or a cerficate signing
request for an authority to sign.

It relies on Windows PKI, so only Windows agents and targets are supported.

The target machine needs to be at least Windows Vista or Windows Server 2008 R2.

The default parameter values (`Key Usage` and `Enhanced Key Usage`) correspond to
a TLS server certificate, modulo the fact that if self signed, it won't be trusted by any browsers.
To create a TLS certificate, one would also have to provide a subject,
with at least a `CN={hostname}` value with the desired site's hostname, and a line
under `Subject alternative name`, in the format `DNS={hostname}`. As of late 2021, Web browsers
expect the server certificate to contain a Subject Alternative Name, and display
a scary security warning if it's not present.

The task was initially conceived, however, with arbitrary PKI tasks in mind. One does need a cert
from time to time besides TLS.

For Extended Key Usage, there a lot of possible options out there. This task lists the first three ones explicitly,
and lets the user specify more as raw OIDs.

The hash algorithm is hard coded to SHA256, the signing algorithm is hard-coded to RSA.
Arbitrary extensions are not currently supported.

For saving CSRs in files, only PEM encoded PKCS# 10 is supported.
