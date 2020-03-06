# Google Compute Engine Service Account Impersonation Proxy

1. Build the binary.
2. Run the binary: `gce-impersonation-proxy -I ACCOUNT-TO-IMPERSONATE@PROJECT-ID.iam.gserviceaccount.com -D BIND-ADDRESS:PORT`
3. Change `/etc/hosts` to point `metadata.google.internal` to `127.0.0.1`.
4. Run any command like `gsutil` and you should be impersonating service account you specified.

