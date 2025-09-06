# FastAPI + NGINX mTLS (PKI) demo

End-to-end demo to test client-certificate auth locally. NGINX terminates TLS and enforces client certs, then forwards identity to FastAPI.

## Prereqs

- Docker Desktop (or Docker Engine) on your host
- Windows for client testing (to import PFX)

## 1) Generate test certificates

From this folder:

```bash
./scripts/gencerts.sh "Your Name"
```

Outputs in `certs/`:

- `ca.crt`, `ca.key` (local root CA)
- `server.crt`, `server.key` (for localhost)
- `client.crt`, `client.key`, `client.pfx` (password: `changeit`)

## 2) Run the stack

From this folder:

```bash
docker compose up --build -d
```

Notes:

- Listens on host port 443 by default. If port 443 is busy, change `ports` in `docker-compose.yml` to "8443:443" and use <https://localhost:8443>

## 3) Trust and import certs on Windows

- Import server CA so the browser trusts `localhost`:
  - Double-click `certs/ca.crt` → install to Local Computer → Trusted Root Certification Authorities.
- Import client cert so the browser can present it:
  - Double-click `certs/client.pfx` (password `changeit`) → Current User → Personal.

Optional PowerShell (run as admin where files are accessible):

```powershell
certutil -addstore -f Root .\certs\ca.crt
certutil -user -p changeit -importpfx MY .\certs\client.pfx
```

## 4) Test

- Open browser to:
  - Public health (no client cert needed): <https://localhost/health>
  - Protected routes (require client cert): <https://localhost/> and <https://localhost/me>
- If prompted, select your client certificate (the one you imported).

CLI test (from Linux/macOS/Git Bash):

```bash
# public
curl -vk https://localhost/health
# protected
curl -vk --cert certs/client.crt --key certs/client.key --cacert certs/ca.crt https://localhost/me
```

## How it works

- NGINX is configured with:
  - `ssl_client_certificate` pointing at `certs/ca.crt` (trust anchor)
  - `ssl_verify_client optional` + a `403` if not `SUCCESS`
  - Forwards identity via headers `X-SSL-*`
- FastAPI checks `x-ssl-client-verify` and reads subject/issuer from headers.

## Files

- `app/` FastAPI app and Dockerfile
- `nginx/nginx.conf` TLS + mTLS + reverse proxy
- `scripts/gencerts.sh` One-shot test CA/client/server generator (localhost SAN)
- `docker-compose.yml` Two services: app and nginx (443 exposed)

## Troubleshooting

- Port 443 in use: change compose ports to `8443:443`.
- Browser says site is untrusted: import `ca.crt` into Trusted Root store.
- Browser not offering a cert: import `client.pfx` (password `changeit`).
- 403 from `/` or `/me`: ensure your client cert chains to `ca.crt` and is selected.

## Extend to corporate PKI (employees authenticate with company PFX)

Goal: require employee client certificates issued by your corporate CA and map the identity to the app user. On Windows, employee PFX certs usually live in the Current User → Personal store; Chrome/Edge will offer them automatically if the server requests a client cert from an acceptable issuer.

### 1) NGINX: trust corporate issuing CAs and forward identity

Place your corporate issuing CA chain (typically the issuing intermediate(s), not just the root) in `certs/corp-issuers.pem` as a PEM bundle. Then update `nginx.conf` (mounted read-only in the container) to request those issuers and forward the full client cert:

```nginx
# trust this CA bundle for client auth (add next to, or replace, the local dev CA)
ssl_client_certificate    /etc/nginx/certs/corp-issuers.pem;
ssl_verify_depth          3;  # adjust to your chain depth

# still keep path-based enforcement (example: only /api/* requires a client cert)
# location ^~ /api/ { if ($ssl_client_verify != SUCCESS) { return 403; } ... }

# optionally forward the full certificate so the app can parse SAN/UPN/email
proxy_set_header X-SSL-Client-Cert $ssl_client_escaped_cert;
```

Notes:

- The set of acceptable issuers you configure in `ssl_client_certificate` controls which certs the browser will offer. Include all relevant corporate issuing CAs (bundle them in one file).
- Keep your server certificate (`server.crt/key`) valid for the hostname you use (SAN required). In corporate environments, use an internal DNS name and a server cert from your corporate CA (or a public CA) that clients trust.

### 2) Windows/Browser behavior

- Chrome/Edge on Windows use the Current User → Personal store. Import employee PFXs there. The browser prompts only if it finds a cert that chains to an issuer advertised by the server.
- If no prompt appears on `/api/*`, verify your `corp-issuers.pem` contains the right issuing CA(s) and that the employee cert EKU includes Client Authentication (1.3.6.1.5.5.7.3.2).
- Firefox uses its own store; import both the client PFX and the issuing CA there if testing with Firefox.

### 3) Identity mapping in the app

Quick options for deriving user identity after NGINX verifies the certificate:

- Simple: use the subject DN common name (already forwarded as `X-SSL-Client-S-DN`, parsed to `common_name` in the demo).
- Better: use an immutable identifier from SAN (email or UPN). To do this, parse the forwarded full certificate.

Optional app changes (parse SAN/UPN/email):

1) Forward the full cert from NGINX (already shown above).
2) Add `cryptography` to the app image and parse the `X-SSL-Client-Cert` header.

Dockerfile (add dependency):

```dockerfile
RUN pip install --no-cache-dir cryptography
```

Python (example sketch):

```python
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import base64

def parse_san_identifiers(pem_escaped: str):
  if not pem_escaped:
    return {}
  pem = pem_escaped.replace('\t', '\n')  # nginx escaped format
  cert = x509.load_pem_x509_certificate(pem.encode(), default_backend())
  ids = {}
  try:
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    ids['emails'] = san.get_values_for_type(x509.RFC822Name)
    # UPN is often in OtherName with OID 1.3.6.1.4.1.311.20.2.3
    upns = []
    for gn in san:
      if isinstance(gn, x509.OtherName) and gn.type_id.dotted_string == '1.3.6.1.4.1.311.20.2.3':
        try:
          upns.append(gn.value.decode('utf-16-le'))
        except Exception:
          upns.append(repr(gn.value))
    ids['upns'] = upns
  except x509.ExtensionNotFound:
    pass
  return ids
```

Then decide your app’s principal (e.g., prefer UPN, else email, else CN) and map it to an internal user.

### 4) Revocation (CRL/OCSP)

- NGINX (open source) supports CRLs for client cert verification. Publish your corporate CRL (or a bundle) and reference it:

```nginx
ssl_crl /etc/nginx/certs/corporate.crl.pem;
```

- Automate CRL refresh (mount updated file and `nginx -s reload`).
- OCSP checking for client certs is not supported in NGINX OSS; consider NGINX Plus or an upstream gateway if OCSP is required.

### 5) Multiple issuers / migration

- You can concatenate multiple issuing CA certs in `corp-issuers.pem` to support several PKIs during a transition.
- Keep `ssl_verify_depth` high enough to cover your chain (e.g., 3).

With these changes, your browser will present employee-issued client certs, NGINX will verify them against your corporate CA(s), and the app can reliably derive a user identity (UPN/email/CN) to authorize employees.
