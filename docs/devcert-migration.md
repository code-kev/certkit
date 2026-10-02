# Coming from devcert?

certkit and devcert can coexist. They use distinct CA identities and data directories; certkit's installer and uninstaller identify its CA by certificate fingerprint and leave unrelated certificates in place. Prior art: devcert established a JavaScript `certificateFor` API backed by a local CA and OS trust integration. See the [devcert README](https://github.com/davewasmer/devcert).

## Move one application at a time

1. Keep the existing devcert setup while you update and verify the application.
2. Install certkit and its Linux `certutil` prerequisite if needed.
3. Run `certkit install`, then replace the devcert call with certkit's API or configure the [Vite plugin](../README.md#vite).
4. Test the actual browser and runtime. `certkit status` reports detected stores, but an `unknown` or `not-detected` result is not proof of trust.
5. Remove the `devcert` dependency only after no project code calls it.

## Remove old devcert trust separately

`certkit uninstall` removes certkit's CA; it does not remove devcert's CA. devcert's README explains that its OS and browser trust entries may need manual removal. Before removing anything, identify the old CA by its certificate fingerprint and delete only that exact entry from each store/profile where devcert installed it. Do not remove a certificate based on a matching display name alone.

On Linux, browser NSS databases need `certutil` to inspect and remove their own entries. System trust removal uses the distribution's CA directory and rebuild command. On macOS and Windows, use the certificate management UI for the affected user and remove only the verified devcert CA. Close affected browsers and restart them after changing trust.

If both tools remain in use, keep their CA material separate. `certkit caroot` prints certkit's current data directory; it contains `ca-cert.pem`, `ca-key.pem`, and state/cache files. Treat `ca-key.pem` as a private signing key: never commit, copy to another machine, or attach it to an issue.
## Audit: is the old CA really gone?

Names are a hint, not proof: certkit's own CA uses the NSS nickname `certkit development CA <12 hex>` and mkcert's uses `mkcert development CA <serial>`, but compare SHA-256 fingerprints before deleting anything. `certkit status` reports certkit's CA per detected store but does not print its fingerprint; `unknown` or `not-detected` means effective trust could not be established, not that an entry is absent.

Print certkit's own fingerprint:

```sh
openssl x509 -in "$(certkit caroot)/ca-cert.pem" -noout -subject -fingerprint -sha256
```

List the development CAs in each store:

**Linux system store**

```sh
ls /usr/local/share/ca-certificates/
awk -v cmd='openssl x509 -noout -subject -fingerprint -sha256' \
  '/BEGIN CERTIFICATE/{close(cmd)};{print|cmd}' /etc/ssl/certs/ca-certificates.crt \
  | grep -B1 -i 'mkcert\|devcert\|certkit'
```

**NSS profiles** (the same `sql:` databases certkit uses; the loop skips profiles that do not exist)

```sh
for db in "$HOME/.pki/nssdb" "$HOME"/.mozilla/firefox/* \
          "$HOME"/.var/app/org.mozilla.firefox/.mozilla/firefox/* \
          "$HOME"/snap/firefox/common/.mozilla/firefox/*; do
  [ -f "$db/cert9.db" ] || continue
  echo "== $db"
  certutil -L -d "sql:$db" | grep -i 'development CA\|mkcert\|devcert\|certkit'
done
```

Fingerprint a single entry once you have its nickname:

```sh
certutil -L -d "sql:<db>" -n "<nickname>" -a | openssl x509 -noout -subject -fingerprint -sha256
```

**macOS login keychain**

```sh
security find-certificate -a -Z -c "mkcert"  ~/Library/Keychains/login.keychain-db
security find-certificate -a -Z -c "devcert" ~/Library/Keychains/login.keychain-db
```

certkit never writes the System keychain, so an entry there came from another tool and needs `sudo` to remove.

**Windows (PowerShell)**

```powershell
Get-ChildItem Cert:\CurrentUser\Root | Format-List Subject, Thumbprint
Get-ChildItem Cert:\LocalMachine\Root | Format-List Subject, Thumbprint
```

Delete only entries whose fingerprint matches the old CA, then restart the affected browsers.

## Java truststores

certkit neither reads nor writes Java truststores: trust is per JDK installation rather than per user, `cacerts` is normally package-manager-owned, and writing it needs the store password. If mkcert ran with `JAVA_HOME` set, its root is in Java's `cacerts` and `certkit uninstall` will not remove it:

```sh
keytool -list -cacerts -storepass changeit | grep -i -A1 'mkcert'
keytool -delete -alias <alias> -cacerts -storepass changeit
```

A JVM will not trust certkit's CA either. Import it into a truststore you own rather than editing the JDK's bundled `cacerts`, and point the JVM at that store:

```sh
keytool -importcert -noprompt -keystore dev-truststore.p12 -storetype PKCS12 \
  -storepass changeit -alias certkit-dev -file "$(certkit caroot)/ca-cert.pem"
```

```sh
java -Djavax.net.ssl.trustStore=dev-truststore.p12 \
     -Djavax.net.ssl.trustStorePassword=changeit -jar app.jar
```
