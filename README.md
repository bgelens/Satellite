# PowerShell module to interface with Satellite 5.7 XML RPC API

```powershell
Get-SatelliteSessionKey -Uri 'https://satellite.mydomain.com/rpc/api' -Credential $cred -IgnoreSSL
'myserver.fqdn.tld' | Get-SatelliteSystem | sort -Property last_checkin | select -First 1 | Remove-SatelliteSystem -Force
```