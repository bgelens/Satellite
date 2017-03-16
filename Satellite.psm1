#requires -version 4
$uri = $Null
$OriginalCertificatePolicy = [System.Net.ServicePointManager]::CertificatePolicy
$SessionKey = $Null
$IgnoreSSL = $false

function IgnoreSSL {
    $Provider = New-Object -TypeName Microsoft.CSharp.CSharpCodeProvider
    $null = $Provider.CreateCompiler()
    $Params = New-Object -TypeName System.CodeDom.Compiler.CompilerParameters
    $Params.GenerateExecutable = $False
    $Params.GenerateInMemory = $True
    $Params.IncludeDebugInformation = $False
    $Params.ReferencedAssemblies.Add('System.DLL') > $null
    $TASource=@'
        namespace Local.ToolkitExtensions.Net.CertificatePolicy
        {
            public class TrustAll : System.Net.ICertificatePolicy
            {
                public TrustAll() {}
                public bool CheckValidationResult(System.Net.ServicePoint sp,System.Security.Cryptography.X509Certificates.X509Certificate cert, System.Net.WebRequest req, int problem)
                {
                    return true;
                }
            }
        }
'@ 
    $TAResults=$Provider.CompileAssemblyFromSource($Params,$TASource)
    $TAAssembly=$TAResults.CompiledAssembly
    ## We create an instance of TrustAll and attach it to the ServicePointManager
    $TrustAll = $TAAssembly.CreateInstance('Local.ToolkitExtensions.Net.CertificatePolicy.TrustAll')
    [System.Net.ServicePointManager]::CertificatePolicy = $TrustAll
}

function PreFlight {
    [CmdletBinding()]
    param (

    )

    Write-Verbose -Message 'Validating SessionKey Acquired'
    if (($null -eq $script:SessionKey) -or ($null -eq $script:uri)) {
        throw 'SessionKey was not acquired, run Get-SatelliteSessionKey first!'
    }
}

function Get-SatelliteSessionKey {
    [cmdletbinding()]
    [outputtype([pscustomobject])]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [System.String] $Uri,

        [Parameter(Mandatory)]
        [pscredential]
        [System.Management.Automation.CredentialAttribute()] $Credential,

        [Switch] $IgnoreSSL
    )
    process {
        $body = [xml](@'
        <methodCall>
            <methodName>auth.login</methodName>
                <params>
                    <param>
                        <value><username>{0}</username></value>
                    </param>
                    <param>
                    <value><password>{1}</password></value>
                    </param>
                </params>
        </methodCall>
'@ -f $Credential.UserName,$Credential.GetNetworkCredential().Password)
        
        Write-Verbose -Message "Constructed body: $($body | fc | Out-String)"
        try {
            if ($IgnoreSSL) {
                Write-Warning -Message 'IgnoreSSL switch defined. Certificate errors will be ignored!'
                #Change Certificate Policy to ignore
                IgnoreSSL
            }

            $Response = Invoke-WebRequest -UseBasicParsing -Uri $uri -Body $body -ContentType application/xml -Method Post
            $Key = (([xml]$Response.Content).methodResponse.params.param.value.string)
            if ($Null -ne $Key) {
                Set-Variable -Name SessionKey -Value $Key -Scope 1
                Set-Variable -Name Uri -Value $Uri -Scope 1
                Set-Variable -Name IgnoreSSL -Value $IgnoreSSL -Scope 1
            } else {
                Set-Variable -Name SessionKey -Value $Null -Scope 1
                Set-Variable -Name IgnoreSSL -Value $false -Scope 1
                throw 'No SessionKey was returned'
            }
        } catch {
            Write-Error -ErrorRecord $_
        } finally {
        #Change Certificate Policy to the original
            if ($IgnoreSSL) {
                [System.Net.ServicePointManager]::CertificatePolicy = $script:OriginalCertificatePolicy
            }
        }
    }
}

function Get-SatelliteSystem {
    [cmdletbinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [System.String] $Name,

        [switch] $RawXML
    )
    process {
        PreFlight

        $body = [xml](@'
        <methodCall>
            <methodName>system.getId</methodName>
                <params>
                    <param>
                        <value><sessionKey>{0}</sessionKey></value>
                    </param>
                    <param>
                        <value><systemName>{1}</systemName></value>
                    </param>
                </params>
        </methodCall>
'@ -f $script:SessionKey,$Name)

        Write-Verbose -Message "Constructed body: $($body | fc | Out-String)"
        try {
            if ($script:IgnoreSSL) {
                Write-Warning -Message 'IgnoreSSL switch defined by Get-SatelliteSessionKey. Certificate errors will be ignored!'
                #Change Certificate Policy to ignore
                IgnoreSSL
            }

            $device = Invoke-WebRequest -UseBasicParsing -Uri $script:uri -Body $body -ContentType application/xml -Method Post
            if ($RawXML) {
                ([xml]$device.Content)
            } else {
                $devices = ([xml]$device.Content).methodResponse.params.param.value.array.data.value
                foreach ($d in $devices) {
                    $deviceprops = $d.struct.member
                    $obj = [pscustomobject]@{
                        Id = ($deviceprops | ?{$_.name -eq 'id'}).value.InnerText
                        Name = ($deviceprops | ?{$_.name -eq 'name'}).value.InnerText
                        last_checkin = [datetime](($deviceprops | ?{$_.name -eq 'last_checkin'}).value.InnerText).insert(4,'/').insert(7,'/')
                    }
                    $obj.PSObject.TypeNames.Insert(0,'Satellite.Device')
                    Write-Output -InputObject $obj
                }
            }
        } catch {
            Write-Error -ErrorRecord $_
        } finally {
            #Change Certificate Policy to the original
            if ($script:IgnoreSSL) {
                [System.Net.ServicePointManager]::CertificatePolicy = $script:OriginalCertificatePolicy
            }
        }
    }
}

function Remove-SatelliteSystem {
    [cmdletbinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [System.Management.Automation.PSTypeName('Satellite.Device')] $Device,

        [switch] $Force
    )
    process {
        PreFlight

        $body = [xml](@'
        <methodCall>
            <methodName>system.deleteSystem</methodName>
                <params>
                    <param>
                        <value><sessionKey>{0}</sessionKey></value>
                    </param>
                    <param>
                        <value><serverId><i4>{1}</i4></serverId></value>
                    </param>
                </params>
        </methodCall>
'@ -f $script:SessionKey,$Device.Id)
        Write-Verbose -Message "Constructed body: $($body | fc | Out-String)"
        try {
            if ($script:IgnoreSSL) {
                Write-Warning -Message 'IgnoreSSL switch defined by Get-SatelliteSessionKey. Certificate errors will be ignored!'
                #Change Certificate Policy to ignore
                IgnoreSSL
            }
            if ($Force -or $PSCmdlet.ShouldProcess($Device.Name)) {
                $Delete = [xml](Invoke-WebRequest -UseBasicParsing -Uri $script:uri -Body $body -ContentType application/xml -Method Post).Content
                if ($faultcode = ($Delete.methodResponse.fault.value.struct.member | ?{$_.name -eq 'faultCode'}).value.InnerText) {
                    $faultmsg = ($Delete.methodResponse.fault.value.struct.member | ?{$_.name -eq 'faultString'}).value.InnerText
                    Write-Error -Message "Exception code: $faultcode, Exception message: $faultmsg" -ErrorAction Stop
                } else {
		            if ($Delete.methodResponse.params.param.value.i4 -eq 1) {
                        #success
		            } else {
                        throw 'System was not deleted because of unknown exception'
		            }
                }
            }
        } catch {
            Write-Error -ErrorRecord $_
        } finally {
            #Change Certificate Policy to the original
            if ($script:IgnoreSSL) {
                [System.Net.ServicePointManager]::CertificatePolicy = $script:OriginalCertificatePolicy
            }
        }
    }
}

Export-ModuleMember -Function *-Satellite*
