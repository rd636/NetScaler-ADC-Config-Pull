<#
	.SYNOPSIS
		Retreives the list of managged NetScaler ADC instances and their 
        ns.conf configuration files via MAS API Proxy.

	.DESCRIPTION
        Uses the API Proxy feature of Application Delivery Manager (ADM) 
        to fetch configuration data from all the Citrix ADC instances 
        themselves, after retreiving a list of instances and their IDs from
        the ADM Server.

        Benefits of using ADM as an API Proxy:

        Role Based Access enforcement 
          ADM validates all API requests against configured security
          and role-based access control (RBAC) policies. 

        Tennent Enforcement   
          ADM is tenant-aware and ensures API activity does not 
          cross tenant boundaries.

        Centralized auditing 
          ADM maintains an audit log of all API activity related to 
          its managed instances.

        Session management
          ADM frees API clients from the task of having to maintain
          sessions with managed instances.  
	
    .EXAMPLE 	
        PS C:\Windows\system32> C:\MAS_NetScaler_Config_Pull_2.ps1
        SESSID = ##84E7D2270C4B1F9763B325EF2367331E019C5FAE29AC392650C786DC0F3F

        systemname mgmt_ip_address type  id                                  
        ---------- --------------- ----  --                                  
        NetScaler  192.168.2.41    nsvpx 5c2a6ae2-25a2-46bc-85c3-2c1d65ebfba3


        # ID: 5c2a6ae2-25a2-46bc-85c3-2c1d65ebfba3
        #NS12.0 Build 56.20
        # Last modified by `save config`, Sun Apr  1 02:10:49 2018
        set ns config -IPAddress 192.168.2.41 -netmask 255.255.255.0
        enable ns feature LB CS SSL SSLVPN AAA AppFlow
        ...

	.FUNCTIONALITY
		Application Delivery Manager (ADM) v12.0.57.19
        NetScaler ADC (NS) v12.0.56.20

	.NOTES
        AUTHOR : Rick Davis
        EMAIL  : Rick.Davis@citrix.com
        DATE   : 06 APR 2018

        NetScaler ADM as an API Proxy Server
        https://docs.citrix.com/en-us/citrix-application-delivery-management-software/current-release/adm-as-api-proxy-server.html

        To make ADM forward a request to a managed instance, include any one 
        of the following HTTP headers in the API request:

        _MPS_API_PROXY_MANAGED_INSTANCE_NAME   Name of the managed instance.
        _MPS_API_PROXY_MANAGED_INSTANCE_IP     IP address of the managed instance.
        _MPS_API_PROXY_MANAGED_INSTANCE_ID     ID of the managed instance.

        The minimum Role Based Access Policy must include the View setting for:
        Networks > API > Device_API_Proxy 

        Authorized MAS API users also obtain nsroot level instance authorization.
	
	.PARAMETER 
	    No input parameters.
        Edit the $NetScaler hash to change variables.
    
    .VERSION
             TODO: (1) Add Logout (2) Update for MAS 12.1 with NITRO v2 calls.
        2.0  Fetching running config rather than systemfile ns.conf. (June 2018)
		1.2  SSL Works with MAS 'default' certificates.
        1.1  Improved documentation.
        1.0  Initial build.

    .LINK
        https://docs.citrix.com/en-us/netscaler-mas/12/mas-as-api-proxy-server.html
        https://stackoverflow.com/questions/32355556/powershell-invoke-restmethod-over-https

    .COPYRIGHT
        This sample code is provided to you as is with no representations, 
		warranties or conditions of any kind. You may use, modify and 
		distribute it at your own risk. CITRIX DISCLAIMS ALL WARRANTIES 
		WHATSOEVER, EXPRESS, IMPLIED, WRITTEN, ORAL OR STATUTORY, INCLUDING 
		WITHOUT LIMITATION WARRANTIES OF MERCHANTABILITY, FITNESS FOR A 
		PARTICULAR PURPOSE, TITLE AND NONINFRINGEMENT. Without limiting the 
		generality of the foregoing, you acknowledge and agree that (a) 
		the sample code may exhibit errors, design flaws or other problems, 
        possibly resulting in loss of data or damage to property; (b) it may 
		not be possible to make the sample code fully functional; and 
		(c) Citrix may, without notice or liability to you, cease to make 
		available the current version and/or any future versions of the sample 
		code. In no event should the code be used to support ultra-hazardous 
		activities, including but not limited to life support or blasting 
		activities. NEITHER CITRIX NOR ITS AFFILIATES OR AGENTS WILL BE LIABLE,
        UNDER BREACH OF CONTRACT OR ANY OTHER THEORY OF LIABILITY, FOR ANY 
		DAMAGES WHATSOEVER ARISING FROM USE OF THE SAMPLE CODE, INCLUDING 
		WITHOUT LIMITATION DIRECT, SPECIAL, INCIDENTAL, PUNITIVE, CONSEQUENTIAL 
		OR OTHER DAMAGES, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGES. 
		Although the copyright in the code belongs to Citrix, any distribution 
		of the sample code should include only your own standard copyright 
		attribution, and not that of Citrix. You agree to indemnify and defend 
		Citrix against any and all claims arising from your use, modification 
		or distribution of the sample code.
#>
Set-StrictMode -Version 3
$VerbosePreference = "SilentlyContinue"                         #Continue or SilentlyContinue

#####  VARIABLES  #####
$NetScaler = @{                     
                'mas'= @{ 
                          method  = 'http'
                          ipaddress  = '192.168.200.250'
                          username   = 'joe'
                          password   = 'joe'
                        }
             }



#####  FUNCTIONS
function NitroCall {  
    param([hashtable]$global:array)
    Write-Verbose ">>> $($MyInvocation.MyCommand) $(Split-Path $array.uri -leaf)"

    $array.uri         = $array.uri.insert(0, $NetScaler.mas.method+'://'+$NetScaler.mas.ipaddress )
    $array.ContentType = 'application/json';  
    if ( (Split-Path $array.uri -leaf) -eq 'login' ) { 
            $array.SessionVariable = "global:myWebSession"
        } else {
            $array.WebSession      = $global:myWebSession
        } 
    try {
        Invoke-RestMethod @array  
    } catch { 
        Write-Warning $_   
    }
    return
}

##### MAIN

# Disabling cert validation...('default' cert is self-signed.)
add-type @"
        using System.Net;
        using System.Security.Cryptography.X509Certificates;

            public class IDontCarePolicy : ICertificatePolicy {
            public IDontCarePolicy() {}
            public bool CheckValidationResult(
                ServicePoint sPoint, X509Certificate cert,
                WebRequest wRequest, int certProb) {
                return true;
            }
        }
"@
[System.Net.ServicePointManager]::CertificatePolicy = new-object IDontCarePolicy
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12      


#####  Login
$jobj = ConvertFrom-Json '{"login":{"username":"nsroot","password":"nsroot"}}'
$jobj.login.username = $NetScaler.mas.username 
$jobj.login.password = $NetScaler.mas.password
NitroCall @{    'uri'          = '/nitro/v1/config/login' 
			    'Method'	   = 'POST'
                'Body'         = 'object='+(ConvertTo-JSON $jobj)
		    }|out-null
write-host "$($myWebSession.Cookies.GetCookies($array.uri).name) = $($myWebSession.Cookies.GetCookies($array.uri).value)"  


##### Get NetScaler list
$apiCall = NitroCall @{ 'uri'    = '/nitro/v2/config/ns'
                        'Method' = 'GET'   
                      } 


##### Print list of devices
$apiCall.ns | Format-Table -AutoSize -Property systemname, mgmt_ip_address, type, id 


##### Get and Print Config of each NetScaler
foreach ($_ in $apiCall.ns) {    
    write-host  "# ID: $($_.id)"
	write-host  "# Configuration for Netscaler: $($_.hostname)"
    $apiCall = NitroCall @{ 'uri'     = '/nitro/v1/config/nsrunningconfig'
                            'Method'  = 'GET' 
                            'Headers' = @{_MPS_API_PROXY_MANAGED_INSTANCE_ID=$($_.id)}
                          } 
	write-host "Length of configuration: " $apiCall.nsrunningconfig.response.length
    $apiCall.nsrunningconfig.response | Select-Object -First 4

}
exit


##### Append these options to the Encoding line above as desired #>
<#
    # to save each file locally with the MAS instance ID as the filename: 
    | Out-File -FilePath c:\temp\ns-$($_.id).conf 
        
    # to print only the first few lines of each file:
    -split "[\r\n]" | Select-Object -First 4
	
	# to download the configuration through the file system.
	'uri'     = '/nitro/v1/config/systemfile/ns.conf?args=filelocation:%2Fnsconfig'
	[System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($apiCall.systemfile.filecontent)) -split "[\r\n]" | Select-Object -First 4
	
	
#>
