# NetScaler-ADC-Config-Pull
Retrieves the list of managed NetScaler ADC instances and their ns.conf configuration files via ADM API Proxy.

PS C:\Windows\system32> C:\MAS_NetScaler_Config_Pull_2.ps1

        SESSID = ##84E7D2270C4B1F9763B325EF2367331E019C5FAE29AC392650C786DC1F3F
        systemname mgmt_ip_address type  id                                  
        ---------- --------------- ----  --                                  
        NetScaler  192.168.2.41    nsvpx 5c2a6ae2-25a2-46bc-85c3-2c1d65ecfba3
        
        # ID: 5c2a6ae2-25a2-46bc-85c3-2c1d65ecfba3
        #NS12.0 Build 56.20
        # Last modified by `save config`, Sun Apr  1 02:10:49 2018
        set ns config -IPAddress 192.168.2.41 -netmask 255.255.255.0
        enable ns feature LB CS SSL SSLVPN AAA AppFlow
        ...
