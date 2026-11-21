# RouterOS v7 - install direct endpoint routes before removing legacy policy
{
    :local uplink "toTR"
    :local routeTag "Mullvad endpoint via toTR"
    :if ([:len [/interface wireguard find where name=$uplink and running=yes and disabled=no]] != 1) do={ :error "toTR must be running" }
    :local prefixes {"23.144.160.67/32";"23.165.56.3/32";"23.234.72.2/32";"23.234.76.2/32";"23.234.88.3/32";"23.234.112.3/32";"23.234.116.3/32";"37.19.210.1/32";"37.19.221.130/32";"37.120.246.130/32";"38.240.225.36/32";"43.225.189.131/32";"45.129.56.67/32";"45.134.79.67/32";"45.134.140.130/32";"45.134.142.219/32";"45.134.212.66/32";"45.134.213.194/32";"45.142.26.2/32";"45.153.102.3/32";"79.127.149.130/32";"79.127.222.194/32";"80.66.197.3/32";"91.90.123.2/32";"93.115.0.3/32";"95.173.223.130/32";"98.98.12.178/32";"98.98.47.130/32";"103.75.11.50/32";"103.125.233.18/32";"103.214.20.50/32";"103.216.220.18/32";"104.36.50.3/32";"104.193.135.196/32";"129.227.46.130/32";"129.227.118.162/32";"135.136.54.2/32";"135.136.123.130/32";"138.199.15.162/32";"138.199.21.239/32";"138.199.34.129/32";"138.199.43.91/32";"138.199.60.2/32";"141.98.252.67/32";"146.70.116.130/32";"146.70.132.2/32";"146.70.188.130/32";"146.70.189.2/32";"146.70.193.2/32";"146.70.196.194/32";"146.70.198.66/32";"146.70.200.2/32";"146.70.211.66/32";"149.22.83.2/32";"149.22.91.66/32";"149.88.20.206/32";"149.88.22.129/32";"149.88.104.2/32";"149.102.229.129/32";"149.102.240.79/32";"149.102.246.2/32";"154.47.16.34/32";"154.47.29.2/32";"154.47.30.130/32";"156.59.50.194/32";"158.173.123.2/32";"163.47.16.146/32";"169.150.198.66/32";"169.150.227.197/32";"176.125.235.71/32";"178.249.211.66/32";"178.249.214.2/32";"185.141.119.131/32";"185.156.46.130/32";"185.188.61.195/32";"185.195.233.76/32";"185.201.188.3/32";"185.204.1.203/32";"185.213.154.66/32";"185.213.155.73/32";"185.213.193.3/32";"193.19.207.195/32";"193.32.126.66/32";"193.32.127.71/32";"193.32.248.66/32";"193.32.249.69/32";"193.138.218.220/32";"194.127.166.2/32";"194.127.199.2/32";"195.47.194.131/32";"213.232.112.3/32"}
    :foreach peer in=[/interface wireguard peers find where interface~"^mv-wg-" and disabled=no] do={
        :local ip [:toip [/interface wireguard peers get $peer endpoint-address]]
        :if ([:typeof $ip] != "ip") do={ :set ip [:toip [/interface wireguard peers get $peer current-endpoint-address]] }
        :if ([:typeof $ip] != "ip") do={ :error "An enabled Mullvad peer has no usable IPv4 endpoint" }
        :local prefix ([:tostr $ip] . "/32")
        :if ([:typeof [:find $prefixes $prefix]] = "nil") do={ :set prefixes ($prefixes, $prefix) }
    }
    :foreach peer in=[/interface wireguard peers find where interface=$uplink and disabled=no] do={
        :foreach field in={"endpoint-address";"current-endpoint-address"} do={
            :local ip [:toip [/interface wireguard peers get $peer $field]]
            :if ([:typeof $ip] = "ip") do={
                :if ([:typeof [:find $prefixes ([:tostr $ip] . "/32")]] != "nil") do={ :error "A Mullvad endpoint overlaps the toTR endpoint" }
            }
        }
    }
    :foreach prefix in=$prefixes do={
        :if ([:len [/ip route find where routing-table=main and dst-address=$prefix and disabled=no and gateway!=$uplink]] > 0) do={ :error ("Conflicting main route for " . $prefix) }
    }
    :if ([:len [/ip firewall nat find where chain=srcnat and action=masquerade and out-interface=$uplink and disabled=no]] = 0) do={
        /ip firewall nat add chain=srcnat action=masquerade out-interface=$uplink comment="NAT for WireGuard toTR"
    }
    :foreach prefix in=$prefixes do={
        :if ([:len [/ip route find where routing-table=main and dst-address=$prefix and gateway=$uplink and disabled=no]] = 0) do={
            /ip route add dst-address=$prefix gateway=$uplink routing-table=main comment=$routeTag
        }
    }
    :foreach prefix in=$prefixes do={
        :if ([:len [/ip route find where routing-table=main and dst-address=$prefix and gateway=$uplink and active=yes]] = 0) do={ :error ("Inactive route for " . $prefix . ". Retry after routes converge.") }
    }
    /ip firewall mangle remove [find where dynamic=no and action=mark-routing and dst-address-list="MVIPs" and new-routing-mark="mv2tr"]
    /ip firewall filter remove [find where dynamic=no and chain=forward and action=accept and dst-address-list="MVIPs" and comment="Bypass FastTrack for MVIPs"]
    /routing rule remove [find where table="mv2tr" and routing-mark="mv2tr" and action=lookup-only-in-table]
    /routing rule remove [find where table="mv2tr" and action=lookup-only-in-table and comment="MVIP handshake via mv2tr"]
    /ip route remove [find where dynamic=no and routing-table="mv2tr" and gateway=$uplink and (comment="Mullvad Route via toTR" or comment="default via toTR" or comment="MVIP via toTR")]
    :if (([:len [/ip firewall mangle find where dst-address-list="MVIPs" or src-address-list="MVIPs"]] = 0) and ([:len [/ip firewall filter find where dst-address-list="MVIPs" or src-address-list="MVIPs"]] = 0) and ([:len [/ip firewall nat find where dst-address-list="MVIPs" or src-address-list="MVIPs"]] = 0) and ([:len [/ip firewall raw find where dst-address-list="MVIPs" or src-address-list="MVIPs"]] = 0)) do={
        /ip firewall address-list remove [find where list="MVIPs" and dynamic=no]
    }
    :foreach route in=[/ip route find where routing-table=main and gateway=$uplink and dynamic=no and comment=$routeTag] do={
        :local prefix [:tostr [/ip route get $route dst-address]]
        :if ([:typeof [:find $prefixes $prefix]] = "nil") do={ /ip route remove $route }
    }
    :put ("Verified Mullvad endpoint routes in main: " . [:len $prefixes])
}
