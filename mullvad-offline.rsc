# RouterOS v7 - install direct endpoint routes before removing legacy policy
{
    :local uplink "toTR"
    :local routeTag "Mullvad endpoint via toTR"
    :if ([:len [/interface wireguard find where name=$uplink and running=yes and disabled=no]] != 1) do={ :error "toTR must be running" }
    :local defaults {"al-tia|45.142.26.2/32";"ar-bue|149.22.83.2/32";"at-vie|146.70.116.130/32";"au-adl|103.214.20.50/32";"au-bne|103.216.220.18/32";"au-mel|163.47.16.146/32";"au-per|158.173.123.2/32";"au-syd|146.70.200.2/32";"be-bru|91.90.123.2/32";"bg-sof|146.70.188.130/32";"br-for|98.98.12.178/32";"br-sao|169.150.198.66/32";"ca-mtr|146.70.198.66/32";"ca-tor|178.249.214.2/32";"ca-van|104.193.135.196/32";"ca-yyc|38.240.225.36/32";"ch-zrh|193.32.127.71/32";"cl-scl|149.88.104.2/32";"co-bog|154.47.16.34/32";"cy-nic|195.47.194.131/32";"cz-prg|135.136.123.130/32";"de-ber|193.32.248.66/32";"de-dus|80.66.197.3/32";"de-fra|185.213.155.73/32";"dk-cph|45.129.56.67/32";"ee-tll|213.232.112.3/32";"es-bcn|185.188.61.195/32";"es-mad|45.134.213.194/32";"es-vlc|193.19.207.195/32";"fi-hel|185.204.1.203/32";"fr-bod|45.134.79.67/32";"fr-mrs|138.199.15.162/32";"fr-par|193.32.126.66/32";"gb-glw|185.201.188.3/32";"gb-lon|141.98.252.67/32";"gb-mnc|146.70.132.2/32";"gr-ath|149.102.246.2/32";"hk-hkg|103.125.233.18/32";"hr-zag|154.47.29.2/32";"hu-bud|146.70.196.194/32";"id-jpu|129.227.46.130/32";"ie-dub|146.70.189.2/32";"il-tlv|169.150.227.197/32";"it-mil|178.249.211.66/32";"it-pmo|149.22.91.66/32";"jp-osa|194.127.166.2/32";"jp-tyo|138.199.21.239/32";"mx-qro|149.88.22.129/32";"my-kul|98.98.47.130/32";"ng-los|79.127.149.130/32";"nl-ams|193.32.249.69/32";"no-osl|176.125.235.71/32";"no-svg|194.127.199.2/32";"nz-akl|103.75.11.50/32";"pe-lim|95.173.223.130/32";"ph-mnl|129.227.118.162/32";"pl-waw|45.134.212.66/32";"pt-lis|149.88.20.206/32";"ro-buh|37.120.246.130/32";"rs-beg|146.70.193.2/32";"se-got|185.213.154.66/32";"se-mma|193.138.218.220/32";"se-sto|185.195.233.76/32";"sg-sin|138.199.60.2/32";"si-lju|93.115.0.3/32";"sk-bts|138.199.34.129/32";"th-bkk|156.59.50.194/32";"tr-ist|149.102.229.129/32";"ua-iev|149.102.240.79/32";"us-atl|45.134.140.130/32";"us-bos|43.225.189.131/32";"us-chi|135.136.54.2/32";"us-dal|146.70.211.66/32";"us-den|37.19.210.1/32";"us-det|185.141.119.131/32";"us-hou|37.19.221.130/32";"us-lax|23.234.72.2/32";"us-mia|45.134.142.219/32";"us-mkc|23.234.116.3/32";"us-nyc|23.165.56.3/32";"us-phx|23.234.88.3/32";"us-qas|185.156.46.130/32";"us-rag|23.234.76.2/32";"us-sea|138.199.43.91/32";"us-sfo|45.153.102.3/32";"us-sjc|23.144.160.67/32";"us-slc|23.234.112.3/32";"us-txc|79.127.222.194/32";"us-uyk|104.36.50.3/32";"us-was|185.213.193.3/32";"za-jnb|154.47.30.130/32"}
    :local prefixes [:toarray ""]
    :local installedCities [:toarray ""]
    :foreach peer in=[/interface wireguard peers find where interface~"^mv-wg-" and disabled=no] do={
        :local ip [:toip [/interface wireguard peers get $peer endpoint-address]]
        :if ([:typeof $ip] != "ip") do={ :set ip [:toip [/interface wireguard peers get $peer current-endpoint-address]] }
        :if ([:typeof $ip] != "ip") do={ :error "An enabled Mullvad peer has no usable IPv4 endpoint" }
        :local prefix ([:tostr $ip] . "/32")
        :if ([:typeof [:find $prefixes $prefix]] = "nil") do={ :set prefixes ($prefixes, $prefix) }
        :local iface [/interface wireguard peers get $peer interface]
        :local cityEnd [:find $iface "-wg-" 6]
        :if ([:typeof $cityEnd] = "num") do={
            :local city [:pick $iface 6 $cityEnd]
            :set ($installedCities->$city) true
        }
    }
    :foreach entry in=$defaults do={
        :local sep [:find $entry "|"]
        :local city [:pick $entry 0 $sep]
        :local prefix [:pick $entry ($sep + 1) [:len $entry]]
        :if (([:typeof ($installedCities->$city)] = "nil") and ([:typeof [:find $prefixes $prefix]] = "nil")) do={
            :set prefixes ($prefixes, $prefix)
        }
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
