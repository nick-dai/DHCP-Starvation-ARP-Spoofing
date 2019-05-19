# DHCP-Starvation-ARP-Spoofing
A script used to analyze pcap/pcapng files for DHCP Starvation and ARP Spoofing.

Usage
-
`python dhcp_arp.py [pcap/pcapng]`

Result
-
[ DHCP Starvation ]<br>
[1] "ComputerName" (MAC_Adr by Brand) sent 6194 discoveries (0.482544/s), and requested 881 IPs.<br>
[2] "ComputerName" (MAC_Adr by Brand) sent 866 discoveries (0.067466/s), and requested 812 IPs.<br>
[3] "ComputerName" (MAC_Adr by Brand) sent 823 discoveries (0.064116/s), and requested 770 IPs.<br>
...<br>
<br>
[ ARP Spoofing ]<br>
[i] IP_Adr has 2 mac addresses:<br>
    MAC_Adr (Juniper Networks): 200 times<br>
    MAC_Adr (ASUSTek COMPUTER INC.): 2 times<br>
[i] IP_Adr has 3 mac addresses:<br>
    MAC_Adr (Microsoft Corporation): 1 times<br>
    MAC_Adr (ASUSTek COMPUTER INC.): 1 times<br>
    MAC_Adr (ASUSTek COMPUTER INC.): 1 times<br>
<br>
[i] Total duration: 12836.144487s