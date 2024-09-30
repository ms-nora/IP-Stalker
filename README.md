#IP-Stalker

Copyright [2024] [ms-nora]


#Description 

The IP Stalker Tool is a Python-based utility for performing comprehensive IP address lookups. 
It gathers detailed geolocation data, checks for potential abuse reports, identifies proxies or VPNs, and scans common ports to provide insights into an IP's activity. 
It's designed for cybersecurity enthusiasts and network administrators who need to evaluate the status of IP addresses for security purposes.

#Features

 + GeoIP Lookup: Retrieves geolocation data (city, country, latitude, longitude, ISP) using the MaxMind GeoLite2 database.

 + AbuseIPDB Integration: Checks if an IP has been reported for abuse, including the abuse confidence score, total reports, 
   and the last reported date.

 + ProxyCheck.io Integration: Detects if the IP address is associated with a proxy, VPN, or TOR.

 + Port Scanning: Scans common ports (e.g., 22, 80, 443) to identify open services on the IP.

 + IPv4/IPv6 Detection: Determines if the IP address is IPv4 or IPv6.

 + Concurrent Lookups: Uses threading to ensure fast lookups and prevent the tool from freezing.

#Requirements

 + Python 3.6 or higher
  * Required libraries:
  * requests
  * geoip2
  * ipwhois
  * tkinter
  * 
You can install these dependencies using pip:
 ```python pip install requests geoip2 ipwhois```

#Usage

1. Clone or download the repository to your local machine.
2. Make sure you have the GeoLite2-City.mmdb file from MaxMind. You can download it here.
3. Open a terminal in the project directory and run:
  ```python python3 ip_stalker.py```

5. Input the following:
   
 - The IP address you want to analyze.
 - The path to the GeoLite2-City.mmdb file.
 - Your AbuseIPDB and ProxyCheck.io API keys.
 - Click Lookup to gather information about the IP address.

#API Key Setup
  + AbuseIPDB: Sign up for a free account at AbuseIPDB.
  + ProxyCheck.io: Sign up for a free API key at ProxyCheck.io.
    
#Output The tool will display:

  + IP Version: Whether the IP is IPv4 or IPv6.
  + GeoIP Data: Geolocation details such as country, city, and ISP.
  + Abuse Report: Information on whether the IP has been reported for abuse.
  + Open Ports: List of open ports if any services are detected.
  + Proxy Check: Information on whether the IP is associated with a proxy, VPN, or TOR.
    
#Contributing 

Feel free to submit pull requests or open issues if you have any suggestions or find any bugs.

#License 

This project is licensed under the Apache License 2.0. See the LICENSE file for more details.




