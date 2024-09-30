import tkinter as tk
from tkinter import filedialog, messagebox
import geoip2.database
import ipwhois
import requests
import ipaddress
import socket
import concurrent.futures
import threading

#Function to perform GeoIP lookup
def geoip_lookup(ip, db_path):
    try:
        with geoip2.database.Reader(db_path) as reader:
            response = reader.city(ip)
            return {
                "IP": ip,
                "Country": response.country.name,
                "City": response.city.name,
                "Latitude": response.location.latitude,
                "Longitude": response.location.longitude,
                "ISP": get_isp_info(ip),
                "Time Zone": response.location.time_zone
            }
    except Exception as e:
        return {"Error": str(e)}

#Function to get ISP info using ipwhois
def get_isp_info(ip):
    try:
        obj = ipwhois.IPWhois(ip)
        results = obj.lookup_rdap()
        asn_description = results.get('asn_description', 'ASN description not available')
        return asn_description
    except Exception as e:
        return "ISP lookup failed: " + str(e)

#Function to check IP abuse reports from AbuseIPDB
def check_abuse_ip(ip, api_key):
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
    headers = {
        'Key': api_key,
        'Accept': 'application/json'
    }
    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            abuse_data = response.json()
            return {
                "Abuse Confidence Score": abuse_data['data']['abuseConfidenceScore'],
                "Total Reports": abuse_data['data']['totalReports'],
                "Last Reported": abuse_data['data']['lastReportedAt'],
            }
        else:
            return {"Error": "Failed to fetch AbuseIPDB data."}
    except Exception as e:
        return {"Error": str(e)}

#Function to determine if the IP is IPv4 or IPv6
def ip_version(ip):
    try:
        ip_type = ipaddress.ip_address(ip)
        return f"IPv{ip_type.version}"
    except ValueError:
        return "Invalid IP"

#Function to scan specific ports
def scan_port(ip, port):
    scanner = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket.setdefaulttimeout(0.5)  #Timeout for each port check
    result = scanner.connect_ex((ip, port))  #Check if the port is open
    scanner.close()
    return result == 0  #Returns True if the port is open

#Function to scan common ports
def scan_common_ports(ip):
    common_ports = [21, 22, 23, 25, 53, 80, 110, 443, 8080]
    open_ports = []
    for port in common_ports:
        if scan_port(ip, port):
            open_ports.append(port)
    return open_ports

#Function to check if an IP is a proxy using ProxyCheck.io
def proxy_check(ip, api_key):
    url = f"http://proxycheck.io/v2/{ip}?key={api_key}&vpn=1"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            return response.json()
        else:
            return "Proxy check failed"
    except Exception as e:
        return {"Error": str(e)}

#Main function to perform all lookups concurrently
def perform_all_lookups(ip_address, db_path, abuse_api_key, proxy_api_key):
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_geoip = executor.submit(geoip_lookup, ip_address, db_path)
        future_abuseipdb = executor.submit(check_abuse_ip, ip_address, abuse_api_key)
        future_proxycheck = executor.submit(proxy_check, ip_address, proxy_api_key)
        
        geo_result = future_geoip.result()
        abuse_result = future_abuseipdb.result()
        proxy_result = future_proxycheck.result()
    
    return geo_result, abuse_result, proxy_result

#Function to handle the button click and perform the lookup
def perform_lookup():
    def background_task():
        ip_address = ip_entry.get()
        db_path = file_entry.get()
        abuse_api_key = abuse_api_entry.get()
        proxy_api_key = proxy_api_entry.get()

        if not db_path or not ip_address or not abuse_api_key or not proxy_api_key:
            messagebox.showerror("Input Error", "Please provide the database path, IP address, and both API keys.")
            return

        #Check the IP version
        ip_version_result = ip_version(ip_address)

        #Perform all lookups concurrently
        geo_result, abuse_result, proxy_result = perform_all_lookups(ip_address, db_path, abuse_api_key, proxy_api_key)

        #Perform port scan
        open_ports = scan_common_ports(ip_address)

        #Clear the output text area
        output_text.delete(1.0, tk.END)

        #Display IP version
        output_text.insert(tk.END, "IP Version: {}\n".format(ip_version_result))

        #Display GeoIP lookup results
        output_text.insert(tk.END, "GeoIP Lookup Results:\n")
        for key, value in geo_result.items():
            output_text.insert(tk.END, "{}: {}\n".format(key, value))

        #Display AbuseIPDB lookup results
        output_text.insert(tk.END, "\nAbuseIPDB Lookup Results:\n")
        for key, value in abuse_result.items():
            output_text.insert(tk.END, "{}: {}\n".format(key, value))

        #Display open ports
        output_text.insert(tk.END, "\nOpen Ports:\n")
        if open_ports:
            output_text.insert(tk.END, ", ".join(str(port) for port in open_ports) + "\n")
        else:
            output_text.insert(tk.END, "No open ports found\n")

        #Display Proxy Check results
        output_text.insert(tk.END, "\nProxy Check Results:\n")
        if isinstance(proxy_result, dict):
            for key, value in proxy_result.items():
                output_text.insert(tk.END, "{}: {}\n".format(key, value))
        else:
            output_text.insert(tk.END, proxy_result + "\n")

     # Run the background task in a separate thread
    threading.Thread(target=background_task).start()

#Function to open a file dialog to select the GeoLite2 database file
def browse_file():
    filename = filedialog.askopenfilename(title="Select GeoLite2-City.mmdb file", filetypes=[("MMDB Files", "*.mmdb")])
    if filename:
        file_entry.delete(0, tk.END)
        file_entry.insert(0, filename)

#Create the main application window
root = tk.Tk()
root.title("IP STALKER")

tk.Label(root, text="IP Address:").grid(row=0, column=0, padx=10, pady=10)
ip_entry = tk.Entry(root)
ip_entry.grid(row=0, column=1, padx=10, pady=10)

tk.Label(root, text="GeoLite2 Database Path:").grid(row=1, column=0, padx=10, pady=10)
file_entry = tk.Entry(root, width=40)
file_entry.grid(row=1, column=1, padx=10, pady=10)

browse_button = tk.Button(root, text="Browse", command=browse_file)
browse_button.grid(row=1, column=2, padx=10, pady=10)

tk.Label(root, text="AbuseIPDB API Key:").grid(row=2, column=0, padx=10, pady=10)
abuse_api_entry = tk.Entry(root, width=40)
abuse_api_entry.grid(row=2, column=1, padx=10, pady=10)

tk.Label(root, text="ProxyCheck API Key:").grid(row=3, column=0, padx=10, pady=10)
proxy_api_entry = tk.Entry(root, width=40)
proxy_api_entry.grid(row=3, column=1, padx=10, pady=10)

lookup_button = tk.Button(root, text="Lookup", command=perform_lookup)
lookup_button.grid(row=4, column=0, columnspan=3, padx=10, pady=10)

output_text = tk.Text(root, height=40, width=100)
output_text.grid(row=5, column=0, columnspan=3, padx=10, pady=10)

root.mainloop()
