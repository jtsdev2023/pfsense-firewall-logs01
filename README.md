# pfsense-firewall-logs01
Scripts to do the following:
- SCP PFSense firewall (FW) filter logs from FW to local directory.
- Parse through FW filter logs and return destination IP addresses.
- Retrieve ARIN IP address information via ARIN RDAP web API.
- Extract and write to file the ARIN CIDR prefix with length and organization name.
- Create a zip file of the ARIN API JSON data.
