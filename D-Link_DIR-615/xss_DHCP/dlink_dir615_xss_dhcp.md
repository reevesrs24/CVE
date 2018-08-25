# D-Link DIR-615 XSS Via DHCP #

**Vendor** ：D-Link

**Product** : DIR-615

**Version**: 20.07

**Hardware Version**: T1

**Vendor Homepage**: http://us.dlink.com/


## Vulnerability detail ##

Verification Steps:

1. In the xss_dhcp.py script set the 'interface' and 'mac' variable.
    - Set 'interface' to the network adapter's name
    - Set 'mac' to the network adapter's mac address
2. Set the 'hostname' variable in the dhcp_request function to some arbitrary javascript
    - e.g. <script>alert('xss')</script>
3. Set the 'siaddr' variable in the dhcp_request function to the D-Link router's local IP address
4. Connect to the router which is undergoing the test
5. Run the python script with **administrator privileges**
6. Navigate to the Status->ActiveClientTable tab in the router admin page to verify that the javascript was uploaded
![alt text](screenshots/xss_dhcp.png "")