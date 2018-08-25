# D-Link DIR-615 XSS Via the UPnP Protocol #

**Vendor** ：D-Link

**Product** : DIR-615

**Version**: 20.07

**Hardware Version**: T1

**Vendor Homepage**: http://us.dlink.com/


## Vulnerability detail ##

Verification Steps:

1. Connect to the D-Link DIR-615 router.
2. Run the xss_upnp.py script with the -d switch to start the UPnP "Simple Search Discovery Process". 
   to retrieve the "upnp:rootdevice" uuid.
3. Two results should be displayed to the terminal "http://192.168.0.1:5431/igdevicedesc.xml" and "http://192.168.0.1:54217/simplecfg.xml".
4. Navigate to "http://192.168.0.1:5431/igdevicedesc.xml" to retrieve the UPnP control url
    - **Note:** The port number and xml file may vary depending on the router, look for the "urn:schemas-upnp-org:service:WANIPConnection:1"
      xml element to find the control url.
    ![alt text](screenshots/control_url.png "")
3. Set the 'url' variable in the xss_upnp.py script to the control-url.
    - e.g. 'http://192.168.0.1:5431/control/WANIPConnection'
4. Set the 'NewPortMappingDescription' field in the "add_port_mapping" function to an HTML where the attribute is javascript.
    - i.e. "<img src="" onerror=alert("XSS") />" (The <script> tag caused the page to fail to load, but adding javascript to an attribute worked)
5. Set the "NewInternalClient" field in the "add_port_mapping" function to the D-Link router's local IP address.
6. Run the xss_upnp.py script with the -m switch to add the port mapping.
    - If successful the router should return an xml acknowledgement similar to this
      "<?xml version="1.0"?>
        <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
            <s:Body>
                <u:AddPortMappingResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"></u:AddPortMappingResponse>
            </s:Body>
        </s:Envelope>"
7. Navigate to the router's Advanced->UPnP page to verify the xss.
    ![alt text](screenshots/xss_upnp.png "")