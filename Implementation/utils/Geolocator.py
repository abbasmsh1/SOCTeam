import requests

class GeoLocator:
    def __init__(self, token: str = None):
        # Optional token for ipinfo.io
        self.token = token
        self.base_url = "https://ipinfo.io/"

    def lookup_geolocation(self, ip: str) -> dict:
        """
        Returns detailed geolocation info for an IP address.
        Returns:
            {
                "ip": str,
                "hostname": str,
                "city": str,
                "region": str,
                "country": str,
                "loc": str,
                "org": str,
                "postal": str,
                "timezone": str,
                "notes": str
            }
        """
        # Handle internal/private IP ranges
        if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
            return {
                "ip": ip,
                "hostname": None,
                "city": None,
                "region": None,
                "country": "Internal Network",
                "loc": None,
                "org": None,
                "postal": None,
                "timezone": None,
                "notes": "Internal Network"
            }
        
        try:
            url = f"{self.base_url}{ip}/json"
            if self.token:
                url += f"?token={self.token}"
            
            response = requests.get(url, timeout=5)
            if response.status_code != 200:
                return {"ip": ip, "notes": "Unable to fetch geolocation"}
            
            data = response.json()
            return {
                "ip": ip,
                "hostname": data.get("hostname"),
                "city": data.get("city"),
                "region": data.get("region"),
                "country": data.get("country"),
                "loc": data.get("loc"),  # latitude,longitude
                "org": data.get("org"),
                "postal": data.get("postal"),
                "timezone": data.get("timezone"),
                "notes": "External IP"
            }
        except Exception as e:
            return {"ip": ip, "notes": f"Error: {e}"}
    
    def locate_ip(self, ip: str) -> dict:
        """
        Alias for lookup_geolocation for compatibility.
        Returns detailed geolocation info for an IP address.
        """
        return self.lookup_geolocation(ip)


# Example usage
# geo = GeoLocator()
# print(geo.lookup_geolocation("89.187.177.74"))
# # print(geo.lookup_geolocation("192.168.1.1"))
