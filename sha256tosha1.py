import requests
import json
import re

x = input("Search URLs, domains, IPs and tag comments:\n")
url = "https://www.virustotal.com/api/v3/search?query="+x

headers = {
        "accept": "application/json",
        "x-apikey": "your api key goes here"
    }
response = requests.get(url, headers=headers)
data=response.json()