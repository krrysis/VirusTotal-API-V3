import requests
import json

def vt():
    #print('Search files, URLs, domains, IPs and tag comments')
    x = input("Search files, URLs, domains, IPs and tag comments:\n")
    url = "https://www.virustotal.com/api/v3/search?query="+x

    headers = {
        "accept": "application/json",
        "x-apikey": "put your api key between the double quotes"
    }

    response = requests.get(url, headers=headers)
    data=response.json()
    #print(response.text)
    if len(data["data"]) > 0:
        Malicious=("Malicious:", data["data"][0]["attributes"]["last_analysis_stats"]['malicious'])
        Undetected=("Undetected:", data["data"][0]["attributes"]["last_analysis_stats"]['undetected'])

        if Malicious[-1] > 0:
            print('\x1b[31m'+"🔴 MALICIOUS \n"+'\x1b[0m')
            #print(Malicious,"\n",Undetected)
            print("Malicious: ",Malicious[-1])
            print("Undetected: ",Undetected[-1])
        else:
            print('\x1b[32m'+'🟢 CLEAN \n'+'\x1b[0m')
            #print(Malicious,"\n",Undetected)
            print("Malicious: ",Malicious[-1])
            print("Undetected: ",Undetected[-1])
    else:

        print('\x1b[1;33;40m' +'\n🟡 NO DATA FOUND' + '\x1b[0m')

    input("\n press ENTER to exit")
    
    
while True:
    vt()
    answer = input("Do you want to search anything else? (y/n): ")
    if answer.lower() == "n":
        break
