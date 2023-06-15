import requests
import json
import re
import csv

#working: IPs, hashes, URLs, domains
#notworking: files
def vt():
    #print('Search files, URLs, domains, IPs and tag comments')
    #x = input("Search URLs, domains, IPs and tag comments:\n")
    with open('file.csv', newline='') as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            x=row[0]
            url = "https://www.virustotal.com/api/v3/search?query="+x

            headers = {
                "accept": "application/json",
                "x-apikey": "put your api key between the double quotes"
            }

            response = requests.get(url, headers=headers)
            data=response.json()
            pattern = r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
            url_pattern = r"(https?://)?(www\.)?([a-zA-Z0-9]+(-?[a-zA-Z0-9])*\.)+[a-z]{2,}(/[\w\-]*)*"
            regex = re.compile(pattern)
            regexurl = re.compile(url_pattern)
            
                
            #print(response.text)
            print(row[0]+": ")
            if len(data["data"]) > 0:
                Malicious=("Malicious:", data["data"][0]["attributes"]["last_analysis_stats"]['malicious'])
                Undetected=("Undetected:", data["data"][0]["attributes"]["last_analysis_stats"]['undetected'])
                #Sha1=("SHA1:", data["data"][0]["attributes"]["sha1"])
                
                
                if regex.match(x):
                    pass
                elif regexurl.match(x):
                    pass
                else:
                    Sha1=("SHA1:", data["data"][0]["attributes"]["sha1"])
                    
                    
                if Malicious[-1] > 0:
                    print('\x1b[31m'+"🔴 MALICIOUS \n"+'\x1b[0m')
                    #print(Malicious,"\n",Undetected)
                    print("Malicious: ",Malicious[-1])
                    print("Undetected: ",Undetected[-1])
                    print("---------------------------"+'\x1b[0m')
                    
                    if regex.match(x):
                        pass
                    elif regexurl.match(x):
                        pass
                    else:
                        print("SHA1: ",Sha1[-1])
                        
                    
                else:
                    print('\x1b[32m'+'🟢 CLEAN \n'+'\x1b[0m')
                    #print(Malicious,"\n",Undetected)
                    print("Malicious: ",Malicious[-1])
                    print("Undetected: ",Undetected[-1])
                    print("---------------------------"+'\x1b[0m')
            else:
                
                print('\x1b[1;33;40m' +'\n🟡 NO DATA FOUND' + '\x1b[0m')

            '''    
            if Malicious[-1] > 0:
                print('\x1b[31m'+"MALICIOUS \n"+'\x1b[0m')
                #print(Malicious,"\n",Undetected)
                print("Malicious: ",Malicious[-1])
                print("Undetected: ",Undetected[-1])
            else:
                print('\x1b[32m'+'CLEAN \n'+'\x1b[0m')
                print(Malicious,"\n",Undetected)
            '''
            #input("\n press ENTER to exit")

while True:
    vt()
    answer = input("\n Do you want to search anything else? (y/n): ")
    if answer.lower() == "n":
        break
