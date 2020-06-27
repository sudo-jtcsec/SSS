import shodan
import sys
import requests, time
from discord_webhook import DiscordWebhook
requests.packages.urllib3.disable_warnings() 

def discordMessage(text):
        webhook = DiscordWebhook(url=URLHERE, content=text)
        webhook.execute()

def checkEndpoint(endpoint,targetIP,targetSite):
        r = requests.get("https://"+targetIP+":443/"+endpoint, verify=False)
        if r.status_code == 200:
                if "unauthorized" not in r.text:
                        noteable.append([targetSite,"https://"+targetIP+":443/"+endpoint])
                        discordMessage("https://"+targetIP+":443/"+endpoint+"\n "+r.text[:50])
                        print("Noteable: "+"https://"+targetIP+":443/"+endpoint+"\n "+r.text[:50])

# Configuration
API_KEY = "APIKEYHERE"

endpointFile = open("spring-endpoints.txt","r")
ends = []
for line in endpointFile:
        ends.append(line.strip())

# Input validation
if len(sys.argv) == 1:
        print('Usage: %s <text file of targets>' % sys.argv[0])
        sys.exit(1)

try:
        # Setup the api
        api = shodan.Shodan(API_KEY)

        fileToCheck = open(sys.argv[1],"r")
        noteable = []
        ips = []
        for line in fileToCheck:
                line.strip()
                parts = line.split(".")
                final = ".".join(parts[:-1])
                query = "ssl:"+line+" http.favicon.hash:116323821"
                print("Trying "+line)
                try:
                        result = api.search(query)
                except:
                        pass
                
                for service in result['matches']:
                        ips.append(str(service['ip_str']))
                        try:
                                for end in ends:
                                        checkEndpoint(end,str(service['ip_str']),line)
                        except:
                                pass
                if len(final.strip()) < 3:
                        pass
                else:
                        query = "ssl:"+final+" http.favicon.hash:116323821"
                time.sleep(2)
                try:
                        result = api.search(query)
                except:
                        pass
                for service in result['matches']:
                        if str(service['ip_str']) not in ips:
                                try:
                                        for end in ends:
                                                checkEndpoint(end,str(service['ip_str']),line)
                                except:
                                        pass
        out = open("springout.txt","w")
        for ip in noteable:
                out.write(str(ip))
except Exception as e:
        print('Error: %s' % e)
        sys.exit(1)
