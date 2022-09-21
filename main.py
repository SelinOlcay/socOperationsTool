import datetime
import re 
import strictyaml 
import requests 
import hashlib 

import time
import tkinter
import os
import sys

import socket
import whois

try:
    f = open("config.yaml", "r")
    configvars = strictyaml.load(f.read())
    f.close()
except FileNotFoundError:
    print("Config.yaml not found.")


def switchMenu(choice):
    if choice == '1':
        urlSanitise()
    if choice == '2':
        emailSanitise()
    if choice == '3':
        urlscan()
    if choice == '4':
        phishingurl_list()
    if choice == '5':
        Md5Encoder()
    if choice == '6':
        reverseDnsLookup()
    if choice == '7':
        dnsLookup()
    if choice == '8':
        unshortenUrl() 
    else:
        mainMenu()
def mainMenu():
    print("\n --------------------------------- ")
    print("\n        SOC - TOOLS JOTFORM          ")
    print("\n --------------------------------- ")
    print(" What would you like to do? ")
    print("\n OPTION 1: URL Sanitise ")
    print("\n OPTION 2: EMAIL Sanitise ")
    print("\n OPTION 3: URL Scan")
    print("\n OPTION 4: URL Phishing Detection")
    print("\n OPTION 5: MD5 Decoder")
    print("\n OPTION 6: Reverse Dns Lookup")
    print("\n OPTION 7: Dns Lookup")
    print("\n OPTION 8: Unshorten URL")    


    switchMenu(input())

def karar():
    print("\n Do you want to continue yes/no")
    switchKarar(input())

def switchKarar(choice):
    if choice == 'yes':
        mainMenu()
    if choice == 'no':
        print("\n Good Byee ...")
        exit()

def urlSanitise():
    print("\n --------------------------------- ")
    print("        URL  SANITISE   TOOL ")
    print(" --------------------------------- ")
    url = str(input("Enter URL to sanitize: ").strip())
    x = re.sub(r"\.", "[.]", url)
    x = re.sub("http://", "hxxp://", x)
    x = re.sub("https://", "hxxps://", x)
    print("\n" + x)
    karar()

def emailSanitise():
    print("\n --------------------------------- ")
    print("        EMAIL  SANITISE TOOL ")
    print(" --------------------------------- ")
    email = str(input("Enter Email to sanitize: ").strip())
    regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'

    if (re.fullmatch(regex, email)):
        print("Valid Email")
        y = re.sub(r"\@", "[at]", email)
        y = re.sub(r"\.", "[.]", y)
        print("\n" + y)
        karar()

    else:
        print("!!! It is not email !!!!")
        mainMenu()


def urlscan():
    print("\n --------------------------------- ")
    print("        URL SCAN TOOL ")
    print(" --------------------------------- ")
    url_to_scan = str(input('\nEnter url: ').strip())

    try:
        type_prompt = str(input('\nSet scan visibility to Public? \nType "1" for Public or "2" for Private: '))
        if type_prompt == '1':
            scan_type = 'public'
        else:
            scan_type = 'private'
    except:
        print('Please make a selection again.. ')

    headers = {
        'Content-Type': 'application/json',
        'API-Key': configvars.data['URLSCAN_IO_KEY'],
    }

    response = requests.post('https://urlscan.io/api/v1/scan/', headers=headers,
                             data='{"url": "%s", "%s": "on"}' % (url_to_scan, scan_type)).json()

    try:
        if 'successful' in response['message']:
            print('\nNow scanning %s.' % url_to_scan)
            uuid_variable = str(response['uuid']) 
            time.sleep(
                45) 
            scan_results = requests.get(
                'https://urlscan.io/api/v1/result/%s/' % uuid_variable).json() 

            task_url = scan_results['task']['url']
            verdicts_overall_score = scan_results['verdicts']['overall']['score']
            verdicts_overall_malicious = scan_results['verdicts']['overall']['malicious']
            task_report_URL = scan_results['task']['reportURL']

            print("\nurlscan.io Report:")
            print("\nURL: " + task_url)
            print("\nOverall Verdict: " + str(verdicts_overall_score))
            print("Malicious: " + str(verdicts_overall_malicious))
            print("urlscan.io: " + str(scan_results['verdicts']['urlscan']['score']))
            if scan_results['verdicts']['urlscan']['malicious']:
                print("Malicious: " + str(scan_results['verdicts']['urlscan']['malicious']))
            if scan_results['verdicts']['urlscan']['categories']:
                print("Categories: ")
            for line in scan_results['verdicts']['urlscan']['categories']:
                print("\t" + str(line))
            for line in scan_results['verdicts']['engines']['verdicts']:
                print(str(line['engine']) + " score: " + str(line['score']))
                print("Categories: ")
                for item in line['categories']:
                    print("\t" + item)
            print("\nSee full report for more details: " + str(task_report_URL))
            print('')
        else:
            print(response['message'])
    except:
        print(' Error reaching URLScan.io')
    karar()

def phishingurl_list():
    search = str(input('\nEnter url: ').strip())
    URL1 = 'https://openphish.com/feed.txt'
    URL2 = 'https://phishunt.io/feed.txt'
    phish1 = requests.get(URL1).text
    phish2 = requests.get(URL2).text
    parsed_data1 = phish1.split("\n")
    parsed_data2 = phish2.split("\n")
    if search in parsed_data1 or parsed_data2:
        print("Detection the phishing URL")
    else:
        print('No Phishing URL')
    karar()

def Md5Encoder():
    text = input(" Please input the encoded text: ")
    print(" MD5 Encoded Text: " + hashlib.md5(text.encode("utf-8")).hexdigest())
    karar()

def reverseDnsLookup():
    d = str(input(" Enter IP: ").strip())
    try:
        s = socket.gethostbyaddr(d)
        print('\n ' + s[0])
    except:
        print(" Hostname not found")
    karar()

def dnsLookup():
    d = str(input(" Enter Domain Name: ").strip())
    d = re.sub("http://", "", d)
    d = re.sub("https://", "", d)
    try:
        s = socket.gethostbyname(d)
        print('\n ' + s)
    except:
        print("Website not found")
    karar()

def unshortenUrl():
    link = str(input(' Enter URL: ').strip())
    req = requests.get(str('https://unshorten.me/s/' + link))
    print(req.text)

def hashRatingChecking():
    apierror = False
    # Virus Total Hash Control
    fileHash = str(input(" Enter Hash of file: ").strip())
    url = 'https://www.virustotal.com/vtapi/v2/file/report'

    params = {'apikey': configvars.data['VT_API_KEY'], 'resource': fileHash}
    response = requests.get(url, params=params)

    try:  # EAFP
        result = response.json()
    except:
        apierror = True
        print("Error: Invalid API Key")

    if not apierror:
        if result['response_code'] == 0:
            print("\n Hash was not found in Malware Database")
        elif result['response_code'] == 1:
            print(" VirusTotal Report: " + str(result['positives']) + "/" + str(result['total']) + " detections found")
            print("   Report Link: " + "https://www.virustotal.com/gui/file/" + fileHash + "/detection")
        else:
            print("No Reponse")
    karar()


if __name__ == '__main__':
    mainMenu()
