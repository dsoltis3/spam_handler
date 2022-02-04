from __future__ import print_function
import os.path
import pickle
import re
import argparse
import base64
import json
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from gmail_core import Gmail
import whois_core

SCOPES = ['https://mail.google.com/']
SUBJECT = 'Unsolicited Spam Emails'

def main(args):
    user = args.email
    debug = False
    try:
        if args.debug:
            debug = True
    except:
        debug = False
    """Shows basic usage of the Gmail API.
    Lists the user's Gmail labels.
    """
    creds = None
    # The file token.pickle stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first
    # time.
    if os.path.exists('token.pickle'):
        with open('token.pickle', 'rb') as token:
            creds = pickle.load(token)
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)
            creds = flow.run_local_server()
        # Save the credentials for the next run
        with open('token.pickle', 'wb') as token:
            pickle.dump(creds, token)

    service = build('gmail', 'v1', credentials=creds)

    # Create Gmail instance with the above created service
    gmail = Gmail(service,debug=debug)

    # Return the list of all SPAM emails
    spam_messages = gmail.ListMessagesWithLabels(label_ids=['SPAM'])
    if len(spam_messages) > 0:
        print('Got spam messages')

    messages_list = []
    
    for message in spam_messages:
        message_id = message['id']
        message = gmail.GetMessage(msg_id=message['id'])
        data = None
        if message['payload']['body']['size'] != 0:
            data = message['payload']['body']['data']
        else:
            eggs = message['payload']['parts']
            for egg in eggs:
                try:
                    data = egg['body']['data']
                except KeyError:
                    print('KeyError')
        if not data:
            print(message)
            gmail.DeleteMessage(message_id)
            continue
        parsed_data = base64.urlsafe_b64decode(data).decode('utf-8')
        header = Headers(message['payload']['headers'])
        ip = header.get_ip()
        print("IP: {}".format(ip))
        if ip:
            who = whois_core.Whois(ip)
            email = who.get_abuse_email()
            if email:
                # print("Send {}\nTo {}".format(header_value,email))
                message = Message(to=email,sender=user,ip=ip,date=header.get_date(),headers=message['payload']['headers'],data=parsed_data)
                new_message = gmail.CreateMessage(user,email,SUBJECT,''.join(message.get_message()))
                gmail.SendMessage(new_message)
        gmail.DeleteMessage(message_id)

def find_ip(text):
    # Check for ipv4 address
    ip_match = re.compile("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
    ipv6_pattern = "(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))"
    ipv6_match = re.compile(ipv6_pattern)
    ip_addr = ip_match.search(text)
    if not ip_addr:
        print("Is IPV6?")
        ip_addr = ipv6_match.search(text)
    print(ip_addr)
    return ip_addr.group(0)

class Message:
    def __init__(self,to, sender,ip,date,headers,data):
        self.to = to
        self.ip = ip
        self.date = date
        self.headers = headers
        self.data = data
        self.message = ['Below are details on spam emails coming from an IP address associated to you based on ARIN data. There is either no way to unsubscribe or the link provided to unsubscribe will subscribe to more spam. I will continue to email you a list of these unsolicited emails until I stop receiving them\n\n','<html>','<table border= "1px solid black">']
        self.add_message("IP Address: {}".format(self.ip))
        self.add_message("Date: {}".format(self.date))
        self.add_message("Header Content: {}".format(self.headers))
        self.add_message("Message Content: {}".format(self.data))

    def add_message(self,message):
        self.message.append('<tr><td>{}</tr></td>'.format(message))

    def get_message(self):
        self.message.append('</table></html>')
        return self.message

    def get_size(self):
        return len(self.message)

class Headers:
    def __init__(self,header):
        self.header = header

    def get_date(self):
        for thing in self.header:
             if thing['name'] == 'Date':
                 return thing['value']
        return False

    def get_ip(self):
        for thing in self.header:
            if thing['name'] == 'Received-SPF':
                print(thing['value'])
                return find_ip(thing['value'])
        return False

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Script to take all labeled spam messages and report to their abuse emails based on ARIN data')
    parser.add_argument('-email',help="Your email address. Used as the from sender")
    parser.add_argument('-debug',help="Set to anything to run in debug mode")
    args = parser.parse_args()
    main(args)