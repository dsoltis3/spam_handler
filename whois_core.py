import subprocess
import re

class Whois:
    def __init__(self,ip):
        self.ip = ip
    
    def get_abuse_email(self):
        response = self._call_subproc(['whois','{}'.format(self.ip)])
        if response:
            response = response.split('\n')
            for thing in response:
                email_match = re.compile('[\w\.-]+@[\w\.-]+')
                if 'abuse-mailbox' in thing or 'abuse contact' in thing.lower() or 'OrgAbuseEmail' in thing:
                    email = email_match.search(thing)
                    if email:
                        return(email.group(0))
        print("No abuse mailbox found for {}".format(self.ip))
        return False

    def _call_subproc(self,command):
        try:
            return subprocess.check_output(command).decode("utf-8")
        except:
            return False


if __name__ == "__main__":
    test = Whois('80.179.42.5')
    test.get_abuse_email()