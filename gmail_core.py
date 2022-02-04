import base64
from email.mime.text import MIMEText
import mimetypes
import os

from apiclient import errors

class Gmail:
    def __init__(self,service,debug):
        self.service = service
        self.user_id = "me"
        self.debug = debug

    def ListMessagesWithLabels(self, label_ids=[]):
        """List all Messages of the user's mailbox with label_ids applied.

        Args:
            service: Authorized Gmail API service instance.
            user_id: User's email address. The special value "me"
            can be used to indicate the authenticated user.
            label_ids: Only return Messages with these labelIds applied.

        Returns:
            List of Messages that have all required Labels applied. Note that the
            returned list contains Message IDs, you must use get with the
            appropriate id to get the details of a Message.
        """
        try:
            response = self.service.users().messages().list(userId=self.user_id,
                                                    labelIds=label_ids).execute()
            messages = []
            if 'messages' in response:
                messages.extend(response['messages'])

            while 'nextPageToken' in response:
                page_token = response['nextPageToken']
                response = self.service.users().messages().list(userId=self.user_id,
                                                            labelIds=label_ids,
                                                            pageToken=page_token).execute()
                messages.extend(response['messages'])

            return messages
        except errors.HttpError as error:
            print('ListMessageWithLabels - An error occurred: %s' % error)

    def GetMessage(self, msg_id):
        """Get a Message with given ID.

        Args:
            service: Authorized Gmail API service instance.
            user_id: User's email address. The special value "me"
            can be used to indicate the authenticated user.
            msg_id: The ID of the Message required.

        Returns:
            A Message.
        """
        try:
            message = self.service.users().messages().get(userId=self.user_id, id=msg_id).execute()
            return message
        except errors.HttpError as error:
            print('GetMessage - An error occurred: %s' % error)

    def DeleteMessage(self, msg_id):
        """Delete a Message.

        Args:
            service: Authorized Gmail API service instance.
            user_id: User's email address. The special value "me"
            can be used to indicate the authenticated user.
            msg_id: ID of Message to delete.
        """
        if not self.debug:
            try:
                self.service.users().messages().delete(userId=self.user_id, id=msg_id).execute()
                print('Message with id: %s deleted successfully.' % msg_id)
            except errors.HttpError as error:
                print('DeleteMessages - An error occurred: %s' % error)
        else:
            print("D")

    def SendMessage(self, message):
        """Send an email message.

        Args:
            service: Authorized Gmail API service instance.
            user_id: User's email address. The special value "me"
            can be used to indicate the authenticated user.
            message: Message to be sent.

        Returns:
            Sent Message.
        """
        try:
            message = (self.service.users().messages().send(userId=self.user_id, body=message)
                    .execute())
            print('Message Id: %s was sent!' % message['id'])
            return message
        except errors.HttpError as error:
            print('SendMessage - An error occurred: %s' % error)


    def CreateMessage(self,sender, to, subject, message_text):
        """Create a message for an email.

        Args:
            sender: Email address of the sender.
            to: Email address of the receiver.
            subject: The subject of the email message.
            message_text: The text of the email message.

        Returns:
            An object containing a base64url encoded email object.
        """
        message = MIMEText(message_text,'html')
        message['to'] = to
        message['from'] = sender
        message['subject'] = subject
        return {'raw': base64.urlsafe_b64encode(message.as_bytes()).decode()}