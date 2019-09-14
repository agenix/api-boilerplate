import AWS = require('aws-sdk');

AWS.config.update({
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  region: 'us-east-1',
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
});

class Email {
    static confirmEmail = async (fullName: string, email: string, confirmationCode: string) => {
      const htmlEmail = `
      <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
      <html xmlns="http://www.w3.org/1999/xhtml">
        <head>
          <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
          <title>Confirm your Worbli account, ${fullName}</title>
          <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
        </head>
        <body style="margin: 0; padding: 0; background-color: #F7F7F7; min-height: 100vh">
          Hi, ${fullName}.<br/>
          Please confirm your Worbli account by clicking this link:
          http://127.0.0.1:3000/confirm_email/${confirmationCode}/<br/>
          Once you confirm, you will have full access to Worbli and all future<br/>
          notifications will be sent to this email address.<br/><br/>
          - Team Worbli<br/>
        </body>
      </html>
      `;
      const params = {
        Destination: {ToAddresses: [email]},
        Message: { Body: {Html: { Charset: 'UTF-8', Data: htmlEmail}}, Subject: {Charset: 'UTF-8', Data: `Confirm your worbli account, ${fullName}`}},
        ReplyToAddresses: ['noreply@worbli.io'],
        Source: 'noreply@worbli.io',
      };
      const send = new AWS.SES({apiVersion: '2010-12-01'}).sendEmail(params).promise();
      const data = await send;
      if (!data) return false; else return true;
  };
}

export {Email};
