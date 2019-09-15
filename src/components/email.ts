import AWS = require('aws-sdk');

AWS.config.update({
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  region: 'us-east-1',
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
});

let frontEndUrl: string;
if (process.env.NODE_ENV === 'production') frontEndUrl = process.env.PROD_FRONT_END_URL;
else frontEndUrl = process.env.DEV_FRONT_END_URL;

class Email {

  static confirmEmail = async (fullName: string, email: string, confirmationCode: string) => {
    try {


      const html = `
      <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
      <html xmlns="http://www.w3.org/1999/xhtml">
        <head>
          <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
          <title>Confirm your Worbli account, ${fullName}</title>
          <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
        </head>
        <body style="margin: 0; padding: 0; background-color: #F7F7F7; min-height: 100vh">
          <h1>Confirm your Worbli account<h1/>
          <hr/>
          Hi, ${fullName}.<br/>
          Please confirm your Worbli account by clicking this link:
          ${frontEndUrl}/confirm_email/${confirmationCode}/<br/>
          Once you confirm, you will have full access to Worbli and all future<br/>
          notifications will be sent to this email address.<br/><br/>
          - Team Worbli<br/><br/>
          Control which emails you receive from Worbli by adjusting your <a href='${frontEndUrl}/my/settings/'>settings.<a/>
        </body>
      </html>
      `;
      const params = {
        Destination: { ToAddresses: [email] },
        Message: { Body: { Html: { Charset: 'UTF-8', Data: html }},
        Subject: { Charset: 'UTF-8', Data: `Confirm your worbli account, ${fullName}`} },
        ReplyToAddresses: ['do-not-reply@worbli.io'], Source: 'do-not-reply@worbli.io',
      };
      const data = await new AWS.SES({apiVersion: '2010-12-01'}).sendEmail(params).promise();
      if (!data) return false; else return true;
    } catch (err) {
        // tslint:disable-next-line: no-console
        console.log(err);
    }
  };

  static resetPassword = async (fullName: string, email: string, resetCode: string) => {
    try {
      const html = `
      <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
      <html xmlns="http://www.w3.org/1999/xhtml">
        <head>
          <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
          <title>Reset your Worbli password, ${fullName}</title>
          <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
        </head>
        <body style="margin: 0; padding: 0; background-color: #F7F7F7; min-height: 100vh">
          <h1>Reset your Worbli password<h1/>
          <hr/>
          Hi, ${fullName}.<br/>
          If you requested a password reset link, click the link below. If you didn’t make the request, you can safely discard this email.
          ${frontEndUrl}/reset_password/${resetCode}/<br/><br/>
          - Team Worbli<br/><br/>
          Control which emails you receive from Worbli by adjusting your <a href='${frontEndUrl}/my/settings/'>settings.<a/>
        </body>
      </html>
      `;
      const params = {
        Destination: { ToAddresses: [email] },
        Message: { Body: { Html: { Charset: 'UTF-8', Data: html }},
        Subject: { Charset: 'UTF-8', Data: `reset your Worbli password`} },
        ReplyToAddresses: ['do-not-reply@worbli.io'], Source: 'do-not-reply@worbli.io',
      };
      const data = await new AWS.SES({apiVersion: '2010-12-01'}).sendEmail(params).promise();
      if (!data) return false; else return true;
    } catch (err) {
        // tslint:disable-next-line: no-console
        console.log(err);
    }
  };
}

export {Email};
