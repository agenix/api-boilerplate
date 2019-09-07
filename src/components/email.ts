class Email {
    static validateEmail = async (fullName: string, email: string, verificationCode: string) => {

// from: noreply@worbli.io
// Title: Conform your worbli account, [fullName]
// Hi, [fullName].
// Please confirm your Worbli account by clicking this link:
// http://127.0.0.1:3000/confirm_email/[verificationCode]/
// Once you confirm, you will have full access to Worbli and all future
// notifications will be sent to this email address.
// - Team Worbli

        console.log('sending email');
  };
}

export {Email};
