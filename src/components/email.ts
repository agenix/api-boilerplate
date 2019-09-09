class Email {
    static emailConfirmation = async (fullName: string, email: string, confirmationCode: string) => {

    // from: noreply@worbli.io
    // Title: Confirm your worbli account, [fullName]
    // Hi, [fullName].
    // Please confirm your Worbli account by clicking this link:
    // http://127.0.0.1:3000/confirm_email/[confirmationCode]/
    // Once you confirm, you will have full access to Worbli and all future
    // notifications will be sent to this email address.
    // - Team Worbli

    // tslint:disable-next-line: no-console
    console.log('sending email');
    return true;
  };
}

export {Email};
