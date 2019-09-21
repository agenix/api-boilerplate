import {Router} from 'express';
import {Login} from './controllers/login';
import {Register} from './controllers/register';

const router = Router();

router.post('/login', Login.validateLogin, Login.login);
router.post('/login/reset_password', Login.validateResetPassword, Login.resetPassword);
router.post('/login/confirm_password', Login.validateConfirmPassword, Login.confirmPassword);

router.post('/register', Register.validateRegister, Register.register);
router.post('/register/resend_email', Register.validateResendEmail, Register.resendEmail);
router.post('/register/confirm_email', Register.validateConfirmEmail, Register.confirmEmail);

export {router};
