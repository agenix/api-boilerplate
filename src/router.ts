import {Router} from 'express';
import {User} from './controllers/user';

const router = Router();

router.post('/user/login', User.validateLogin, User.login);
router.post('/user/resend_email', User.validateResendEmail, User.resendEmail);
router.post('/user/register', User.validateRegister, User.register);
router.post('/user/confirm_email', User.validateConfirmEmail, User.confirmEmail);

export {router};
