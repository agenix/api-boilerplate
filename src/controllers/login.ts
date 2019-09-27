import * as Joi from '@hapi/joi';
import * as bcrypt from 'bcrypt';
import {randomBytes} from 'crypto';
import { NextFunction, Request, Response } from 'express';
import * as jwt from 'jsonwebtoken';
import { Email } from '../components/email';
import { userModel } from '../models/user';

class Login {

  static validateLogin = async (req: Request, res: Response, next: NextFunction) => {
    const schema = Joi.object().keys({
      email: Joi.string().lowercase().trim().email({ minDomainSegments: 2 }).required(),
      password: Joi.string().min(5).required(),
    });
    const { email, password } = req.body;
    Joi.validate({ email, password }, schema, (err, val) => {
      if (!err) {
        req.body = val;
        next();
      } else res.status(400).send(err.details);
    });
  };

  static login = async (req: Request, res: Response) => {
    const { email, password } = req.body;
    const account = await userModel.findOne({email}).exec();
    if (!account) {
      res.status(400).send({ message: 'You have not registered' });
    } else {
      const {fullName, emailConfirmed} = account;
      const passwordsMatch = await bcrypt.compare(password, account.password);
      if (!passwordsMatch) {
        res.status(400).send({ message: 'Incorrect email or password' });
      } else {
        const jwtToken = jwt.sign({ email: account.email, id: account._id }, process.env.JWT_SECRET);
        res.status(200).send({ message: 'You are now logged-in', jwtToken, fullName, emailConfirmed});
      }
    }
  };

  static validateResetPassword = async (req: Request, res: Response, next: NextFunction) => {
    const schema = Joi.object().keys({
      email: Joi.string().lowercase().trim().email({ minDomainSegments: 2 }).required(),
    });
    const { email } = req.body;
    Joi.validate({ email }, schema, (err, val) => {
      if (!err) {
        req.body = val;
        next();
      } else res.status(400).send(err.details);
    });
  };

  static resetPassword = async (req: Request, res: Response) => {
    const { email } = req.body;
    const resetCode = randomBytes(20).toString('hex');
    const account = await userModel.findOneAndUpdate({email}, {$set: {
      resetPasswordCode: resetCode,
      resetSentAt: Date.now(),
    }}).exec();
    if (!account) res.status(400).send({ message: 'You need to register first' });
    else {
      const {fullName, resetPasswordCode} = account;
      const sent = await Email.confirmEmail(fullName, email, resetPasswordCode);
      if (sent) res.status(200).send({ message: 'Reset password email sent' });
    }
  };

  static validateConfirmPassword = async (req: Request, res: Response, next: NextFunction) => {
    const schema = Joi.object().keys({
      newPassword: Joi.string().trim().min(5).required(),
      resetPasswordCode: Joi.string().trim().min(39).required(),
    });
    const { newPassword, resetPasswordCode } = req.body;
    Joi.validate({ newPassword, resetPasswordCode }, schema, (err, val) => {
      if (!err) {
        req.body = val;
        next();
      } else res.status(400).send(err.details);
    });
  };

  static confirmPassword = async (req: Request, res: Response) => {
    const { newPassword, resetPasswordCode } = req.body;
    const account = await userModel.findOne({resetPasswordCode}).exec();
    if (!account) res.status(400).send({ message: 'Reset code is invalid' });
    const hours = Math.floor((Date.now() - Date.parse(account.resetSentAt)) / 3600000);
    if (hours >= 12) res.status(400).send({ message: 'Reset code is invalid' });
    else {
      const hashedPassword = await bcrypt.hash(newPassword, 10);
      const updated = await userModel.findOneAndUpdate({resetPasswordCode}, {
        $set: {password: hashedPassword},
        $unset: {resetPasswordCode: '', resetSentAt: ''},
      }).exec();
      if (updated) res.status(200).send({ message: 'Password reset' });
    }
  };

}

export {Login};
