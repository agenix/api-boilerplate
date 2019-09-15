import * as Joi from '@hapi/joi';
import * as bcrypt from 'bcrypt';
import {randomBytes} from 'crypto';
import { NextFunction, Request, Response } from 'express';
import * as jwt from 'jsonwebtoken';
import { Email } from '../components/email';
import { userModel, UserModelInterface } from '../models/user';

class User {

  static validateLogin = async (req: Request, res: Response, next: NextFunction) => {
    const schema = Joi.object().keys({
      email: Joi.string().lowercase().trim().email({ minDomainSegments: 2 }),
      password: Joi.string().min(5),
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

  static validateRegister = async (req: Request, res: Response, next: NextFunction) => {
    const schema = Joi.object().keys({
      email: Joi.string().lowercase().trim().email({ minDomainSegments: 2 }),
      fullName: Joi.string().trim().max(30),
      password: Joi.string().trim().min(5),
    });
    const { email, password, fullName } = req.body;
    Joi.validate({ email, password, fullName }, schema, (err, val) => {
      if (!err) {
        req.body = val;
        next();
      } else res.status(400).send(err.details);
    });
  };

  static register = async (req: Request, res: Response) => {
    const { email, password, fullName } = req.body;
    const confirmationCode = randomBytes(20).toString('hex');
    const alreadyRegistered = await userModel.findOne({email}).exec();
    if (!alreadyRegistered) {
      const hashedPassword = await bcrypt.hash(password, 10);
      if (!hashedPassword) {
        res.status(500).send({ message: 'Failed to encrypt your password' });
      } else {
        const user = new userModel({email, password: hashedPassword, fullName, confirmationCode} as UserModelInterface);
        const saved = await user.save();
        if (!saved) {
          res.status(500).send({ message: 'Failed to register you' });
        } else {
          const jwtToken = jwt.sign({ email: saved.email, id: saved._id }, process.env.JWT_SECRET);
          // const sent = await Email.confirmEmail(fullName, email, confirmationCode);
          const sent = true;
          if (!sent) {
            res.status(500).send({ message: 'Failed to send email', jwtToken });
          } else  {
            res.status(200).send({ message: 'You are now registered', jwtToken });
          }
        }
      }
    } else {
      res.status(400).send({ message: 'You have already registered' });
    }
  };

  static validateConfirmEmail = async (req: Request, res: Response, next: NextFunction) => {
    const schema = Joi.object().keys({
      confirmationCode: Joi.string().trim().min(40).required(),
    });
    const { confirmationCode } = req.body;
    Joi.validate({ confirmationCode }, schema, (err, val) => {
      if (!err) {
        req.body = val;
        next();
      } else res.status(400).send(err.details);
    });
  };

  static confirmEmail = async (req: Request, res: Response) => {
    const { confirmationCode } = req.body;
    const alreadyConfirmed = await userModel.findOne({confirmationCode}).exec();
    if (!alreadyConfirmed) {
      res.status(400).send({ message: 'Invalid confirmation code' });
    } else if (alreadyConfirmed && alreadyConfirmed.emailConfirmed) {
      res.status(200).send({ message: 'You already confirmed your email' });
    } else if (alreadyConfirmed && !alreadyConfirmed.emailConfirmed) {
      const confirmed = await userModel.findOneAndUpdate({confirmationCode}, {$set: {emailConfirmed: true}}).exec();
      if (confirmed) {
        res.status(200).send({ message: 'Email confirmed' });
      }
    }
  };

  static validateResendEmail = async (req: Request, res: Response, next: NextFunction) => {
    const schema = Joi.object().keys({
      jwtToken: Joi.string().trim().required(),
    });
    const { jwtToken } = req.body;
    Joi.validate({ jwtToken }, schema, (err, val) => {
      if (!err) {
        req.body = val;
        next();
      } else res.status(400).send(err.details);
    });
  };

  static resendEmail = async (req: Request, res: Response) => {
    interface JwtInterface { email: string; id: string; }
    const jwtData = jwt.verify(req.body.jwtToken, process.env.JWT_SECRET);
    const isJWTData = (input: object | string): input is JwtInterface => {
       return typeof input === 'object' && 'id' in input;
    };
    if (isJWTData(jwtData)) {
      const _id = jwtData.id;
      const account = await userModel.findOne({_id}).exec();
      const { fullName, email, confirmationCode } = account;
      const sent = await Email.confirmEmail(fullName, email, confirmationCode);
      if (sent) {
        res.status(200).send({ message: 'Email resent' });
      }
    }
  };


  static validateReset = async (req: Request, res: Response, next: NextFunction) => {
    const schema = Joi.object().keys({
      email: Joi.string().lowercase().trim().email({ minDomainSegments: 2 }),
    });
    const { email } = req.body;
    Joi.validate({ email }, schema, (err, val) => {
      if (!err) {
        req.body = val;
        next();
      } else res.status(400).send(err.details);
    });
  };
  static reset = async (req: Request, res: Response) => {
    res.status(200).send({ message: 'You already confirmed your email' });
  };

}

export {User};
