import * as mongoose from 'mongoose';
import { Document, Schema } from 'mongoose';

interface UserModelInterface extends Document {
  email: string;
  fullName: string;
  password: string;
  confirmationCode: string;
  emailConfirmed: boolean;
}

const userSchema: Schema = new Schema({
  confirmationCode: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  emailConfirmed: { type: Boolean, default: false },
  fullName: { type: String, required: true },
  password: { type: String, required: true },
});

const userModel = mongoose.model<UserModelInterface>('User', userSchema);

export {userModel, UserModelInterface};
