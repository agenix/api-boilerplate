import * as mongoose from 'mongoose';
import { Document, Schema } from 'mongoose';

export interface Iuser extends Document {
  email: string;
  password: string;
}

const userSchema: Schema = new Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

const userModel = mongoose.model<Iuser>('User', userSchema);

export {userModel};
