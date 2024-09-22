// Archivo: src/utils/passwordUtils.ts

import crypto from 'crypto';
import { hash as externalHash, verify } from 'password-builder';

export const generateSalt = (): string => {
  return crypto.randomBytes(16).toString('hex');
};

export const PasswordBuilder = {
  hash: (password: string, salt: string): string => {
    const localHash = crypto.createHmac('sha256', salt)
                            .update(password)
                            .digest('hex');
    return localHash;
  },

  verify: (password: string, hashedPassword: string, salt: string): boolean => {
    const hash = PasswordBuilder.hash(password, salt);
    return hash === hashedPassword;
  }
};

export { verify };
