"use strict";
// Archivo: src/utils/passwordUtils.ts
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.verify = exports.PasswordBuilder = exports.generateSalt = void 0;
const crypto_1 = __importDefault(require("crypto"));
const password_builder_1 = require("password-builder");
Object.defineProperty(exports, "verify", { enumerable: true, get: function () { return password_builder_1.verify; } });
const generateSalt = () => {
    return crypto_1.default.randomBytes(16).toString('hex');
};
exports.generateSalt = generateSalt;
exports.PasswordBuilder = {
    hash: (password, salt) => {
        const localHash = crypto_1.default.createHmac('sha256', salt)
            .update(password)
            .digest('hex');
        return localHash;
    },
    verify: (password, hashedPassword, salt) => {
        const hash = exports.PasswordBuilder.hash(password, salt);
        return hash === hashedPassword;
    }
};
