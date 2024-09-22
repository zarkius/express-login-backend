"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const passport_1 = __importDefault(require("passport"));
const passport_google_oauth20_1 = require("passport-google-oauth20");
// Middleware para verificar la autenticación
function isAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect('/api/auth');
}
passport_1.default.use(new passport_google_oauth20_1.Strategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: 'http://localhost:3000/api/auth/callback',
    passReqToCallback: true
}, (req, accessToken, refreshToken, profile, done) => {
    var _a, _b;
    const emails = (_b = (_a = profile.emails) === null || _a === void 0 ? void 0 : _a.map((email) => email.value)) !== null && _b !== void 0 ? _b : [];
    const userProfile = {
        id: profile.id,
        displayName: profile.displayName,
        emails: emails
    };
    return done(null, userProfile);
}));
passport_1.default.serializeUser((user, done) => {
    done(null, user);
});
passport_1.default.deserializeUser((obj, done) => {
    done(null, obj);
});
exports.default = passport_1.default;
