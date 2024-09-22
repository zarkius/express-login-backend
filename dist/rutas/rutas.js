"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const passport_google_oauth20_1 = require("passport-google-oauth20");
const passport_local_1 = require("passport-local");
const passport_1 = __importDefault(require("passport"));
const db_1 = __importDefault(require("../db/db")); // Asegúrate de que la ruta a tu archivo de configuración de la base de datos es correcta
const passwordutils_1 = require("../utils/passwordutils"); // Asegúrate de que la ruta a tu archivo de utilidades es correcta
const router = (0, express_1.Router)();
// Estrategia Local
passport_1.default.use(new passport_local_1.Strategy({
    usernameField: 'display_name',
    passwordField: 'password'
}, (display_name, password, done) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const [results] = yield db_1.default.query('SELECT id, display_name, hashedpassword, salt FROM usuarios WHERE display_name = ?', [display_name]);
        if (results.length > 0) {
            const user = results[0];
            //console.log(user);
            const isValidPassword = passwordutils_1.PasswordBuilder.verify(password, user.hashedpassword, user.salt);
            if (isValidPassword) {
                return done(null, user);
            }
            else {
                return done(null, false, { message: 'Contraseña incorrecta' });
            }
        }
        else {
            return done(null, false, { message: 'Usuario no encontrado' });
        }
    }
    catch (error) {
        return done(error);
    }
})));
// Configurar estrategia Google OAuth2
passport_1.default.use(new passport_google_oauth20_1.Strategy({
    clientID: '396336709726-06rprvjnq8f8ru35tvgps5qc2jc4nuta.apps.googleusercontent.com',
    clientSecret: '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',
    callbackURL: 'http://localhost:3000/api/auth/callback',
    passReqToCallback: true
}, (req, accessToken, refreshToken, profile, done) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        // Verificar que el perfil tenga la propiedad id y emails
        if (!profile.id || !profile.emails || profile.emails.length === 0) {
            return done(new Error('El perfil no tiene una propiedad id o emails'));
        }
        // Buscar el usuario en la base de datos
        const [results] = yield db_1.default.query('SELECT * FROM users WHERE google_id = ?', [profile.id]);
        const authType = 'google';
        if (Array.isArray(results) && results.length > 0) {
            // Usuario encontrado, devolver el objeto de usuario
            return done(null, results[0], { authType });
        }
        else {
            // Usuario no encontrado, crear un nuevo usuario
            const [result] = yield db_1.default.query('INSERT INTO users (google_id, display_name, email) VALUES (?, ?, ?)', [profile.id, profile.displayName, profile.emails[0].value]);
            const insertId = result.insertId;
            const [userResults] = yield db_1.default.query('SELECT * FROM users WHERE id = ?', [insertId]);
            return done(null, userResults[0], { authType });
        }
    }
    catch (error) {
        return done(error);
    }
})));
//serializar el usuario
passport_1.default.serializeUser((user, done) => {
    done(null, user.id);
});
//deserializar el usuario
passport_1.default.deserializeUser((id, done) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const [results] = yield db_1.default.query('SELECT * FROM users WHERE id = ?', [id]);
        if (Array.isArray(results) && results.length > 0) {
            done(null, results[0]);
        }
        else {
            done(null, false);
        }
    }
    catch (error) {
        done(error);
    }
}));
//Middleware para verificar si existe sesion
// Middleware para verificar si existe una sesión
function checkSession(req, res, next) {
    if (req.session && req.session.user) {
        return next();
    }
    res.redirect('/api/login');
}
// Middleware para verificar la autenticación
function isAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect('/api/auth');
}
// Rutas de autenticación local
router.get('/', (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    res.render('index');
}));
router.get('/login', (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    res.render('login');
}));
router.post('/login', passport_1.default.authenticate('local', {
    session: true,
    failureRedirect: '/api/login',
}), (req, res) => {
    req.session.user = req.user;
    res.redirect('/api/usuarios1');
});
router.get('/registro', (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    res.render('registro');
}));
router.post('/registro', (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { display_name, email, password } = req.body;
        const salt = (0, passwordutils_1.generateSalt)();
        const hashedPassword = passwordutils_1.PasswordBuilder.hash(password, salt);
        const newUser = {
            display_name,
            email,
            hashedPassword,
            salt,
        };
        yield db_1.default.query('INSERT INTO usuarios SET ?', [newUser]);
        res.redirect('/api/usuarios1');
    }
    catch (error) {
        console.error('Error al registrar el usuario:', error);
        res.status(500).send('Error interno del servidor.');
    }
}));
router.get('/usuarios1', checkSession, (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const user = req.session.user;
    console.log('Usuario autenticado:', user);
    res.render('usuarios1', { user });
}));
// Rutas de autenticación con Google
router.get('/auth', passport_1.default.authenticate('google', { scope: ['profile', 'email', 'openid', 'https://www.googleapis.com/auth/userinfo.profile', 'https://www.googleapis.com/auth/userinfo.email'] }));
router.get('/auth/callback', passport_1.default.authenticate('google', { failureRedirect: '/api/auth' }), (req, res) => {
    req.session.authType = 'google';
    console.log('Tipo de autenticación:', req.session.authType);
    res.redirect('/api/usuarios2');
});
// Ruta para el perfil de usuario2
router.get('/usuarios2', isAuthenticated, (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    if (req.isAuthenticated()) {
        try {
            const user = req.user;
            console.log('Usuario autenticado:', user);
            console.log('Tipo de autenticación:', req.session.authType);
            const [rows] = yield db_1.default.query('SELECT * FROM users WHERE id = ?', [user.id]);
            console.log('Resultado de la consulta:', rows);
            if (Array.isArray(rows) && rows.length > 0) {
                const dbUser = rows[0];
                if (dbUser && dbUser.display_name && dbUser.email) {
                    res.render('usuarios2', { user: dbUser, authType: req.session.authType });
                }
                else {
                    res.status(404).send('Propiedades del usuario no encontradas en la base de datos.');
                }
            }
            else {
                res.status(404).send('Usuario no encontrado en la base de datos.');
            }
        }
        catch (error) {
            console.error('Error al obtener el perfil del usuario:', error);
            res.status(500).send('Error interno del servidor.');
        }
    }
}));
// Ruta para cerrar sesión
router.get('/logout', (req, res) => {
    req.session.destroy((error) => {
        if (error) {
            console.error('Error al cerrar la sesión:', error);
            res.status(500).send('Error interno del servidor.');
        }
        else {
            res.redirect('/api');
        }
    });
});
exports.default = router;
