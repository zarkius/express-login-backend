'use strict';
import { Router, Request, Response } from 'express';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { Strategy as LocalStrategy } from 'passport-local';
import passport from 'passport';
import pool from '../db/db'; // Asegúrate de que la ruta a tu archivo de configuración de la base de datos es correcta
import { PasswordBuilder, generateSalt } from '../utils/passwordutils'; // Asegúrate de que la ruta a tu archivo de utilidades es correcta
import dotenv from 'dotenv';
dotenv.config();
const router = Router();

declare module 'express-session' {
  interface Session {
    authType?: string;
    user?: any;
  }
}


// Estrategia Local
passport.use(new LocalStrategy({
  usernameField: 'display_name',
  passwordField: 'password'
}, async (display_name, password, done) => {
  try {
    const [results]: any = await pool.query('SELECT id, display_name, hashedpassword, salt FROM usuarios WHERE display_name = ?', [display_name]);
    if (results.length > 0) {
      const user = results[0];
      //console.log(user);
      const isValidPassword = PasswordBuilder.verify(password, user.hashedpassword, user.salt);
      if (isValidPassword) {
        return done(null, user);
      } else {
        return done(null, false, { message: 'Contraseña incorrecta' });
      }
    } else {
      return done(null, false, { message: 'Usuario no encontrado' });
    }
  } catch (error) {
    return done(error);
  }
}));


// Configurar estrategia Google OAuth2
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID!,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
  callbackURL: 'http://localhost:3000/api/auth/callback',
  passReqToCallback: true
},
async (req, accessToken, refreshToken, profile, done) => {
  try {
    // Verificar que el perfil tenga la propiedad id y emails
    if (!profile.id || !profile.emails || profile.emails.length === 0) {
      return done(new Error('El perfil no tiene una propiedad id o emails'));
    }

    // Buscar el usuario en la base de datos
    const [results]: any = await pool.query('SELECT * FROM users WHERE google_id = ?', [profile.id]);
    const authType = 'google';
    if (Array.isArray(results) && results.length > 0) {
      // Usuario encontrado, devolver el objeto de usuario
      return done(null, results[0], { authType });
    } else {
      // Usuario no encontrado, crear un nuevo usuario
      const [result]: any = await pool.query('INSERT INTO users (google_id, display_name, email) VALUES (?, ?, ?)', [profile.id, profile.displayName, profile.emails[0].value]);
      const insertId = (result as any).insertId;
      const [userResults]: any = await pool.query('SELECT * FROM users WHERE id = ?', [insertId]);
      return done(null, userResults[0], { authType });
    }
  } catch (error) {
    return done(error);
  }
}));

//serializar el usuario
passport.serializeUser((user: any, done) => {
  done(null, user.id);
});

//deserializar el usuario

passport.deserializeUser(async (id: any, done) => {
  try {
    const [results]: any = await pool.query('SELECT * FROM users WHERE id = ?', [id]);
    if (Array.isArray(results) && results.length > 0) {
      done(null, results[0]);
    } else {
      done(null, false);
    }
  } catch (error) {
    done(error);
  }
});

//Middleware para verificar si existe sesion
// Middleware para verificar si existe una sesión
function checkSession(req: Request, res: Response, next: any) {
  if (req.session && req.session.user) {
    return next();
  }
  res.redirect('/api/login');
}


// Middleware para verificar la autenticación
function isAuthenticated(req: Request, res: Response, next: any) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect('/api/auth');
}

// Rutas de autenticación local

router.get('/', async (req: Request, res: Response) => {
  res.render('index');
});

router.get('/login', async (req: Request, res: Response) => {
  res.render('login');
});

router.post('/login', passport.authenticate('local', {
  session: true,
  failureRedirect: '/api/login',
}), (req, res) => {
  req.session.user = req.user;
  res.redirect('/api/usuarios1');
});

router.get('/registro', async (req: Request, res: Response) => {
  res.render('registro');
});

router.post('/registro', async (req: Request, res: Response) => {
  try {
    const { display_name, email, password } = req.body;
    const salt = generateSalt();
    const hashedPassword = PasswordBuilder.hash(password, salt);
    const newUser = {
      display_name,
      email,
      hashedPassword,
      salt,
    };
    await pool.query('INSERT INTO usuarios SET ?', [newUser]);
    res.redirect('/api/usuarios1');
  } catch (error) {
    console.error('Error al registrar el usuario:', error);
    res.status(500).send('Error interno del servidor.');
  }
});

router.get('/usuarios1', checkSession, async (req: Request, res: Response) => {
  const user = req.session.user;
  console.log('Usuario autenticado:', user);
  res.render('usuarios1', { user });
});



// Rutas de autenticación con Google
router.get('/auth', passport.authenticate( 'google', { scope: ['profile', 'email', 'openid', 'https://www.googleapis.com/auth/userinfo.profile', 'https://www.googleapis.com/auth/userinfo.email'] }));

router.get('/auth/callback',
  passport.authenticate('google', { failureRedirect: '/api/auth' }),
  (req, res) => {
    req.session.authType = 'google';
    console.log('Tipo de autenticación:', req.session.authType);
    res.redirect('/api/usuarios2');
  }
);

// Ruta para el perfil de usuario2
router.get('/usuarios2', isAuthenticated, async (req: Request, res: Response) => {
  if (req.isAuthenticated()) {
    try {
      const user = req.user as { id: any; displayName: string; emails: { value: string }[] };
      console.log('Usuario autenticado:', user);
      console.log('Tipo de autenticación:', req.session.authType);
  
      const [rows] = await pool.query('SELECT * FROM users WHERE id = ?', [user.id]);
      console.log('Resultado de la consulta:', rows);
  
      if (Array.isArray(rows) && rows.length > 0) {
        const dbUser = rows[0] as { display_name: string; email: string };
        if (dbUser && dbUser.display_name && dbUser.email) {
          res.render('usuarios2', { user: dbUser, authType: req.session.authType });
        } else {
          res.status(404).send('Propiedades del usuario no encontradas en la base de datos.');
        }
      } else {
        res.status(404).send('Usuario no encontrado en la base de datos.');
      }
    } catch (error) {
      console.error('Error al obtener el perfil del usuario:', error);
      res.status(500).send('Error interno del servidor.');
    }
  }
});

// Ruta para cerrar sesión
router.get('/logout', (req: Request, res: Response) => {
  req.session.destroy((error) => {
    if (error) {
      console.error('Error al cerrar la sesión:', error);
      res.status(500).send('Error interno del servidor.');
    } else {
      res.redirect('/api');
    }
  });
});

export default router;