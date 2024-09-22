'use strict';
import express from 'express';
import bodyParser from 'body-parser';
import session from 'express-session';
import passport from 'passport';
import path from 'path';
import router from './rutas/rutas';
import morgan from 'morgan';

const app = express();
const PORT = 3000;

app.use(morgan('combined'));

// Configurar el motor de plantillas EJS
app.set('view engine', 'ejs');
// Configurar el directorio de vistas
app.set('views', path.join(__dirname, 'vistas'));

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Middleware para capturar y registrar las solicitudes
app.use((req, res, next) => {
  console.log(`${req.method} ${req.url}`);
  next();
});

app.use(session({
  secret: '1234',
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());


// Usar el enrutador para las rutas definidas en './rutas/rutas'
app.use('/api', router);
app.use('/registro', router);


app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});