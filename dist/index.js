'use strict';
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const body_parser_1 = __importDefault(require("body-parser"));
const express_session_1 = __importDefault(require("express-session"));
const passport_1 = __importDefault(require("passport"));
const path_1 = __importDefault(require("path"));
const rutas_1 = __importDefault(require("./rutas/rutas"));
const app = (0, express_1.default)();
const PORT = 3000;
// Configurar el motor de plantillas EJS
app.set('view engine', 'ejs');
// Configurar el directorio de vistas
app.set('views', path_1.default.join(__dirname, 'vistas'));
app.use(body_parser_1.default.json());
app.use(body_parser_1.default.urlencoded({ extended: true }));
// Middleware para capturar y registrar las solicitudes
app.use((req, res, next) => {
    console.log(`${req.method} ${req.url}`);
    next();
});
app.locals.GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
app.use((0, express_session_1.default)({
    secret: '1234',
    resave: false,
    saveUninitialized: false
}));
app.use(passport_1.default.initialize());
app.use(passport_1.default.session());
// Usar el enrutador para las rutas definidas en './rutas/rutas'
app.use('/api', rutas_1.default);
app.use('/registro', rutas_1.default);
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
