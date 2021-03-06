import * as bodyParser from 'body-parser';
import * as cors from 'cors';
import * as dotenv from 'dotenv';
import * as express from 'express';
import * as helmet from 'helmet';
import * as http from 'http';
import * as mongoose from 'mongoose';
import * as morgan from 'morgan';
import * as path from 'path';
import * as socketIo from 'socket.io';
import { router } from './router';

// Set env values
dotenv.config();
// Connect to MongoDB
mongoose.connect(`mongodb+srv://${process.env.DB_USERNAME}:${process.env.DB_PASSWORD}@${process.env.DB_HOST}/${process.env.DB_NAME}?retryWrites=true`,
{useCreateIndex: true, useNewUrlParser: true, useFindAndModify: false, useUnifiedTopology: true});
mongoose.connection.on('error', () => {
  throw new Error(`unable to connect to database: ${process.env.DB_NAME}`);
});

// Configure CORS
const options: cors.CorsOptions = {
  allowedHeaders: ['Origin', 'X-Requested-With', 'Content-Type', 'Accept', 'X-Access-Token'],
  credentials: true,
  methods: 'GET, HEAD, OPTIONS, PUT, PATCH, POST, DELETE',
  origin: (origin, callback) => callback(null, process.env.CORS_WHITELIST.indexOf(origin) !== -1),
  preflightContinue: false,
};

// Configure Server
const app = express();
const server = new http.Server(app);
const io = socketIo(server);

// Configure App
app.use(helmet());
app.use(morgan('dev'));
app.use(cors(options));
app.options('*', cors(options));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Catch Syntax Error in JSON
interface Error {
  status?: number;
}
app.use((err: Error, req: express.Request, res: express.Response, next: express.NextFunction) => {
  if (err.status === 400 && err instanceof SyntaxError && 'body' in err) {
    res.status(200).send({ message: 'JSON Syntax Error' });
  } else {
    next();
  }
});
app.use('/', router);

io.on('connection', (socket) => {
  // tslint:disable-next-line: no-console
  console.log('Socket Connected');
});

// Start Server
const port = process.env.API_PORT;
server.listen(port, () => {
  // tslint:disable-next-line: no-console
  console.log(`listening on ${port}`);
});

// Serve Socket test page
app.get('/socket', (req: express.Request, res: express.Response) => {
  res.sendFile(path.resolve('./src/client/index.html'));
});

export {app};
