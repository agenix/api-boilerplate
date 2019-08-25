import * as bluebird from 'bluebird';
import * as bodyParser from 'body-parser';
import * as cors from 'cors';
import * as dotenv from 'dotenv';
import * as express from 'express';
import * as helmet from 'helmet';
import * as mongoose from 'mongoose';
import * as morgan from 'morgan';
import * as path from 'path';
import { RateLimiterMongo } from 'rate-limiter-flexible';
import { router } from './router';
import './sockets';

// Set env values
dotenv.config();

// Connect to MongoDB
(<any> mongoose).Promise = bluebird;
mongoose.connect(`mongodb+srv://${process.env.DB_USERNAME}:${process.env.DB_PASSWORD}@${process.env.DB_HOST}/${process.env.DB_NAME}?retryWrites=true`,
{useCreateIndex: true, useNewUrlParser: true});
mongoose.connection.on('error', () => {
  throw new Error(`unable to connect to database: ${process.env.DB_NAME}`);
});

// Configure Rate Limiter
const rateLimiterMongo = new RateLimiterMongo({storeClient: mongoose.connection, points: 4, duration: 1});
const rateLimiter = (req: express.Request, res: express.Response, next: express.NextFunction) => {
  rateLimiterMongo.consume(req.ip)
    .then(() => next())
    .catch(() => res.status(429).send('Whoa! Slow down there little buddy'));
};

// Configure CORS
const corsOptions = {
  origin: (origin: any, callback: any) => {
    if (process.env.CORS_WHITELIST && process.env.CORS_WHITELIST.indexOf(origin) !== -1) callback(null, true);
    else callback('Not allowed by CORS');
  },
  allowedHeaders: ['Accept', 'Authorization', 'Content-Length', 'Content-Type', 'X-Requested-With'],
  methods: ['DELETE', 'GET', 'OPTIONS', 'POST', 'PUT'], optionsSuccessStatus: 200,
};

// Configure App
const app = express();
app.use(helmet());
app.use(morgan('dev'));
app.use(cors(corsOptions));
app.use(rateLimiter);
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Catch Syntax Error in JSON
app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
  if (err.status === 400 && err instanceof SyntaxError && 'body' in err) {
    res.status(200).send({ message: 'JSON Syntax Error' });
  } else {
    next();
  }
});
app.use('/', router);

const http = require('http').Server(app);
require('socket.io')(http);

// Start Server
const port = process.env.API_PORT;
http.listen(port, () => {
  // tslint:disable-next-line: no-console
  console.log(`listening on ${port}`);
});

// Serve Socket test page
app.get('/socket', (req: express.Request, res: express.Response) => {
    res.sendFile(path.resolve('./src/client/index.html'));
  });

export {app};
