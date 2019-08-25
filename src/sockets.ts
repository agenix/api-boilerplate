import { Socket } from 'socket.io';

const sockets = (io: Socket) => {

  io.on('connection', (socket: Socket) => {
    // tslint:disable-next-line: no-console
    console.log('a user connected');
      // whenever we receive a 'message' we log it out
    socket.on('message', (message: string) => {
      // tslint:disable-next-line: no-console
      console.log(message);
    });
  });
};

export {sockets};
