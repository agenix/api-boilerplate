FROM node:10-alpine
RUN mkdir -p /home/node/app/node_modules && chown -R node:node /home/node/app
WORKDIR /home/node/app
COPY package*.json ./
USER node
RUN yarn
COPY --chown=node:node . .
EXPOSE 9000
CMD [ "node", "start" ]