FROM rocketchat/base:4

ENV RC_VERSION 0.59.0-develop

MAINTAINER buildmaster@rocket.chat

RUN set -x \
 && apt-get -y update \
 && apt-get -y install git \
 && apt-get -y install bzip2 \
 && npm install -g n \
 && n 6.10.0 \
 && npm install postcss-smart-import \
 && npm install postcss-cssnext \
 && curl https://install.meteor.com | /bin/sh \
 && mkdir ~/.ssh \
 && ssh-keyscan github.com >> ~/.ssh/known_hosts \
 && git clone -b streamr https://github.com/streamr-dev/Rocket.Chat.git /Rocket.Chat \
 && mkdir /app \
 && chown rocketchat:rocketchat /app \
 && chown -R rocketchat:rocketchat /Rocket.Chat \
 && mkdir /home/rocketchat \
 && chown -R rocketchat:rocketchat /home/rocketchat \
 && cd /Rocket.Chat \
 && su rocketchat -c "meteor npm i" \
 && su rocketchat -c "meteor build --server-only /app" \
 && tar -zxf /app/Rocket.Chat.tar.gz -C /app \
 && rm /app/Rocket.Chat.tar.gz \
 && cd /app/bundle/programs/server \
 && npm install \
 && npm cache clear \
 && chown -R rocketchat:rocketchat /app

USER rocketchat

VOLUME /app/uploads

WORKDIR /app/bundle

# needs a mongoinstance - defaults to container linking with alias 'mongo'
ENV DEPLOY_METHOD=docker \
    NODE_ENV=production \
    MONGO_URL=mongodb://mongo:27017/rocketchat \
    HOME=/tmp \
    PORT=3000 \
    ROOT_URL=http://localhost:3000 \
    Accounts_AvatarStorePath=/app/uploads

EXPOSE 3000

CMD ["node", "main.js"]
