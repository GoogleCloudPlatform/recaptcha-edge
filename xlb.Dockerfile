FROM node:22

WORKDIR /app

COPY . .

RUN npm install
RUN npm run build

WORKDIR /app/bindings/xlb

RUN npm install
RUN npm run protogen

CMD ["npx", "tsx", "src/server.ts"]