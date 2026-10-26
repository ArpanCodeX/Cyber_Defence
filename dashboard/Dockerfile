FROM node:22-alpine
WORKDIR /ui
COPY package.json .
RUN npm install
COPY . .
EXPOSE 5174
CMD ["npm", "run", "dev"]
