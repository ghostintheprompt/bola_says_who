FROM node:22-slim

WORKDIR /lab

COPY package.json package-lock.json ./
RUN npm install --no-audit --no-fund

COPY cases/ ./cases/

CMD ["npm", "test"]
