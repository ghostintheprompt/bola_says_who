FROM node:22-slim

WORKDIR /lab

COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund

COPY cases/ ./cases/
COPY tests/ ./tests/

CMD ["npm", "test"]
