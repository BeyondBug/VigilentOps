# Stage 1 — build
FROM node:20-alpine AS build
WORKDIR /app

COPY package.json package-lock.json ./

RUN npm ci --legacy-peer-deps

COPY . .
ENV GENERATE_SOURCEMAP=false
RUN npm run build

# Stage 2 — serve with nginx
FROM nginx:alpine
COPY --from=build /app/build /usr/share/nginx/html

RUN printf 'server {\n\
  listen 3000;\n\
  root /usr/share/nginx/html;\n\
  index index.html;\n\
  location / { try_files $uri $uri/ /index.html; }\n\
  location /api { proxy_pass http://orchestrator:8000; }\n\
  location /health { proxy_pass http://orchestrator:8000; }\n\
  location /cve-intel/ { proxy_pass http://cve-intel:8001/; }\n\
}\n' > /etc/nginx/conf.d/default.conf

EXPOSE 3000
