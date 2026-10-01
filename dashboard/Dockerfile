# Stage 1 — build
FROM node:20-alpine AS build
WORKDIR /app

COPY package.json package-lock.json ./

RUN npm ci --legacy-peer-deps

COPY . .
ARG PUBLIC_URL=/dashboard
ENV PUBLIC_URL=${PUBLIC_URL}
ENV GENERATE_SOURCEMAP=false
RUN npm run build

# Stage 2 — serve with nginx
FROM nginx:alpine
COPY --from=build /app/build /usr/share/nginx/html

RUN printf 'server {\n\
  listen 3000;\n\
  root /usr/share/nginx/html;\n\
  index index.html;\n\
  resolver 127.0.0.11 valid=10s ipv6=off;\n\
  location / { try_files $uri $uri/ /index.html; }\n\
  location /api { set $api_backend orchestrator:8000; proxy_pass http://$api_backend$request_uri; }\n\
  location /health { set $api_backend orchestrator:8000; proxy_pass http://$api_backend$request_uri; }\n\
  location /cve-intel/ { set $cve_backend cve-intel:8001; rewrite ^/cve-intel/(.*)$ /$1 break; proxy_pass http://$cve_backend$uri$is_args$args; }\n\
}\n' > /etc/nginx/conf.d/default.conf

EXPOSE 3000
