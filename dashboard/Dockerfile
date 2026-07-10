# Stage 1 — build
FROM node:20-alpine AS build
WORKDIR /app

COPY package.json ./

# Force-install ajv@8 first to fix react-scripts peer dep conflict on Node 20
RUN npm install --legacy-peer-deps && \
    npm install ajv@^8.12.0 ajv-keywords@^5.1.0 --legacy-peer-deps

COPY . .
ENV REACT_APP_API_URL=http://localhost:8000
ENV REACT_APP_CVE_INTEL_URL=http://localhost:8001
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
}\n' > /etc/nginx/conf.d/default.conf

EXPOSE 3000
