FROM prabhushan/sbom-base:1.0.2

RUN apk add --no-cache nodejs npm jq

WORKDIR /app

COPY entrypoint.sh /entrypoint.sh
COPY secret-scanner.js /app/secret-scanner.js
COPY package.json package-lock.json /app/

RUN npm install

RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]

