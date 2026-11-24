FROM node:24-bookworm-slim AS opencode
RUN npm install -g @opencode/cli

FROM python:3.12-slim-bookworm
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 OSINT_HOST=0.0.0.0 OSINT_DATA_DIR=/data
COPY --from=opencode /usr/local/bin/node /usr/local/bin/node
COPY --from=opencode /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -s "$(node -p 'const p = require("/usr/local/lib/node_modules/@opencode/cli/package.json"); "/usr/local/lib/node_modules/@opencode/cli/" + (typeof p.bin === "string" ? p.bin : p.bin.opencode)')" /usr/local/bin/opencode \
    && opencode --version
WORKDIR /app
RUN addgroup --system osint && adduser --system --ingroup osint osint \
    && mkdir /data && chown osint:osint /data
COPY app.py collectors.py public_pages.py cti.py policy.py cti_history.json ./
COPY static ./static
USER osint
EXPOSE 8080
CMD ["python", "app.py"]
