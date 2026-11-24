FROM python:3.12-slim-bookworm
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 OSINT_HOST=0.0.0.0 OSINT_DATA_DIR=/data
WORKDIR /app
RUN addgroup --system osint && adduser --system --ingroup osint osint \
    && mkdir /data && chown osint:osint /data
COPY app.py collectors.py public_pages.py cti.py policy.py egress.py noise.py entities.py cti_history.json reliability.json noise.json ./
COPY static ./static
USER osint
EXPOSE 8080
CMD ["python", "app.py"]
