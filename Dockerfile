# template-python-fastapi/Dockerfile
FROM python:3.11-slim-bookworm AS builder

WORKDIR /app

# Instalar dependencias del sistema necesarias
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Copiar requirements e instalar dependencias
COPY requirements/base.txt .
RUN pip install --no-cache-dir -r base.txt

FROM python:3.11-slim-bookworm AS production

# Instalar solo curl para health check
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Crear usuario no-root
RUN addgroup --system app && adduser --system --group app

WORKDIR /app

# Copiar dependencias instaladas a un directorio accesible
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin
COPY . .

# Configurar entorno
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Configurar permisos
RUN chown -R app:app /app

USER app

# Exponer puerto (DLT-015: signing-service usa 8001, distinto de
# certificate-service/8000, para poder correr ambos en el mismo host/red)
EXPOSE 8001

# Health check robusto
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8001/api/v1/health || exit 1

# Comando de inicio
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8001"]