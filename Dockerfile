FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY pyproject.toml /app/
COPY src/ /app/src/
RUN pip install --no-cache-dir .
RUN useradd --create-home --uid 10001 labuser && mkdir -p /app/instance && chown labuser /app/instance
USER labuser
EXPOSE 5000
CMD ["tradelink-enterprise", "--db", "/app/instance/tradelink.sqlite3", "serve", "--port", "5000", "--host", "0.0.0.0"]
