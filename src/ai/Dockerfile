FROM python:3.12-slim
WORKDIR /app
COPY soc_agent/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY soc_agent/ soc_agent/
