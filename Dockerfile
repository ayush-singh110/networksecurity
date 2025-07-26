
FROM continuumio/miniconda3:latest

WORKDIR /app

ENV PORT=8080
ENV PYTHONUNBUFFERED=1


RUN conda install -y -c conda-forge \
    pandas \
    numpy \
    scikit-learn \
    requests \
    beautifulsoup4 \
    && conda clean -afy


RUN pip install --no-cache-dir \
    python-dotenv \
    pymongo \
    certifi \
    "pymongo[srv]==3.6" \
    dill \
    pyaml \
    mlflow \
    dagshub \
    fastapi \
    uvicorn \
    python-whois \
    tldextract


COPY . .

RUN mkdir -p logs


RUN groupadd -r appuser && useradd -r -g appuser appuser
RUN chown -R appuser:appuser /app
USER appuser

HEALTHCHECK --interval=30s --timeout=10s --start-period=40s \
  CMD curl -f http://localhost:$PORT/health || curl -f http://localhost:$PORT/docs || exit 1

EXPOSE $PORT


CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]