FROM python:3.12-alpine
RUN pip install --no-cache-dir flask==3.0.3
WORKDIR /site
COPY app.py .
EXPOSE 8081
CMD ["python", "app.py"]
