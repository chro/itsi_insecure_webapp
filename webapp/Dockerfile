FROM python:3.12-alpine
RUN pip install --no-cache-dir flask 'pyjwt[crypto]'
WORKDIR /app
COPY keygen.py .
RUN python keygen.py
COPY app.py .
COPY templates/ templates/
EXPOSE 5001
CMD ["python", "app.py"]
