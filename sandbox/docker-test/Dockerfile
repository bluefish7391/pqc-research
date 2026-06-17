FROM python:3.11-alpine
WORKDIR /app
COPY quick_test.py .

# ENTRYPOINT is the fixed base command
ENTRYPOINT ["python", "quick_test.py"]

# CMD acts as the default parameters if you don't provide any
CMD ["1", "1", "https://www.google.com"]