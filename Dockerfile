# Start with an official Python image
FROM python:3.12.3-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Create and set working directory in the container
WORKDIR /usr/src/app

# Copy and install dependencies
COPY ./src /usr/src/app/src
COPY ./requirements.txt /usr/src/app/

RUN pip install --no-cache-dir -r requirements.txt

# Copy environment variables and keycloak config
COPY .env /usr/src/app/
COPY keycloak_config.json /usr/src/app/

# Expose the desired port
EXPOSE 5000

WORKDIR /usr/src/app/

# Start the Flask server by default
CMD ["python", "-m", "src.rest.server"]