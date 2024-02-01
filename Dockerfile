# Use the official Python image as the base image
FROM python:3

# Set the working directory in the container
WORKDIR /app

# Copy the local requirements.txt file to the container at /app
COPY requirements.txt /app/
RUN apt-get update && apt-get install ffmpeg libsm6 libxext6  -y

# Install the dependencies from requirements.txt
RUN pip3 install -r requirements.txt

# Copy the local code to the container at /app
COPY . /app/

# Install the Python package (assuming it contains a setup.py file)
RUN pip3 install .

# Run hawk_Scanner from python3 main.py
ENTRYPOINT ["hawk_scanner"]