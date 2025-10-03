# Use an official lightweight Python image as a parent image
FROM python:3.11-slim

# Set the working directory inside the container
WORKDIR /app

# Copy the requirements file into the container
COPY requirements.txt .

# Install the Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy all your backend source code into the container
COPY . .

# Inform Docker that the container listens on port 8000
EXPOSE 8000

# This is the default command to run when the container starts.
# You will override this in your Render settings for each specific service.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]