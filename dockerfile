# Χρήση image για Python
FROM python:3.9-slim

# Ορισμός του working directory
WORKDIR /app

# Αντιγραφή των απαιτήσεων
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Αντιγραφή του υπολοίπου project
COPY . .

# Εντολή για να τρέξει η εφαρμογή
CMD ["python", "app.py"]

