# 1. Naudojame oficialų Python atvaizdą
FROM python:3.11-slim

# 2. Aplinkos kintamieji: neleidžiame .pyc failų ir užtikriname tiesioginį logų išvedimą
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# 3. Įdiegiame sistemines bibliotekas (MySQL, Nmap ir įrankiai jų kompiliavimui)
# Viską darome viename RUN sluoksnyje, kad konteineris būtų lengvesnis
RUN apt-get update && apt-get install -y \
    gcc \
    default-libmysqlclient-dev \
    pkg-config \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# 4. Nustatome darbinį katalogą
WORKDIR /app

# 5. Nukopijuojame tik requirements.txt ir juos įdiegiame (tai pagreitina build'inimą)
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# 6. Nukopijuojame visą backend kodą
COPY . /app/

# 7. Paleidžiame Django serverį
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
