# Naudojame oficialų Node.js atvaizdą
FROM node:20-alpine

# Nustatome darbinį aplanką konteinerio viduje
WORKDIR /app

# Nukopijuojame priklausomybių failus
COPY package.json package-lock.json ./

# Įdiegiame priklausomybes
RUN npm install

# Nukopijuojame visą likusį kodą
COPY . .

# Atidarome prievadą React serveriui
EXPOSE 3000

# Paleidžiame React vystymo serverį
CMD ["npm", "start"]
