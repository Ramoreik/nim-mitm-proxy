FROM ubuntu

RUN apt update
RUN apt install -y build-essential libssl-dev curl
RUN echo -ne "Y\n"|curl https://nim-lang.org/choosenim/init.sh -sSf | sh

COPY src /app
WORKDIR /app

CMD ["proxy"]

