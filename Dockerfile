FROM debian:testing
RUN apt-get update && apt-get install -y python python-pip libscrypt0 libsodium18 python-openssl libssl-dev
RUN apt-get install -y python3.6 python3-pip libpython3.6-dev
RUN python -m pip install coverage scrypt
RUN python3.6 -m pip install coverage scrypt
WORKDIR /app
CMD ["./run_docker.sh"]
