#!/bin/sh

FROM ubuntu:latest

MAINTAINER KZ1106

RUN apt-get update -y && \
    apt-get install -y python3-pip python3-dev build-essential

COPY . /app
WORKDIR /app

RUN pip3 install --upgrade pip
RUN pip3 install -r requirements.txt

COPY . /app

ENTRYPOINT [ "python3" ]

CMD [ "app.py" ]