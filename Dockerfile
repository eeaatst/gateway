# Python'un standart slim imajını temel alıyoruz
FROM quay.io/fedora/python-311
# Gerekli kütüphaneleri kuruyoruz
RUN pip install mitmproxy requests



WORKDIR /app