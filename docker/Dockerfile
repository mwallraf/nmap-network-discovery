FROM kalilinux/kali-rolling

RUN apt-get update && apt-get upgrade -y && apt-get -y install nmap masscan python3-xmltodict

COPY snmp-sysdetails.nse /usr/share/nmap/scripts/

ARG GROUPID=20001

ENV OUTPUTFOLDER=/app/output 

RUN addgroup --gid $GROUPID app && usermod --append --groups app root

RUN mkdir -p /app && chown -R root:app /app && chmod -R 775 /app

RUN mkdir -p /app/output

WORKDIR /app

ENTRYPOINT [ "nmap" ]