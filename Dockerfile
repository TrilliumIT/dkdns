FROM alpine

ADD https://trilliumstaffing.com/gh-latest/repo/TrilliumIT/dkdns/dkdns /
RUN chmod +x dkdns

EXPOSE 53

ENTRYPOINT ["/dkdns"]
