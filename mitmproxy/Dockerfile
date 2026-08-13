FROM mitmproxy/mitmproxy:latest

RUN pip install --no-cache-dir requests

COPY ingest_addon.py /addons/ingest_addon.py

EXPOSE 8080
CMD ["mitmdump", "-s", "/addons/ingest_addon.py", "-p", "8080"]
