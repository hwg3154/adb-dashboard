# design.md §9: python:3.12-slim, multi-arch, Debian adb, non-root, read-only rootfs.
FROM python:3.12-slim

# `adb` is the Debian package name on bookworm; --no-install-recommends keeps the
# Android SDK's other tools out of the image.
RUN apt-get update \
 && apt-get install -y --no-install-recommends adb \
 && rm -rf /var/lib/apt/lists/*

RUN useradd --system --uid 10001 --create-home --home-dir /home/tvd tvd

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY tvdashboard/ ./tvdashboard/

# adb writes its RSA key to $HOME/.android/adbkey on first use. With a read-only rootfs it
# cannot create one at all, and without a volume a restart generates a new key - which makes
# the TV show its "Allow wireless debugging" dialog again, and only someone standing at the
# TV can accept it (design.md §10). Both paths below must be writable and must persist.
ENV HOME=/home/tvd \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    TVD_DATA_DIR=/data

RUN mkdir -p /data /home/tvd/.android \
 && chown -R tvd:tvd /data /home/tvd \
 && chmod 700 /data /home/tvd/.android

USER tvd
VOLUME ["/data", "/home/tvd/.android"]
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2).status==200 else 1)"

ENTRYPOINT ["python", "-m", "tvdashboard"]
