## Setup Instructions for SQLite (Linux)

```console
docker pull ghcr.io/o2lab/crs-local:latest
docker tag ghcr.io/o2lab/crs-local:latest crs-local

# .env creation
echo "ANTHROPIC_API_KEY=..." > .env

# verify existence of docker image for crs-local
docker run -it --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  --env-file .env \
  --entrypoint /bin/bash \
  crs-local

# take image id if it exists
docker images | grep aixcc-afc/sqlite3

exit
```

Build fuzzer
```
mkdir -p fuzz-build-out/sqlite3-address

docker run --privileged --shm-size=2g --platform linux/amd64 --rm \
  -e FUZZING_ENGINE=libfuzzer \
  -e SANITIZER=address \
  -e ARCHITECTURE=x86_64 \
  -e PROJECT_NAME=sqlite3 \
  -e FUZZING_LANGUAGE=c \
  -v $(pwd)/fuzz-build-out/sqlite3-address:/out \
  aixcc-afc/sqlite3:latest \
  /bin/bash -c 'compile'
# Fails on customfuzz3.c
ls -la fuzz-build-out/sqlite3-address/ossfuzz
```

Run
```console
docker run -it --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v $(pwd)/fuzz-build-out:/crs-workdir/local-test-sqlite3-full-01/fuzz-tooling/build/out \
  --env-file .env \
  crs-local /crs-workdir/local-test-sqlite3-full-01/
```




```
export ANTHROPIC_API_KEY=...
```
```
./crs-local /crs-workdir/local-test-integration-delta-01/
```
```
./crs-local /crs-workdir/local-test-libxml2-delta-01/
```
```
./crs-local /crs-workdir/local-test-sqlite3-full-01/
```
```
./crs-local /crs-workdir/local-test-tika-delta-01/
```
```
./crs-local /crs-workdir/local-test-zookeeper-delta-01/
```

## Test LOCAL CRS:

```console
docker pull ghcr.io/o2lab/crs-local:latest
docker tag ghcr.io/o2lab/crs-local:latest crs-local

docker run -it --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  --env-file .env \
  --entrypoint /bin/bash \
  crs-local

docker run -it --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  --env-file .env \
  crs-local /crs-workdir/local-test-sqlite3-full-01/
```

docker run --privileged --shm-size=2g --platform linux/amd64 --rm -i \
  -e FUZZING_ENGINE=libfuzzer -e SANITIZER=address -e ARCHITECTURE=x86_64 \
  -e PROJECT_NAME=sqlite3 -e HELPER=True -e FUZZING_LANGUAGE=c \
  --env-file .env \
  -v /path/on/your/host/to/sqlite3/source:/tmp/source \
  -v /path/on/your/host/to/output:/out \
  -t ghcr.io/o2lab/crs-local:latest \
  /bin/bash -c 'cp -r /tmp/source /src/sqlite3 && compile'


docker run -it --rm \
  --env-file .env \
  crs-local

## Deploy LOCAL CRS:
```
cd crs
./build-local-crs-image.sh
```

## Static Analysis Service:

The CRS requires a static analysis service to be running on port 7082. Start it with:

```console
cd static-analysis
./start-server.sh
```

To stop the service:
```console
cd static-analysis
./stop-server.sh
```

Check service health:
```console
curl http://localhost:7082/v1/health
```

## CRS Development:
```
cd crs
go run ./cmd/local/main.go /crs-workdir/local-test-integration-delta-01/
```
