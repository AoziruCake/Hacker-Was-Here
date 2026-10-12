FROM golang:1.27.2-bookworm@sha256:5cf287a799e6b94384bad13d16b14904c531f51ba65792237e122ce42b392f61
ENV GOTOOLCHAIN=local CGO_ENABLED=0
RUN apt-get update && apt-get install -y --no-install-recommends strace python3 util-linux && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY LICENSE ./
COPY internal ./internal
COPY cmd ./cmd
COPY tools/safefs-probe ./tools/safefs-probe
COPY tests ./tests
RUN go test -c ./internal/safefs -o /opt/safefs.test && go build -trimpath -o /opt/safefs-probe ./tools/safefs-probe
RUN go build -trimpath -o /opt/hwh ./cmd/hwh
ENTRYPOINT ["/bin/sh", "/src/tests/safefs/run.sh"]

