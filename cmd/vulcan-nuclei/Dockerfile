FROM golang:1.14-alpine as base
WORKDIR /
RUN GO111MODULE=on go get -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei
RUN /go/bin/nuclei -update-templates

FROM golang:1.14-alpine as builder
WORKDIR /
COPY go.mod /
COPY go.sum /
RUN go mod download
COPY main.go .
RUN GOOS=linux CGO_ENABLED=0 go build -a -ldflags '-extldflags "-static"' main.go

FROM alpine
WORKDIR /
COPY --from=base /root/.nuclei-config.json /root/
COPY --from=base /root/nuclei-templates /root/nuclei-templates
COPY --from=base /go/bin/nuclei /
COPY --from=builder main /
COPY entrypoint.sh /
CMD ["/entrypoint.sh"]
