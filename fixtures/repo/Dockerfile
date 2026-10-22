# syntax=docker/dockerfile:1
FROM registry-bad.test:5443/base/node:20 AS build
RUN echo build
FROM --platform=linux/amd64 registry-good.test:5444/runtime/distroless:1
COPY --from=build /app /app
FROM alpine:3.20
