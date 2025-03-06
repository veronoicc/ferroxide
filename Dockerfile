# syntax=docker/dockerfile:1

# Builder stage
FROM golang:1.20-alpine AS builder
WORKDIR /app
COPY . .
RUN GOARCH=$(echo $TARGETPLATFORM | cut -d'/' -f2) go build -o ferroxide ./cmd/ferroxide

# Final stage
FROM scratch
COPY --from=builder /app/ferroxide /ferroxide
ENTRYPOINT ["/ferroxide"]
