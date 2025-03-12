# syntax=docker/dockerfile:1

# Builder stage
FROM --platform=$BUILDPLATFORM golang:1.20-alpine AS builder
WORKDIR /app
COPY . .
RUN GOARCH=$(echo $TARGETPLATFORM | cut -d'/' -f2) go build -o ferroxide ./cmd/ferroxide

# Final stage
FROM gcr.io/distroless/static-debian12
COPY --from=builder /app/ferroxide /ferroxide
USER ferroxide:ferroxide
ENTRYPOINT ["/ferroxide"]
