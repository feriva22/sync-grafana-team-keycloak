FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o app

FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/app .
RUN apk add --no-cache ca-certificates

# Add healthcheck (optional)
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD pgrep app || exit 1

# For safety, use a non-root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser

# The program handles its own interval execution
CMD ["./app"]