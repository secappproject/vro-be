FROM golang:1.25-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o server .

FROM alpine:latest

WORKDIR /app
RUN apk add --no-cache postgresql-client

COPY --from=builder /app/server .
COPY --from=builder /app/init.sql .

EXPOSE 8080

CMD sh -c "if [ -f /app/init.sql ]; then psql \"$DATABASE_URL\" -f /app/init.sql || true; fi && ./server"
