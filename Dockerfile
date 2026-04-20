FROM golang:1.25-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o server .

# --- STAGE 2: FINAL IMAGE ---
FROM alpine:latest

WORKDIR /app

# Ambil file executable server dari stage builder
COPY --from=builder /app/server .

# KUNCI UTAMA: Ambil file .env dari stage builder biar Go bisa baca passwordnya!
# (Pake tanda bintang * biar kalau filenya nggak sengaja kehapus, build-nya nggak langsung error)
COPY --from=builder /app/.env* ./

EXPOSE 8080

# Langsung jalanin servernya aja bang, biarin urusan init.sql diurusin sama container DB
CMD ["./server"]
