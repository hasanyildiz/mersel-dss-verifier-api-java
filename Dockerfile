# Multi-stage Dockerfile for Verify API
# Stage 1: Build
FROM maven:3.8-openjdk-8 AS builder

WORKDIR /build

# Copy pom.xml (for dependency resolution)
COPY pom.xml .

# Download dependencies (cache layer)
RUN mvn dependency:go-offline -B

# Copy rest of source code
COPY src ./src

# Build application
RUN mvn clean package -DskipTests -B

# Stage 2: Runtime
FROM eclipse-temurin:8-jre

LABEL maintainer="Mersel <info@mersel.io>"
LABEL description="Mersel DSS Verify API - Dijital İmza Doğrulama Servisi"
LABEL version="0.1.0"

# Install required packages
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create app user (security best practice)
RUN groupadd -r -g 501 efaturaprod && useradd --no-log-init -m -r -u 501 -g efaturaprod efaturaprod
# Create directories
RUN mkdir -p /app/logs /app/certs && \
    chown -R efaturaprod:efaturaprod /app

WORKDIR /app

# Copy jar from builder stage
COPY --from=builder /build/target/app.jar /app/app.jar

# Switch to non-root user
USER efaturaprod

# Environment variables with defaults
ENV LOG_PATH=/app/logs

# Run application
ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -Djava.security.egd=file:/dev/./urandom -jar /app/app.jar"]

