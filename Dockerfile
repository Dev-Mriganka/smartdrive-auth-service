FROM openjdk:17-jdk-slim

WORKDIR /app

# Copy the built JAR file
COPY build/libs/*.jar app.jar

# Expose the port
EXPOSE 8085

# Set environment variables
ENV SPRING_PROFILES_ACTIVE=docker
ENV REDIS_HOST=redis
ENV REDIS_PORT=6379
ENV JWT_SECRET=your-256-bit-secret-key-here-make-it-long-and-secure
ENV JWT_EXPIRATION=86400000
ENV JWT_REFRESH_EXPIRATION=604800000
ENV JWT_ISSUER=smartdrive-auth-service

# Run the application
ENTRYPOINT ["java", "-jar", "app.jar"]
