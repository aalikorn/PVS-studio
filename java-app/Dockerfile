# Multi-stage build for Java Spring Boot application
FROM --platform=linux/amd64 maven:3.9-eclipse-temurin-17-alpine AS build

WORKDIR /java-app

# Copy pom.xml and download dependencies (cached layer)
COPY pom.xml .
RUN mvn dependency:go-offline -B

# Copy source code and build
COPY src ./src
RUN mvn clean package -DskipTests

# Runtime stage
FROM --platform=linux/amd64 eclipse-temurin:17-jre-alpine

WORKDIR /java-app

# Copy the built JAR from build stage
COPY --from=build /app/target/*.jar app.jar

# Expose port
EXPOSE 5001

# Run the application
ENTRYPOINT ["java", "-jar", "app.jar"]
