# Multi-stage build for Java Spring Boot application
FROM maven:3.9-eclipse-temurin-17-alpine AS build

WORKDIR /java-app

# Copy pom.xml first so dependency downloads stay in a cached layer when possible
COPY pom.xml .

# Copy source code and build
COPY src ./src
RUN mvn clean package -DskipTests

# Runtime stage
FROM eclipse-temurin:17-jre-alpine

WORKDIR /java-app

# Copy the built JAR from build stage
COPY --from=build /java-app/target/*.jar app.jar

# Expose port
EXPOSE 5001

# Run the application
ENTRYPOINT ["java", "-jar", "app.jar"]
