# Multi-stage build for the Spring Boot Identity & Keycloak API service.

# --- Build stage -----------------------------------------------------------
FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /src
COPY pom.xml ./
# Pre-fetch dependencies (cached when pom.xml is unchanged).
RUN mvn -q -B dependency:go-offline || true
COPY src ./src
RUN mvn -q -B clean package -DskipTests

# --- Runtime stage ---------------------------------------------------------
FROM eclipse-temurin:21-jre
WORKDIR /app
COPY --from=build /src/target/identity-keycloak-api-0.0.1.jar /app/app.jar
EXPOSE 3000
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
