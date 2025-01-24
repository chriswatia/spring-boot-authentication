FROM openjdk:21-jdk-slim
WORKDIR /app
COPY target/*.jar /app/authentication-authorization.jar
EXPOSE 8761
ENTRYPOINT ["java", "-jar", "authentication-authorization.jar"]