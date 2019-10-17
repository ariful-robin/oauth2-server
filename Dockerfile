FROM maven:3.6-jdk-12 as build
WORKDIR /sputnik-ena-parent
COPY pom.xml .
COPY oauth2-server oauth2-server/
RUN mvn -f oauth2-server/pom.xml clean package -DskipTests=true

#FROM frolvlad/alpine-oraclejdk8:slim
FROM openjdk:12
COPY --from=build /sputnik-ena-parent/oauth2-server/target/*.jar app.jar
EXPOSE 8081 8081
EXPOSE 38787 8787
LABEL name=sputnik-ena/oauth2-server
ENV JAVA_OPTS="-Xdebug -Xrunjdwp:server=y,transport=dt_socket,address=8787,suspend=n"
ENTRYPOINT [ "sh", "-c", "java $JAVA_OPTS -Djava.security.egd=file:/dev/./urandom -Dspring.profiles.active=docker -jar /app.jar" ]
