FROM gradle:8.14.3-jdk21 AS build
WORKDIR /home/gradle/project
COPY --chown=gradle:gradle . .
RUN gradle --no-daemon test installDist

FROM eclipse-temurin:21-jre-jammy
WORKDIR /app
COPY --from=build /home/gradle/project/build/install/spdecode-key-attestation /app
USER 65532:65532
ENV JAVA_TOOL_OPTIONS="-Xmx192m -Dsun.net.httpserver.maxReqTime=15 -Dsun.net.httpserver.maxRspTime=15"
CMD ["/app/bin/spdecode-key-attestation"]
