# 1단계: 빌드 스테이지
FROM gradle:8.5-jdk21 AS build
WORKDIR /app

# Gradle 래퍼와 설정 파일 먼저 복사 (캐시 활용)
COPY gradlew .
COPY gradle gradle
COPY build.gradle settings.gradle ./

# [최적화] 의존성 미리 다운로드 (변경 없을 시 캐시 사용)
# --no-daemon과 함께 메모리 제한 옵션을 주면 저사양 서버에서 안정적입니다.
RUN ./gradlew dependencies --no-daemon || return 0

# 소스 복사
COPY . .

# [최적화] 빌드 시 테스트 제외 및 JVM 메모리 제한
# -x test: 테스트를 건너뛰어 빌드 시간과 메모리 사용량을 획기적으로 줄임
RUN ./gradlew bootJar --no-daemon -x test -Dorg.gradle.jvmargs="-Xmx512m"

# 2단계: 실행 스테이지 (JRE 사용 권장)
# 실행만 할 때는 JDK보다 더 가벼운 JRE를 사용하는 것이 용량 이득이 큽니다.
FROM eclipse-temurin:21-jre
WORKDIR /app

# 빌드 스테이지에서 생성된 jar 파일만 추출
COPY --from=build /app/build/libs/*.jar app.jar

# 컨테이너 실행 명령
ENTRYPOINT ["java", "-Xmx512m", "-jar", "app.jar"]