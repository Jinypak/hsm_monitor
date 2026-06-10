import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter

plugins {
    application
    // CLI 전용 빌드(-PskipJavafx)에서는 JavaFX 플러그인을 적용하지 않는다.
    // 플러그인이 내부적으로 Gradle toolchain을 사용해 javac를 탐색하는데,
    // RHEL 등에서 JRE만 설치된 경우(java-21-openjdk, javac 없음) 빌드 실패.
    id("org.openjfx.javafxplugin") version "0.1.0" apply false
}

group = "com.yours.hsm"
version = "0.1.0-SNAPSHOT"

// toolchain 을 사용하지 않고 현재 실행 중인 JDK를 그대로 사용한다.
// Gradle toolchain auto-detection 은 비표준 경로(RHEL 등)에서 설치된 JDK를 못 찾는 경우가 있어
// "Cannot find a Java installation" 오류가 발생한다.
val runningJdk = JavaVersion.current()
java {
    sourceCompatibility = runningJdk
    targetCompatibility = runningJdk
}

// 최소 JDK 21 요구 (virtual threads, sealed interfaces, pattern switch 등 사용)
if (runningJdk < JavaVersion.VERSION_21) {
    throw GradleException("JDK 21 이상이 필요합니다. 현재: $runningJdk")
}

// Luna JSP 경로 — OS별 기본값(Windows/Linux). -PlunaClientPath / -PlunaJspLib 로 오버라이드.
val isWindows = System.getProperty("os.name").lowercase().contains("win")
val lunaClientPath: String =
    (project.findProperty("lunaClientPath") as String?)
        ?: if (isWindows) "C:/Program Files/SafeNet/LunaClient" else "/usr"

// Windows: JSP/lib (LunaProvider.jar + LunaAPI.dll), Linux: jsp/lib (LunaProvider.jar + libLunaAPI.so)
val lunaJspLib: String =
    (project.findProperty("lunaJspLib") as String?)
        ?: if (isWindows) "$lunaClientPath/JSP/lib" else "$lunaClientPath/jsp/lib"

repositories {
    mavenCentral()
}

// -PskipJavafx: CLI 전용 빌드 (JRE만 있어도 빌드 가능, UI 코드 제외)
// GUI 빌드(기본): JavaFX 플러그인 적용, ui/ 포함
val skipJavafx = project.hasProperty("skipJavafx")

if (!skipJavafx) {
    apply(plugin = "org.openjfx.javafxplugin")
    extensions.configure<org.openjfx.gradle.JavaFXOptions>("javafx") {
        version = "21.0.4"
        modules = listOf("javafx.controls", "javafx.fxml")
    }
}

// CLI 빌드 시 JavaFX 의존 코드(ui/, App.java) 컴파일에서 제외
sourceSets.main {
    java {
        if (skipJavafx) {
            exclude("**/ui/**")
            exclude("**/App.java")
        }
    }
}

dependencies {
    // Luna JSP — gradle.properties 의 lunaClientPath/JSP/lib/LunaProvider.jar 직접 참조
    implementation(files("$lunaJspLib/LunaProvider.jar"))

    implementation("com.fasterxml.jackson.core:jackson-databind:2.17.2")
    implementation("com.fasterxml.jackson.module:jackson-module-parameter-names:2.17.2")

    implementation("org.slf4j:slf4j-api:2.0.13")
    implementation("org.apache.logging.log4j:log4j-slf4j2-impl:2.23.1")
    implementation("org.apache.logging.log4j:log4j-core:2.23.1")

    testImplementation(platform("org.junit:junit-bom:5.11.3"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    testImplementation("org.mockito:mockito-core:5.14.2")
}

application {
    mainClass.set("com.yours.hsm.App")
    applicationDefaultJvmArgs = listOf(
        "--enable-native-access=ALL-UNNAMED,javafx.graphics",
        "-Dfile.encoding=UTF-8",
        "-Dlog4j.configurationFile=log4j2.xml"
    )
}

tasks.named<JavaExec>("run") {
    // LunaAPI.dll 은 JSP/lib 에 있음 — 네이티브 경로에 추가
    jvmArgs("-Djava.library.path=$lunaJspLib")
}

tasks.withType<JavaCompile> {
    options.compilerArgs.add("-parameters")
}

// 빌드마다 갱신되는 타임스탬프 — build-info.properties 에 스탬핑되어 GUI 제목에 노출됨
val buildTimestamp: String =
    DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss")
        .withZone(ZoneId.systemDefault())
        .format(Instant.now())

tasks.processResources {
    // 타임스탬프가 매번 달라지므로 processResources 는 리빌드마다 다시 실행됨
    inputs.property("buildTimestamp", buildTimestamp)
    filesMatching("build-info.properties") {
        expand(mapOf(
            "version"        to project.version.toString(),
            "buildTimestamp" to buildTimestamp
        ))
    }
}

tasks.test {
    useJUnitPlatform()
    // Mockito(Byte Buddy)가 JDK 25(class file 69)를 아직 정식 지원하지 않아 experimental 플래그 필요.
    // Byte Buddy 가 JDK 25 를 정식 지원하면 제거 가능.
    systemProperty("net.bytebuddy.experimental", "true")
    // Mockito 인라인 mock maker 의 동적 에이전트 로딩 경고 억제(향후 JDK 기본 비활성 대비).
    jvmArgs("-XX:+EnableDynamicAgentLoading")
}

// slot 0 → slot 1 키 이전 CLI 하니스 (실제 HSM 필요)
// 예: ./gradlew keyTransfer -Pslot0=0 -Pslot1=1 -PkekLabel=myAesKek
tasks.register<JavaExec>("probeLuna") {
    group = "verification"
    description = "LunaProvider 가 노출하는 Cipher 알고리즘 이름 덤프"
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("com.yours.hsm.tools.ProbeLuna")
    jvmArgs("-Djava.library.path=$lunaJspLib", "--enable-native-access=ALL-UNNAMED",
            "-Dfile.encoding=UTF-8", "-Dstdout.encoding=UTF-8")
}

tasks.register<JavaExec>("algoList") {
    group = "verification"
    description = "카탈로그 × LunaProvider 가용성 매칭 — 구현 가능한 알고리즘 목록 출력"
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("com.yours.hsm.tools.AlgoSupportProbe")
    jvmArgs("-Djava.library.path=$lunaJspLib", "--enable-native-access=ALL-UNNAMED",
            "-Dfile.encoding=UTF-8", "-Dstdout.encoding=UTF-8", "-DconsoleLevel=OFF")
}

tasks.register<JavaExec>("importPub") {
    group = "verification"
    description = "X.509 DER 공개키 파일을 HSM 토큰에 import (-Pslot -Pfile -Plabel -Ppin)"
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("com.yours.hsm.tools.ImportPublicKeyHarness")
    jvmArgs("-Djava.library.path=$lunaJspLib", "--enable-native-access=ALL-UNNAMED",
            "-Dfile.encoding=UTF-8", "-Dstdout.encoding=UTF-8", "-Dstderr.encoding=UTF-8")
    for (k in listOf("slot", "file", "label", "pin")) {
        (project.findProperty(k) as String?)?.let { systemProperty(k, it) }
    }
}

tasks.register<JavaExec>("keyMigrate") {
    group = "verification"
    description = "slot0에서 ML-DSA 생성·래핑(export) → slot1에 언래핑(import). 외부 AES KEK를 RSA봉투로 양 슬롯 주입"
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("com.yours.hsm.tools.Hsm2HsmTransferHarness")
    jvmArgs("-Djava.library.path=$lunaJspLib", "--enable-native-access=ALL-UNNAMED",
            "-Dfile.encoding=UTF-8", "-Dstdout.encoding=UTF-8", "-Dstderr.encoding=UTF-8")
    for (k in listOf("slot0", "slot1", "pin", "base")) {
        (project.findProperty(k) as String?)?.let { systemProperty(k, it) }
    }
}

tasks.register<JavaExec>("keyCleanup") {
    group = "verification"
    description = "테스트로 만든 키만 prefix로 삭제 (-Pslots=0,1 -Ppin -Pprefixes=..). 고객 원본은 보존"
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("com.yours.hsm.tools.KeyCleanupHarness")
    jvmArgs("-Djava.library.path=$lunaJspLib", "--enable-native-access=ALL-UNNAMED",
            "-Dfile.encoding=UTF-8", "-Dstdout.encoding=UTF-8", "-Dstderr.encoding=UTF-8")
    for (k in listOf("slots", "pin", "prefixes")) {
        (project.findProperty(k) as String?)?.let { systemProperty(k, it) }
    }
}

tasks.register<JavaExec>("wrapTest") {
    group = "verification"
    description = "Java SunJCE vs OpenSSL AES-KWP 래핑 비교 (LunaClient 폴더에 파일 생성)"
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("com.yours.hsm.tools.WrapTestHarness")
    jvmArgs("--enable-native-access=ALL-UNNAMED",
            "-Dfile.encoding=UTF-8", "-Dstdout.encoding=UTF-8")
}

tasks.register<JavaExec>("keyImport") {
    group = "verification"
    description = "외부 생성 ML-DSA 개인키를 AES(DEK)로 래핑→DEK를 RSA로 HSM 주입→HSM에서 언래핑·저장"
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("com.yours.hsm.tools.ExternalKeyImportHarness")
    jvmArgs("-Djava.library.path=$lunaJspLib", "--enable-native-access=ALL-UNNAMED",
            "-Dfile.encoding=UTF-8", "-Dstdout.encoding=UTF-8", "-Dstderr.encoding=UTF-8")
    for (k in listOf("slot", "pin")) {
        (project.findProperty(k) as String?)?.let { systemProperty(k, it) }
    }
}

tasks.register<JavaExec>("hsmCli") {
    group = "application"
    description = "HSM Monitor 대화형 CLI (Linux headless). 슬롯/PIN은 실행 후 대화형 입력."
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("com.yours.hsm.cli.CliApp")
    jvmArgs("-Djava.library.path=$lunaJspLib", "--enable-native-access=ALL-UNNAMED",
            "-Dfile.encoding=UTF-8", "-Dstdout.encoding=UTF-8", "-Dstderr.encoding=UTF-8",
            "-DconsoleLevel=OFF")
    standardInput = System.`in`
}

tasks.register<JavaExec>("pqcHsmTest") {
    group = "verification"
    description = "실제 HSM 에 ML-DSA/ML-KEM 키 생성→서명/검증·캡슐화 검증 후 정리 (-Pslot -Ppin)"
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("com.yours.hsm.tools.PqcHsmHarness")
    jvmArgs("-Djava.library.path=$lunaJspLib", "--enable-native-access=ALL-UNNAMED",
            "-Dfile.encoding=UTF-8", "-Dstdout.encoding=UTF-8", "-Dstderr.encoding=UTF-8",
            "-DconsoleLevel=OFF")
    for (k in listOf("slot", "pin")) {
        (project.findProperty(k) as String?)?.let { systemProperty(k, it) }
    }
}

tasks.register<JavaExec>("keyTransfer") {
    group = "verification"
    description = "slot0 에서 ML-DSA 키 생성→래핑→내보내기, slot1 에서 언래핑→저장"
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("com.yours.hsm.tools.KeyTransferHarness")
    jvmArgs("-Djava.library.path=$lunaJspLib", "--enable-native-access=ALL-UNNAMED",
            "-Dfile.encoding=UTF-8", "-Dstdout.encoding=UTF-8", "-Dstderr.encoding=UTF-8")
    // -P 속성을 시스템 프로퍼티로 전달
    for (k in listOf("slot0", "slot1", "kekLabel", "lunaDir")) {
        (project.findProperty(k) as String?)?.let { systemProperty(k, it) }
    }
}
