/*
 * Root build for mini-kms.
 *
 * Shared configuration applied to every Java subproject: Maven Central,
 * a Java 21 toolchain (pinned), and JUnit 5 for tests. Per-module build
 * files only declare their own dependencies and (for runnable modules) the
 * application entry point.
 */

subprojects {
    apply(plugin = "java")

    repositories {
        mavenCentral()
    }

    extensions.configure<JavaPluginExtension> {
        toolchain {
            languageVersion = JavaLanguageVersion.of(21)
        }
    }

    tasks.withType<Test>().configureEach {
        useJUnitPlatform()
        testLogging {
            events("passed", "skipped", "failed")
        }
    }

    tasks.withType<JavaCompile>().configureEach {
        options.encoding = "UTF-8"
        options.compilerArgs.add("-parameters")
    }
}
