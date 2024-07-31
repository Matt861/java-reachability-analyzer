package com.lmco.crt;

public final class Constants {

    private Constants() {
        // No instantiation
    }

    public static final String CSV_FILE_NAME = "src\\main\\resources\\crt-maven-dependencies-vulnerable-code.csv";
    public static final String APPLICATION_GROUP = "com/lmco/crt";
    public static final String EXECUTION_PATHS_OUTPUT_DIR = "output\\VulnerableCodeExecutionPaths.txt";
    public static final String REACHABLE_PATHS_OUTPUT_DIR = "output\\ReachableCodeExecutionPaths.txt";
    public static final String SERVICE_JAR_PATH = "jars\\crt-service-1.0-SNAPSHOT.jar";
    public static final String CRT_DEPENDENCIES_JAR_PATH = "jars\\crt-dependencies-0.4.0.jar";
    public static final String CRT_TEST_DEPENDENCIES_JAR_PATH = "jars\\crt-test-dependencies-0.4.0.jar";
    public static final String CRT_CLASSPATH_DEPENDENCIES_JAR_PATH = "jars\\crt-classpath-dependencies-0.4.0.jar";

}
