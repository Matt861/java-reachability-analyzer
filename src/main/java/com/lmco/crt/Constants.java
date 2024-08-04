package com.lmco.crt;

import java.util.*;

public final class Constants {

    private Constants() {
        // No instantiation
    }

    public static final String CSV_FILE_NAME = "src\\main\\resources\\VulnerableCode.csv";
    public static final String APPLICATION_GROUP = "com/lmco/crt";
    public static final String EXECUTION_PATHS_OUTPUT_DIR = "output\\VulnerableCodeExecutionPaths.txt";
    public static final String REACHABLE_PATHS_OUTPUT_DIR = "output\\ReachableCodeExecutionPaths.txt";
    public static final String SERVICE_JAR_PATH = "jars\\crt-service-4.0-SNAPSHOT.jar";
    public static final String CRT_DEPENDENCIES_JAR_PATH = "jars\\crt-dependencies-0.4.0.jar";
    public static final String CRT_TEST_DEPENDENCIES_JAR_PATH = "jars\\crt-test-dependencies-0.4.0.jar";
    public static final String CRT_CLASSPATH_DEPENDENCIES_JAR_PATH = "jars\\crt-classpath-dependencies-0.4.0.jar";
    public static final Map<String, List<String>> TARGET_CODE_MAP = Utilities.readCsvFromResources(Constants.CSV_FILE_NAME);
    public static final Map<String, Set<String>> callGraph = new HashMap<>();
    public static final Map<String, List<String>> modifiedTargetCodeMap = new HashMap<>(TARGET_CODE_MAP);
    public static final Map<String, Map<String, List<List<String>>>> vulnerableCodeExecutionMap = new HashMap<>();
    public static final Map<String, Map<String, List<List<String>>>> reachableVulnerableCodeExecutionMap = new HashMap<>();
    public static final Map<String, String> interfaceMap = new HashMap<>();
    public static final Map<String, byte[]> classBytesMap = new HashMap<>();
    public static final Map<String, List<String>> methodInterfaceMap = new HashMap<>();
}
