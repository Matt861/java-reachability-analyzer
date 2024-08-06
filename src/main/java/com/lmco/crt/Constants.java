package com.lmco.crt;

import java.util.*;

public final class Constants {

    private Constants() {
        // No instantiation
    }

    public static final Map<String, List<String>> TARGET_CODE_MAP = Utilities.readCsvFromResources(AnalyzerProperties.getCsvFileName());
    public static final Map<String, List<String>> MODIFIED_TARGET_CODE_MAP = new HashMap<>(TARGET_CODE_MAP);
    public static final Map<String, Map<String, List<List<String>>>> VULNERABLE_CODE_EXECUTION_MAP = new HashMap<>();
    public static final Map<String, Map<String, List<List<String>>>> REACHABLE_VULNERABLE_CODE_EXECUTION_MAP = new HashMap<>();
    public static final Map<String, byte[]> CLASS_BYTES_MAP = new HashMap<>();
    public static final Map<String, List<String>> METHOD_INTERFACE_MAP = new HashMap<>();
    public static final Map<String, Set<String>> CALL_GRAPH = new HashMap<>();
    public enum ANALYSIS_ENUM {
        MAIN, TEST, CLASSPATH, ALL;
    }

    public static final ANALYSIS_ENUM ANALYSIS_TYPE = ANALYSIS_ENUM.valueOf(AnalyzerProperties.getAnalysisType().toUpperCase());
}
