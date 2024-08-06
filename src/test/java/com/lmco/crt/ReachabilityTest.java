package com.lmco.crt;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.time.Duration;

public class ReachabilityTest {

    @BeforeEach
    void setUp() {
        AnalyzerProperties.loadProperties();
    }

    void setProperties(String analysisType) {
        AnalyzerProperties.setAnalysisType(analysisType);
        AnalyzerProperties.setCsvFileName(Utilities.getCsvFile(AnalyzerProperties.getAnalysisType()));
    }

    @Test
    void analyzeTestJarFilesTest() {
        setProperties("TEST");
        CodeReachabilityAnalyzer.analyzeJarFiles();
        Assertions.assertFalse(Constants.CLASS_BYTES_MAP.isEmpty());
    }

    @Test
    void analyzeClasspathJarFilesTest() {
        setProperties("CLASSPATH");
        CodeReachabilityAnalyzer.analyzeJarFiles();
        Assertions.assertFalse(Constants.CLASS_BYTES_MAP.isEmpty());
    }

    @Test
    void analyzeMainJarFilesTest() {
        setProperties("MAIN");
        CodeReachabilityAnalyzer.analyzeJarFiles();
        Assertions.assertFalse(Constants.CLASS_BYTES_MAP.isEmpty());
    }

    @Test
    void analyzeTestJarFileClassesTest() {
        Assertions.assertTimeout(Duration.ofSeconds(20), () -> {
            setProperties("TEST");
            CodeReachabilityAnalyzer.analyzeJarFiles();
            Assertions.assertFalse(Constants.CLASS_BYTES_MAP.isEmpty());
            CodeReachabilityAnalyzer.analyzeClasses();
            Assertions.assertFalse(Constants.CALL_GRAPH.isEmpty());
            Assertions.assertFalse(Constants.METHOD_INTERFACE_MAP.isEmpty());
        });
    }

    @Test
    void analyzeClasspathJarFileClassesTest() {
        Assertions.assertTimeout(Duration.ofSeconds(20), () -> {
            setProperties("CLASSPATH");
            CodeReachabilityAnalyzer.analyzeJarFiles();
            Assertions.assertFalse(Constants.CLASS_BYTES_MAP.isEmpty());
            CodeReachabilityAnalyzer.analyzeClasses();
            Assertions.assertFalse(Constants.CALL_GRAPH.isEmpty());
            Assertions.assertFalse(Constants.METHOD_INTERFACE_MAP.isEmpty());
        });
    }

    @Test
    void analyzeMainJarFileClassesTest() {
        Assertions.assertTimeout(Duration.ofSeconds(40), () -> {
            setProperties("MAIN");
            CodeReachabilityAnalyzer.analyzeJarFiles();
            Assertions.assertFalse(Constants.CLASS_BYTES_MAP.isEmpty());
            CodeReachabilityAnalyzer.analyzeClasses();
            Assertions.assertFalse(Constants.CALL_GRAPH.isEmpty());
            Assertions.assertFalse(Constants.METHOD_INTERFACE_MAP.isEmpty());
        });
    }

    @Test
    void analyzeTestModifyCodeSourcesTest() {
        Assertions.assertTimeout(Duration.ofSeconds(25), () -> {
            setProperties("TEST");
            CodeReachabilityAnalyzer.analyzeJarFiles();
            Assertions.assertFalse(Constants.CLASS_BYTES_MAP.isEmpty());
            CodeReachabilityAnalyzer.analyzeClasses();
            Assertions.assertFalse(Constants.CALL_GRAPH.isEmpty());
            Assertions.assertFalse(Constants.METHOD_INTERFACE_MAP.isEmpty());
            CodeReachabilityAnalyzer.modifyVulnerableCodeSources();
            Assertions.assertFalse(Constants.MODIFIED_TARGET_CODE_MAP.isEmpty());
        });
    }

    @Test
    void analyzeClasspathModifyCodeSourcesTest() {
        Assertions.assertTimeout(Duration.ofSeconds(25), () -> {
            setProperties("CLASSPATH");
            CodeReachabilityAnalyzer.analyzeJarFiles();
            Assertions.assertFalse(Constants.CLASS_BYTES_MAP.isEmpty());
            CodeReachabilityAnalyzer.analyzeClasses();
            Assertions.assertFalse(Constants.CALL_GRAPH.isEmpty());
            Assertions.assertFalse(Constants.METHOD_INTERFACE_MAP.isEmpty());
            CodeReachabilityAnalyzer.modifyVulnerableCodeSources();
            Assertions.assertFalse(Constants.MODIFIED_TARGET_CODE_MAP.isEmpty());
        });
    }

    @Test
    void analyzeMainModifyCodeSourcesTest() {
        Assertions.assertTimeout(Duration.ofSeconds(40), () -> {
            setProperties("MAIN");
            CodeReachabilityAnalyzer.analyzeJarFiles();
            Assertions.assertFalse(Constants.CLASS_BYTES_MAP.isEmpty());
            CodeReachabilityAnalyzer.analyzeClasses();
            Assertions.assertFalse(Constants.CALL_GRAPH.isEmpty());
            Assertions.assertFalse(Constants.METHOD_INTERFACE_MAP.isEmpty());
            CodeReachabilityAnalyzer.modifyVulnerableCodeSources();
            Assertions.assertFalse(Constants.MODIFIED_TARGET_CODE_MAP.isEmpty());
        });
    }

    @Test
    void analyzeTestGetExecutionPathsTest() {
        Assertions.assertTimeout(Duration.ofSeconds(600), () -> {
            setProperties("TEST");
            CodeReachabilityAnalyzer.analyzeJarFiles();
            Assertions.assertFalse(Constants.CLASS_BYTES_MAP.isEmpty());
            CodeReachabilityAnalyzer.analyzeClasses();
            Assertions.assertFalse(Constants.CALL_GRAPH.isEmpty());
            Assertions.assertFalse(Constants.METHOD_INTERFACE_MAP.isEmpty());
            CodeReachabilityAnalyzer.modifyVulnerableCodeSources();
            Assertions.assertFalse(Constants.MODIFIED_TARGET_CODE_MAP.isEmpty());
            CodeReachabilityAnalyzer.getVulnerableCodeExecutionPaths();
            Assertions.assertFalse(Constants.VULNERABLE_CODE_EXECUTION_MAP.isEmpty());
        });
    }

    @Test
    void analyzeClasspathGetExecutionPathsTest() {
        Assertions.assertTimeout(Duration.ofSeconds(600), () -> {
            setProperties("CLASSPATH");
            CodeReachabilityAnalyzer.analyzeJarFiles();
            Assertions.assertFalse(Constants.CLASS_BYTES_MAP.isEmpty());
            CodeReachabilityAnalyzer.analyzeClasses();
            Assertions.assertFalse(Constants.CALL_GRAPH.isEmpty());
            Assertions.assertFalse(Constants.METHOD_INTERFACE_MAP.isEmpty());
            CodeReachabilityAnalyzer.modifyVulnerableCodeSources();
            Assertions.assertFalse(Constants.MODIFIED_TARGET_CODE_MAP.isEmpty());
            CodeReachabilityAnalyzer.getVulnerableCodeExecutionPaths();
            Assertions.assertFalse(Constants.VULNERABLE_CODE_EXECUTION_MAP.isEmpty());
        });
    }

    @Test
    void analyzeMainGetExecutionPathsTest() {
        Assertions.assertTimeout(Duration.ofSeconds(900), () -> {
            setProperties("MAIN");
            CodeReachabilityAnalyzer.analyzeJarFiles();
            Assertions.assertFalse(Constants.CLASS_BYTES_MAP.isEmpty());
            CodeReachabilityAnalyzer.analyzeClasses();
            Assertions.assertFalse(Constants.CALL_GRAPH.isEmpty());
            Assertions.assertFalse(Constants.METHOD_INTERFACE_MAP.isEmpty());
            CodeReachabilityAnalyzer.modifyVulnerableCodeSources();
            Assertions.assertFalse(Constants.MODIFIED_TARGET_CODE_MAP.isEmpty());
            CodeReachabilityAnalyzer.getVulnerableCodeExecutionPaths();
            Assertions.assertFalse(Constants.VULNERABLE_CODE_EXECUTION_MAP.isEmpty());
        });
    }

    @Test
    void analyzeTestWriteExecutionPathsTest() {
        Assertions.assertTimeout(Duration.ofSeconds(600), () -> {
            setProperties("TEST");
            CodeReachabilityAnalyzer.analyzeJarFiles();
            Assertions.assertFalse(Constants.CLASS_BYTES_MAP.isEmpty());
            CodeReachabilityAnalyzer.analyzeClasses();
            Assertions.assertFalse(Constants.CALL_GRAPH.isEmpty());
            Assertions.assertFalse(Constants.METHOD_INTERFACE_MAP.isEmpty());
            CodeReachabilityAnalyzer.modifyVulnerableCodeSources();
            Assertions.assertFalse(Constants.MODIFIED_TARGET_CODE_MAP.isEmpty());
            CodeReachabilityAnalyzer.getVulnerableCodeExecutionPaths();
            Assertions.assertFalse(Constants.VULNERABLE_CODE_EXECUTION_MAP.isEmpty());
            CodeReachabilityAnalyzer.writeCodeExecutionPaths(Constants.VULNERABLE_CODE_EXECUTION_MAP, AnalyzerProperties.getExecutionPathsOutputDir());
            String executionPathsFileName = Utilities.createFileName(AnalyzerProperties.getExecutionPathsOutputDir());
            File executionPathsFile = new File(executionPathsFileName);
            Assertions.assertTrue(executionPathsFile.exists());
            CodeReachabilityAnalyzer.writeCodeExecutionPaths(Constants.REACHABLE_VULNERABLE_CODE_EXECUTION_MAP, AnalyzerProperties.getReachablePathsOutputDir());
            String reachablePathsFileName = Utilities.createFileName(AnalyzerProperties.getReachablePathsOutputDir());
            File reachablePathsFile = new File(reachablePathsFileName);
            Assertions.assertTrue(reachablePathsFile.exists());
        });
    }

    @Test
    void analyzeClasspathWriteExecutionPathsTest() {
        Assertions.assertTimeout(Duration.ofSeconds(600), () -> {
            setProperties("CLASSPATH");
            CodeReachabilityAnalyzer.analyzeJarFiles();
            Assertions.assertFalse(Constants.CLASS_BYTES_MAP.isEmpty());
            CodeReachabilityAnalyzer.analyzeClasses();
            Assertions.assertFalse(Constants.CALL_GRAPH.isEmpty());
            Assertions.assertFalse(Constants.METHOD_INTERFACE_MAP.isEmpty());
            CodeReachabilityAnalyzer.modifyVulnerableCodeSources();
            Assertions.assertFalse(Constants.MODIFIED_TARGET_CODE_MAP.isEmpty());
            CodeReachabilityAnalyzer.getVulnerableCodeExecutionPaths();
            Assertions.assertFalse(Constants.VULNERABLE_CODE_EXECUTION_MAP.isEmpty());
            CodeReachabilityAnalyzer.writeCodeExecutionPaths(Constants.VULNERABLE_CODE_EXECUTION_MAP, AnalyzerProperties.getExecutionPathsOutputDir());
            String executionPathsFileName = Utilities.createFileName(AnalyzerProperties.getExecutionPathsOutputDir());
            File executionPathsFile = new File(executionPathsFileName);
            Assertions.assertTrue(executionPathsFile.exists());
            CodeReachabilityAnalyzer.writeCodeExecutionPaths(Constants.REACHABLE_VULNERABLE_CODE_EXECUTION_MAP, AnalyzerProperties.getReachablePathsOutputDir());
            String reachablePathsFileName = Utilities.createFileName(AnalyzerProperties.getReachablePathsOutputDir());
            File reachablePathsFile = new File(reachablePathsFileName);
            Assertions.assertTrue(reachablePathsFile.exists());
        });
    }

    @Test
    void analyzeMainWriteExecutionPathsTest() {
        Assertions.assertTimeout(Duration.ofSeconds(900), () -> {
            setProperties("MAIN");
            CodeReachabilityAnalyzer.analyzeJarFiles();
            Assertions.assertFalse(Constants.CLASS_BYTES_MAP.isEmpty());
            CodeReachabilityAnalyzer.analyzeClasses();
            Assertions.assertFalse(Constants.CALL_GRAPH.isEmpty());
            Assertions.assertFalse(Constants.METHOD_INTERFACE_MAP.isEmpty());
            CodeReachabilityAnalyzer.modifyVulnerableCodeSources();
            Assertions.assertFalse(Constants.MODIFIED_TARGET_CODE_MAP.isEmpty());
            CodeReachabilityAnalyzer.getVulnerableCodeExecutionPaths();
            Assertions.assertFalse(Constants.VULNERABLE_CODE_EXECUTION_MAP.isEmpty());
            CodeReachabilityAnalyzer.writeCodeExecutionPaths(Constants.VULNERABLE_CODE_EXECUTION_MAP, AnalyzerProperties.getExecutionPathsOutputDir());
            String executionPathsFileName = Utilities.createFileName(AnalyzerProperties.getExecutionPathsOutputDir());
            File executionPathsFile = new File(executionPathsFileName);
            Assertions.assertTrue(executionPathsFile.exists());
            CodeReachabilityAnalyzer.writeCodeExecutionPaths(Constants.REACHABLE_VULNERABLE_CODE_EXECUTION_MAP, AnalyzerProperties.getReachablePathsOutputDir());
            String reachablePathsFileName = Utilities.createFileName(AnalyzerProperties.getReachablePathsOutputDir());
            File reachablePathsFile = new File(reachablePathsFileName);
            Assertions.assertTrue(reachablePathsFile.exists());
        });
    }

}
