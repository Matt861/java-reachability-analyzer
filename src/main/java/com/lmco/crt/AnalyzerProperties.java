package com.lmco.crt;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Properties;

public class AnalyzerProperties {

    private static String applicationGroup;
    private static String mainCsvFileName;
    private static String testCsvFileName;
    private static String classpathCsvFileName;
    private static String executionPathsOutputDir;
    private static String reachablePathsOutputDir;
    private static String mainServiceJar;
    private static String testServiceJar;
    private static String crtDependenciesJar;
    private static String crtTestDependenciesJar;
    private static String crtClasspathDependenciesJar;
    private static String analysisType;
    private static String serviceName;
    private static String csvFileName;

    public static String getApplicationGroup() {
        return applicationGroup;
    }
    public static String getMainCsvFileName() {
        return mainCsvFileName;
    }
    public static String getTestCsvFileName() {
        return testCsvFileName;
    }
    public static String getClasspathCsvFileName() {
        return classpathCsvFileName;
    }
    public static String getExecutionPathsOutputDir() {
        return executionPathsOutputDir;
    }
    public static String getReachablePathsOutputDir() {
        return reachablePathsOutputDir;
    }
    public static String getMainServiceJar() { return mainServiceJar; }
    public static String getTestServiceJar() { return testServiceJar; }
    public static String getCrtDependenciesJar() {
        return crtDependenciesJar;
    }
    public static String getCrtTestDependenciesJar() {
        return crtTestDependenciesJar;
    }
    public static String getCrtClasspathDependenciesJar() {
        return crtClasspathDependenciesJar;
    }
    public static String getAnalysisType() { return analysisType; }
    public static String getServiceName() { return serviceName; }
    public static String getCsvFileName() { return csvFileName; }

    public static void loadProperties() {
        Properties properties = new Properties();
        try (InputStream input = Files.newInputStream(Paths.get("src\\main\\resources\\config.properties"))) {
            properties.load(input);
            applicationGroup = properties.getProperty("application.group");
            mainCsvFileName = properties.getProperty("main.csv.file.name");
            testCsvFileName = properties.getProperty("test.csv.file.name");
            classpathCsvFileName = properties.getProperty("classpath.csv.file.name");
            executionPathsOutputDir = properties.getProperty("execution.paths.output.dir");
            reachablePathsOutputDir = properties.getProperty("reachable.paths.output.dir");
            mainServiceJar = properties.getProperty("main.service.jar");
            testServiceJar = properties.getProperty("test.service.jar");
            crtDependenciesJar = properties.getProperty("crt.dependencies.jar");
            crtTestDependenciesJar = properties.getProperty("crt.test.dependencies.jar");
            crtClasspathDependenciesJar = properties.getProperty("crt.classpath.dependencies.jar");
            analysisType = properties.getProperty("analysis.type");
            serviceName = properties.getProperty("service.name");
            csvFileName = Utilities.getCsvFile(analysisType);
        } catch (IOException ex) {
            ex.printStackTrace();
        }
    }

    public static void setAnalysisType(String analysisType) {
        AnalyzerProperties.analysisType = analysisType;
    }

    public static void setCsvFileName(String csvFileName) {
        AnalyzerProperties.csvFileName = csvFileName;
    }
}
