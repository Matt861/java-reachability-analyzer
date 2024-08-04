package com.lmco.crt;

import org.junit.Test;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.zip.GZIPInputStream;

public class ReachabilityTest {

//    @Test
//    public void test1() throws IOException {
//        File serviceJarFile = new File(Constants.SERVICE_JAR_PATH);
//        File dependenciesJar = new File(Constants.CRT_DEPENDENCIES_JAR_PATH);
//        File tempJarFile = Files.createTempFile("test", ".jar").toFile();
//        try (FileOutputStream out = new FileOutputStream(tempJarFile)) {
//            Files.copy(dependenciesJar.toPath(), out);
//        }
//        //MethodReachabilityAnalyzer3 analyzer = new MethodReachabilityAnalyzer3();
//        //CodeReachabilityAnalyzer3.analyzeJar(serviceJar, true);
//        CodeReachabilityAnalyzer3.analyzeJar(tempJarFile);
//        System.out.println("breakpoint");
//    }

    @Test
    public void test2() throws IOException {
        Map<String, Set<String>> callGraph = Constants.callGraph;
        try (GZIPInputStream gzipInputStream = new GZIPInputStream(Files.newInputStream(Paths.get("input\\CallGraph.csv.gz")));
             BufferedReader reader = new BufferedReader(new InputStreamReader(gzipInputStream))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(",", 2);
                if (parts.length == 2) {
                    String key = parts[0];
                    String value = parts[1];
                    Constants.callGraph.computeIfAbsent(key, k -> new HashSet<>()).add(value);
                }
            }
        }
        System.out.println("breakpoint");
    }
}
