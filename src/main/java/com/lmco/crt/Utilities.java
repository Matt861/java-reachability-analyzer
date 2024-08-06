package com.lmco.crt;

import java.io.*;
import java.util.*;

public class Utilities {

    public static long startTime;

    /**
     * Reads contents of a csv file located in main/resources and writes
     * contents to a map data structure.
     * @param csvFilePath Directory of csv file
     * @return Map data structured created from csv file contents
     */
    public static Map<String, List<String>> readCsvFromResources(String csvFilePath) {

        String line;
        String csvSplitBy = ",";

        Map<String, List<String>> vulnerableCodeMap = new HashMap<>();

        try (BufferedReader br = new BufferedReader(new FileReader(csvFilePath))) {

            // Read and discard the first line (header)
            br.readLine();

            while ((line = br.readLine()) != null) {
                // use comma as separator
                String[] columns = line.split(csvSplitBy);
                String key = columns[0].replace(" ", "");
                // Vulnerable class/method defined
                if (columns.length == 3) {
                    // Combine class/method name columns and remove whitespaces
                    String value = (columns[1] + "." + columns[2]).replace(" ", "");
                    // Check if the key already exists
                    if (vulnerableCodeMap.containsKey(key)) {
                        // If the key exists, add the new values to the existing list
                        vulnerableCodeMap.get(key).add(value);
                    } else {
                        // If the key doesn't exist, create a new entry
                        vulnerableCodeMap.put(key, new ArrayList<>(Collections.singleton(value)));
                    }
                }
                // Only vulnerable class is defined
                else if (columns.length == 2) {
                    String value = columns[1].replace(" ", "");
                    // Check if the key already exists
                    if (vulnerableCodeMap.containsKey(key)) {
                        // If the key exists, add the new values to the existing list
                        vulnerableCodeMap.get(key).add(value);
                    } else {
                        // If the key doesn't exist, create a new entry
                        vulnerableCodeMap.put(key, new ArrayList<>(Collections.singleton(value)));
                    }
                }
                else {
                    System.out.println("Invalid line: " + line);
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        return vulnerableCodeMap;
    }

    public static List<List<String>> retrieveVulnerableCodeExecutionPathsFromTree(TreeNode<String> vulnerableCode) {
        List<List<String>> result = new ArrayList<>();
        if (vulnerableCode == null) {
            return result;
        }

        List<String> currentPath = new ArrayList<>();
        depthFirstSearch(vulnerableCode, currentPath, result);
        return result;
    }

    public static void depthFirstSearch(TreeNode<String> vulnerableCode, List<String> currentPath, List<List<String>> result) {
        if (vulnerableCode == null) {
            return;
        }

        if (vulnerableCode.isInterfaceNode) {
            currentPath.add("Interface: " + vulnerableCode.data);
        }
        else {
            currentPath.add(vulnerableCode.data);
        }

        if (vulnerableCode.children.isEmpty()) {
            result.add(new ArrayList<>(currentPath));
        } else {
            for (TreeNode<String> child : vulnerableCode.children) {
                depthFirstSearch(child, currentPath, result);
            }
        }

        currentPath.remove(currentPath.size() - 1);
    }

    public static void startCodeExecutionTimer(String message) {
        System.out.println(message);
        startTime = System.nanoTime();
    }

    public static void stopCodeExecutionTimer() {
        long endTime = System.nanoTime();
        long duration = endTime - startTime;
        System.out.println("Execution time in milliseconds: " + (duration / 1_000_000));
        startTime = 0;
    }

    public static String getCsvFile(String analysisType) {
        switch (analysisType) {
            case "MAIN":
                return AnalyzerProperties.getMainCsvFileName();
            case "TEST":
                return AnalyzerProperties.getTestCsvFileName();
            case "CLASSPATH":
                return AnalyzerProperties.getClasspathCsvFileName();
            default:
                return null;
        }
    }

    public static String createFileName(String filePath) {
        String[] parts = filePath.split("\\\\");
        String fileName = parts[parts.length - 1];
        fileName = AnalyzerProperties.getServiceName() + "_" + getCurrentAnalysisType() + "_" + fileName;

        StringBuilder result = new StringBuilder();

        // Append all parts except the last one
        for (int i = 0; i < parts.length - 1; i++) {
            result.append(parts[i]);
            if (i < parts.length - 2) {
                result.append("\\");
            }
        }

        result.append("\\\\");
        result.append(fileName);

        return String.valueOf(result);
    }

    public static Constants.ANALYSIS_ENUM getCurrentAnalysisType() {
        return Constants.ANALYSIS_TYPE;
    }
}