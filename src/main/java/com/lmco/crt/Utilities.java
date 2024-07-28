package com.lmco.crt;

import java.io.*;
import java.util.*;

public class Utilities {

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
}