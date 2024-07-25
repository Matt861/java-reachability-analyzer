package com.lmco.crt;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.io.*;
import java.util.*;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.stream.Collectors;

public class CodeReachabilityAnalyzer {

    private static final Map<String, List<String>> TARGET_CODE_MAP = Utilities.readCsvFromResources(Constants.CSV_FILE_NAME);
    private static final Map<String, Set<String>> callGraph = new HashMap<>();
    private static final Set<String> allMethods = new HashSet<>();
    private static final Map<String, List<String>> modifiedTargetCodeMap = new HashMap<>(TARGET_CODE_MAP);
    private static final Map<String, Map<String, List<List<String>>>> vulnerableCodeExecutionMap = new HashMap<>();
    private static final Map<String, Map<String, List<List<String>>>> reachableVulnerableCodeExecutionMap = new HashMap<>();

    /**
     *
     * @param args None
     * @throws IOException
     */
    public static void main(String[] args) throws IOException {
        File jarFile = new File(Constants.FAT_JAR_PATH);
        CodeReachabilityAnalyzer analyzer = new CodeReachabilityAnalyzer();
        analyzer.analyzeJar(jarFile);
        analyzer.modifyVulnerableCodeSources();
        analyzer.getVulnerableCodeExecutionPaths();
        analyzer.writeCodeExecutionPaths(vulnerableCodeExecutionMap, Constants.EXECUTION_PATHS_OUTPUT_DIR);
        analyzer.writeCodeExecutionPaths(reachableVulnerableCodeExecutionMap, Constants.REACHABLE_PATHS_OUTPUT_DIR);
    }

    /**
     *
     * @param jarFile
     * @throws IOException
     */
    private void analyzeJar(File jarFile) throws IOException {
        try (JarFile jar = new JarFile(jarFile)) {
            Enumeration<JarEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                if (entry.getName().endsWith(".class") && !entry.getName().contains("META-INF/")) {
                    try {
                        analyzeClass(jar, entry);
                    } catch (SecurityException | IOException e) {
                        System.err.println("Skipping entry due to error: " + entry.getName() + " - " + e.getMessage());
                    }
                }
            }
        }
    }

    /**
     *
     * @param jar
     * @param entry
     * @throws IOException
     */
    private void analyzeClass(JarFile jar, JarEntry entry) throws IOException {
        try (InputStream inputStream = jar.getInputStream(entry)) {
            ClassReader classReader = new ClassReader(inputStream);
            ClassNode classNode = new ClassNode();
            classReader.accept(classNode, 0);

            for (MethodNode method : classNode.methods) {
                String methodName = classNode.name + "." + method.name + method.desc;
                allMethods.add(methodName);
                Set<String> calledMethods = new HashSet<>();
                if (method.instructions != null) {
                    for (AbstractInsnNode insn : method.instructions) {
                        if (insn.getType() == AbstractInsnNode.METHOD_INSN) {
                            MethodInsnNode methodInsn = (MethodInsnNode) insn;
                            calledMethods.add(methodInsn.owner + "." + methodInsn.name + methodInsn.desc);
                        }
                    }
                }
                callGraph.put(methodName, calledMethods);
            }
        }
    }

    /**
     *
     * @return
     */
    private void modifyVulnerableCodeSources() {
        for (Map.Entry<String, List<String>> targetMapEntry : modifiedTargetCodeMap.entrySet()) {
            List<String> updatedCodeTargets = new ArrayList<>();
            String vulnerabilityId = targetMapEntry.getKey();
            List<String> codeTargets = targetMapEntry.getValue();
            for (String target : codeTargets) {
                List<String> newCodeTargets;
                // Target code is a class and a method
                if (target.contains(".")) {
                    String[] codeTargetParts = target.split("\\.");
                    newCodeTargets = findMethodsByClassAndName(codeTargetParts[0], codeTargetParts[1]);
                }
                // Target code is an entire class
                else {
                    newCodeTargets = findMethodsByClassAndName(target, null);
                }
                updatedCodeTargets.addAll(newCodeTargets);
            }
            modifiedTargetCodeMap.put(vulnerabilityId, updatedCodeTargets);
        }
    }

    /**
     *
     * @param className
     * @param methodName
     * @return
     */
    public static List<String> findMethodsByClassAndName(String className, String methodName) {
        return allMethods.stream().filter(method -> method.startsWith(className + ".") &&
                            (methodName == null || methodName.isEmpty() ||
                                method.contains("." + methodName + "("))).collect(Collectors.toList());
    }

    /**
     *
     */
    private void getVulnerableCodeExecutionPaths() {
        for (Map.Entry<String, List<String>> codeTargetMapEntry : modifiedTargetCodeMap.entrySet()) {
            Map<String, List<List<String>>> vulnerableCodeExecutionPathsMap = new HashMap<>();
            String vulnerabilityId = codeTargetMapEntry.getKey();
            List<String> codeTargets = codeTargetMapEntry.getValue();
            for (String codeTarget : codeTargets) {
                TreeNode<String> vulnerableCode = new TreeNode<>(codeTarget);
                TreeUtil.createVulnerableCodeExecutionTree(vulnerableCode);
                List<List<String>> vulnerableCodeExecutionPaths = TreeUtil.retrieveVulnerableCodeExecutionPathsFromTree(vulnerableCode);
                getReachableVulnerableCodeExecutionPaths(vulnerableCodeExecutionPaths, vulnerableCode, vulnerabilityId);
                vulnerableCodeExecutionPathsMap.put(vulnerableCode.data, vulnerableCodeExecutionPaths);
            }
            vulnerableCodeExecutionMap.put(vulnerabilityId, vulnerableCodeExecutionPathsMap);
        }
    }

    /**
     *
     * @param vulnerableCodeExecutionPaths
     * @param vulnerableCode
     * @param vulnerabilityId
     */
    private void getReachableVulnerableCodeExecutionPaths(List<List<String>> vulnerableCodeExecutionPaths, TreeNode<String> vulnerableCode, String vulnerabilityId) {
        Map<String, List<List<String>>> reachableVulnerableCodeExecutionPathsMap = new HashMap<>();
        List<List<String>> reachableVulnerableCodePaths = new ArrayList<>();
        boolean isReachable = false;
        for (List<String> vulnerableCodeExecutionPath : vulnerableCodeExecutionPaths) {
            for (String path : vulnerableCodeExecutionPath) {
                if (path.contains(Constants.APPLICATION_GROUP)) {
                    // This copy needs to happen to that the list reversal that happens later doesn't affect both lists
                    List<String> vulnerableCodeExecutionPathCopy = new ArrayList<>(vulnerableCodeExecutionPath);
                    reachableVulnerableCodePaths.add(vulnerableCodeExecutionPathCopy);
                    isReachable = true;
                    break;
                }
            }
            reachableVulnerableCodeExecutionPathsMap.put(vulnerableCode.data, reachableVulnerableCodePaths);
        }
        if (isReachable) {
            reachableVulnerableCodeExecutionMap.put(vulnerabilityId, reachableVulnerableCodeExecutionPathsMap);
        }
    }

    /**
     *
     * @param codeExecutionMap
     * @param filePath
     */
    private void writeCodeExecutionPaths(Map<String, Map<String, List<List<String>>>> codeExecutionMap, String filePath) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(filePath))) {
            for (Map.Entry<String, Map<String, List<List<String>>>> codeExecutionMapping : codeExecutionMap.entrySet()) {
                String vulnerabilityId = codeExecutionMapping.getKey();
                writer.write("Vulnerability ID: " + vulnerabilityId + "\n");
                Map<String, List<List<String>>> codeExecutionSubMap = codeExecutionMapping.getValue();
                for (Map.Entry<String, List<List<String>>> codeExecutionPathsMap : codeExecutionSubMap.entrySet()) {
                    String vulnerableCode = codeExecutionPathsMap.getKey();
                    writer.write("  Vulnerable Code: " + vulnerableCode + "\n");
                    List<List<String>> codeExecutionPaths = codeExecutionPathsMap.getValue();
                    if (!codeExecutionPaths.isEmpty()) {
                        for (List<String> codeExecutionPath : codeExecutionPaths) {
                            writer.write("      Execution Path: \n");
                            StringBuilder sb = new StringBuilder("          ");
                            Collections.reverse(codeExecutionPath);
                            for (String path : codeExecutionPath) {
                                sb.append(" ");
                                writer.write(sb + "->" + path + "\n");
                            }
                        }
                    }
                    else {
                        writer.write("      Execution Path: N/A \n");
                    }
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     *
     * @return callGraph
     */
    public static Map<String, Set<String>> getCallGraph() {
        return callGraph;
    }
}