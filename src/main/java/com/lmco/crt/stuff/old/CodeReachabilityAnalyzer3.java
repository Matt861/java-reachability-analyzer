//package com.lmco.crt.stuff.old;
//
//import com.lmco.crt.Constants;
//import com.lmco.crt.TreeNode;
//import com.lmco.crt.TreeUtil;
//import org.objectweb.asm.ClassReader;
//import org.objectweb.asm.ClassVisitor;
//import org.objectweb.asm.ClassWriter;
//import org.objectweb.asm.Opcodes;
//import org.objectweb.asm.tree.*;
//
//import java.io.*;
//import java.nio.file.Files;
//import java.nio.file.Paths;
//import java.util.*;
//import java.util.jar.JarEntry;
//import java.util.jar.JarFile;
//import java.util.stream.Collectors;
//import java.util.zip.GZIPInputStream;
//import java.util.zip.GZIPOutputStream;
//
///**
// * Class that performs a static code analysis of a fat jar.
// * Generates all code execution paths to user inputted class/methods.
// * Determines if generated execution paths are reachable by the main application of the jar.
// */
//public class CodeReachabilityAnalyzer3 {
//
//    /**
//     * Main execution:
//     * 1) Read fat jar contents and create code call graph
//     * 2) Modify user inputted class/method names to be more defined
//     * 3) Use call graph to create a tree of vulnerable code execution paths
//     * 4) Write all vulnerable execution paths to output file
//     * 5) Write reachable vulnerable execution paths to output file
//     * @param args None
//     * @throws IOException N/A
//     */
//    public static void main(String[] args) throws IOException {
//        File serviceJar = new File(Constants.SERVICE_JAR_PATH);
//        File dependenciesJar = new File(Constants.CRT_DEPENDENCIES_JAR_PATH);
//        File testDependenciesJar = new File(Constants.CRT_TEST_DEPENDENCIES_JAR_PATH);
//        File classpathDependenciesJar = new File(Constants.CRT_CLASSPATH_DEPENDENCIES_JAR_PATH);
//        analyzeJar(serviceJar);
//        analyzeJar(dependenciesJar);
//        //analyzeJar(classpathDependenciesJar);
//        //analyzeJar(testDependenciesJar);
//        //readCallGraphFromGzipFile("input\\CallGraph.csv.gz");
//        //writeCallGraphToGzipFile("input\\CallGraph.csv.gz");
//        modifyVulnerableCodeSources();
//        getVulnerableCodeExecutionPaths();
//        writeCodeExecutionPaths(Constants.vulnerableCodeExecutionMap, Constants.EXECUTION_PATHS_OUTPUT_DIR);
//        writeCodeExecutionPaths(Constants.reachableVulnerableCodeExecutionMap, Constants.REACHABLE_PATHS_OUTPUT_DIR);
//        System.out.println("breakpoint");
//    }
//
//    /**
//     * Loops fat jar file contents to find all classes and sends
//     * the classes to the anaylzeClass method for further analysis.
//     * @param jarFile Fat jar containing source code and dependency source code
//     * @throws IOException N/A
//     */
//    protected static void analyzeJar(File jarFile) throws IOException {
//        try (JarFile jar = new JarFile(jarFile)) {
//            Enumeration<JarEntry> entries = jar.entries();
//            while (entries.hasMoreElements()) {
//                JarEntry entry = entries.nextElement();
//                if (entry.getName().endsWith(".class") && !entry.getName().contains("META-INF/")) {
//                    try {
//                        analyzeClass(jar, entry);
//                    } catch (SecurityException | IOException e) {
//                        System.err.println("Skipping entry due to error: " + entry.getName() + " - " + e.getMessage());
//                    }
//                }
//            }
//        }
//    }
//
//    /**
//     * Retrieve all methods from the class and adds them as keys to the callGraph.
//     * Additionally, retrieves all called methods, constructors, etc. from the classes methods
//     * and adds them as values to the callGraph.
//     * @param jar Fat jar containing source code and dependency source code
//     * @param entry Class file from jar
//     * @throws IOException N/A
//     */
//    protected static void analyzeClass(JarFile jar, JarEntry entry) throws IOException {
//        Map<String, List<String>> methodInterfaceMap = new HashMap<>();
//        try (InputStream inputStream = jar.getInputStream(entry)) {
//            ClassReader classReader = new ClassReader(inputStream);
//            ClassNode classNode = new ClassNode();
//            classReader.accept(classNode, 0);
//            boolean isInterface = (classNode.access & Opcodes.ACC_INTERFACE) != 0;
//            boolean isSuper = classNode.superName != null;
//
//            for (MethodNode method : classNode.methods) {
//                String methodName = classNode.name + "." + method.name + method.desc;
//
////                if (isSuper) {
////                    supers.add(methodName);
////                }
//
//                Set<String> calledMethods = new HashSet<>();
//                if (method.instructions != null) {
//                    for (AbstractInsnNode insn : method.instructions) {
//                        if (insn.getType() == AbstractInsnNode.METHOD_INSN) {
//                            MethodInsnNode methodInsn = (MethodInsnNode) insn;
//                            calledMethods.add(methodInsn.owner + "." + methodInsn.name + methodInsn.desc);
//                            if (!classNode.interfaces.isEmpty() && !Constants.interfaceMap.containsKey(methodName)) {
//                                tryMapInterfaceToMethod(jar, classNode, method);
//                            }
//                        }
//                    }
//                }
//
//                Constants.callGraph.put(methodName, calledMethods);
//            }
//        }
//    }
//
//    private static boolean isJavaStandardLibrary(String internalName) {
//        return internalName.startsWith("java/") || internalName.startsWith("javax/")
//                || internalName.startsWith("jdk/") || internalName.startsWith("sun/")
//                || internalName.startsWith("com/oracle/jrockit/jfr/") || internalName.startsWith("oracle/jrockit/jfr/")
//                || internalName.startsWith("oracle/deploy/update/") || internalName.startsWith("javafx/");
//    }
//
//    protected static void tryMapInterfaceToMethod(JarFile jar, ClassNode classNode, MethodNode method) {
//        for (String interfaceName : classNode.interfaces) {
//            try {
//                // Debugging information
//                //.out.println("Attempting to load interface: " + interfaceName);
//                if (isJavaStandardLibrary(interfaceName)) {
//                    // Skip interfaces from standard Java library
//                    continue;
//                }
//
//                // Load the interface class from the JAR file
//                ClassNode interfaceNode = loadInterfaceFromJar(jar, interfaceName + ".class");
//                if (interfaceNode != null) {
//                    for (MethodNode interfaceMethod : interfaceNode.methods) {
//                        if (method.name.equals(interfaceMethod.name) && method.desc.equals(interfaceMethod.desc)) {
//                            //System.out.println("Found in interface: " + interfaceNode.name);
//                            String fullInterfaceName = interfaceName + "." + interfaceMethod.name + interfaceMethod.desc;
//                            String fullMethodName = classNode.name + "." + method.name + method.desc;
//                            Constants.interfaceMap.put(fullMethodName, fullInterfaceName);
//                        }
//                    }
//                }
//            } catch (IOException e) {
//                System.err.println("Failed to load interface: " + interfaceName);
//                e.printStackTrace();
//            }
//        }
//    }
//
//    protected static ClassNode loadInterfaceFromJar(JarFile jar, String classFilePath) throws IOException {
//        try {
//            JarEntry entry = jar.getJarEntry(classFilePath);
//            if (entry == null) {
//                throw new IOException("Class not found: " + classFilePath);
//            }
//
//            try (InputStream classStream = jar.getInputStream(entry)) {
//                ClassReader classReader = new ClassReader(classStream);
//                ClassNode classNode = new ClassNode();
//                classReader.accept(classNode, 0);
//                return classNode;
//            }
//        } catch (IOException e) {
//            System.out.println("Failed to load interface: " + classFilePath);
//            return null;
//        }
//    }
//
//    /**
//     * Takes user inputted class/methods and retrieves matching
//     * class/methods from the allMethods data structure.  The retrieved
//     * class/methods are used for evaluation in place of the user inputted class/methods.
//     */
//    protected static void modifyVulnerableCodeSources() {
//        for (Map.Entry<String, List<String>> targetMapEntry : Constants.modifiedTargetCodeMap.entrySet()) {
//            List<String> updatedCodeTargets = new ArrayList<>();
//            String vulnerabilityId = targetMapEntry.getKey();
//            List<String> codeTargets = targetMapEntry.getValue();
//            for (String target : codeTargets) {
//                List<String> newCodeTargets;
//                // Target code is a class and a method
//                if (target.contains(".")) {
//                    String[] codeTargetParts = target.split("\\.");
//                    newCodeTargets = findMethodsByClassAndName(codeTargetParts[0], codeTargetParts[1]);
//                }
//                // Target code is an entire class
//                else {
//                    newCodeTargets = findMethodsByClassAndName(target, null);
//                }
//                updatedCodeTargets.addAll(newCodeTargets);
//            }
//            Constants.modifiedTargetCodeMap.put(vulnerabilityId, updatedCodeTargets);
//        }
//    }
//
//    /**
//     * Searches allMethods data structure for class/methods that match
//     * the class/method parameters
//     * @param className Name of class being evaluated for execution paths
//     * @param methodName Name of method being evaluated for execution paths
//     * @return Matching class/methods
//     */
//    public static List<String> findMethodsByClassAndName(String className, String methodName) {
//        return Constants.callGraph.keySet().stream().filter(method -> method.startsWith(className + ".") &&
//                (methodName == null || methodName.isEmpty() ||
//                        method.contains("." + methodName + "("))).collect(Collectors.toList());
//    }
//
//    /**
//     * Creates code execution paths for the class/methods in the fat jar
//     * that match the user inputted class/methods
//     */
//    protected static void getVulnerableCodeExecutionPaths() {
//        for (Map.Entry<String, List<String>> codeTargetMapEntry : Constants.modifiedTargetCodeMap.entrySet()) {
//            Map<String, List<List<String>>> vulnerableCodeExecutionPathsMap = new HashMap<>();
//            String vulnerabilityId = codeTargetMapEntry.getKey();
//            List<String> codeTargets = codeTargetMapEntry.getValue();
//            for (String codeTarget : codeTargets) {
//                System.out.println("Getting execution paths for: " + codeTarget);
//                //TreeNode<String> vulnerableCode = new TreeNode<>(codeTarget);
//                long startTime = System.nanoTime();
//                TreeNode<String> vulnerableCode = TreeUtil.createVulnerableCodeExecutionTree(codeTarget);
//                long endTime = System.nanoTime();
//                long duration = endTime - startTime;
//                System.out.println("Execution time in milliseconds: " + (duration / 1_000_000));
//                List<List<String>> vulnerableCodeExecutionPaths = TreeUtil.retrieveVulnerableCodeExecutionPathsFromTree(vulnerableCode);
//                getReachableVulnerableCodeExecutionPaths(vulnerableCodeExecutionPaths, codeTarget, vulnerabilityId);
//                vulnerableCodeExecutionPathsMap.put(codeTarget, vulnerableCodeExecutionPaths);
//            }
//            Constants.vulnerableCodeExecutionMap.put(vulnerabilityId, vulnerableCodeExecutionPathsMap);
//        }
//    }
//
//    /**
//     * Determines if a code execution path is reachable by the main application.
//     * The logic is if a class/method in the execution path derives from the main application,
//     * then the execution path is reachable.
//     * @param vulnerableCodeExecutionPaths List of class/methods that are linked together to form a path of code execution
//     * @param vulnerableCode class/method that contains vulnerable code
//     * @param vulnerabilityId ID of the vulnerability that has a compromised class/method being evaluated
//     */
//    protected static void getReachableVulnerableCodeExecutionPaths(List<List<String>> vulnerableCodeExecutionPaths, String vulnerableCode, String vulnerabilityId) {
//        Map<String, List<List<String>>> reachableVulnerableCodeExecutionPathsMap = new HashMap<>();
//        List<List<String>> reachableVulnerableCodePaths = new ArrayList<>();
//        boolean isReachable = false;
//        for (List<String> vulnerableCodeExecutionPath : vulnerableCodeExecutionPaths) {
//            for (String path : vulnerableCodeExecutionPath) {
//                if (path.contains(Constants.APPLICATION_GROUP)) {
//                    // This copy needs to happen to that the list reversal that happens later doesn't affect both lists
//                    List<String> vulnerableCodeExecutionPathCopy = new ArrayList<>(vulnerableCodeExecutionPath);
//                    reachableVulnerableCodePaths.add(vulnerableCodeExecutionPathCopy);
//                    isReachable = true;
//                    break;
//                }
//            }
//            reachableVulnerableCodeExecutionPathsMap.put(vulnerableCode, reachableVulnerableCodePaths);
//        }
//        if (isReachable) {
//            Constants.reachableVulnerableCodeExecutionMap.put(vulnerabilityId, reachableVulnerableCodeExecutionPathsMap);
//        }
//    }
//
//    /**
//     * Writes vulnerable code execution paths to a text file
//     * @param codeExecutionMap Map that links Vulnerability Id, vulnerable code, and vulnerable code execution paths together
//     * @param filePath Directory of the generated text file
//     */
//    protected static void writeCodeExecutionPaths(Map<String, Map<String, List<List<String>>>> codeExecutionMap, String filePath) {
//        try (BufferedWriter writer = new BufferedWriter(new FileWriter(filePath))) {
//            for (Map.Entry<String, Map<String, List<List<String>>>> codeExecutionMapping : codeExecutionMap.entrySet()) {
//                String vulnerabilityId = codeExecutionMapping.getKey();
//                writer.write("Vulnerability ID: " + vulnerabilityId + "\n");
//                Map<String, List<List<String>>> codeExecutionSubMap = codeExecutionMapping.getValue();
//                for (Map.Entry<String, List<List<String>>> codeExecutionPathsMap : codeExecutionSubMap.entrySet()) {
//                    String vulnerableCode = codeExecutionPathsMap.getKey();
//                    writer.write("  Vulnerable Code: " + vulnerableCode + "\n");
//                    List<List<String>> codeExecutionPaths = codeExecutionPathsMap.getValue();
//                    if (!codeExecutionPaths.isEmpty()) {
//                        for (List<String> codeExecutionPath : codeExecutionPaths) {
//                            writer.write("      Execution Path: \n");
//                            StringBuilder sb = new StringBuilder("          ");
//                            Collections.reverse(codeExecutionPath);
//                            for (String path : codeExecutionPath) {
//                                sb.append(" ");
//                                writer.write(sb + "->" + path + "\n");
//                            }
//                        }
//                    }
//                    else {
//                        writer.write("      Execution Path: N/A \n");
//                    }
//                }
//            }
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
//    }
//
//    /**
//     *
//     * @param filename
//     * @return
//     * @throws IOException
//     */
//    public static void readCallGraphFromGzipFile(String filename) throws IOException {
//        try (GZIPInputStream gzipInputStream = new GZIPInputStream(Files.newInputStream(Paths.get(filename)));
//             BufferedReader reader = new BufferedReader(new InputStreamReader(gzipInputStream))) {
//            String line;
//            while ((line = reader.readLine()) != null) {
//                String[] parts = line.split(",", 2);
//                if (parts.length == 2) {
//                    String key = parts[0];
//                    String value = parts[1];
//                    Constants.callGraph.computeIfAbsent(key, k -> new HashSet<>()).add(value);
//                }
//            }
//        }
//    }
//
//    /**
//     *
//     * @param filename
//     * @throws IOException
//     */
//    public static void writeCallGraphToGzipFile(String filename) throws IOException {
//        try (GZIPOutputStream gzipOutputStream = new GZIPOutputStream(new FileOutputStream(filename));
//             BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(gzipOutputStream))) {
//            for (Map.Entry<String, Set<String>> entry : Constants.callGraph.entrySet()) {
//                String key = entry.getKey();
//                for (String value : entry.getValue()) {
//                    writer.write(key + "," + value + "\n");
//                }
//            }
//        }
//    }
//}