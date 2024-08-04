//package com.lmco.crt;
//
//import org.objectweb.asm.ClassReader;
//import org.objectweb.asm.Opcodes;
//import org.objectweb.asm.tree.*;
//
//import java.io.*;
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
//public class CodeReachabilityAnalyzer {
//
//    private static final Map<String, List<String>> TARGET_CODE_MAP = Utilities.readCsvFromResources(Constants.CSV_FILE_NAME);
//    private static final Map<String, Set<String>> callGraph = new HashMap<>();
//    //private static final Set<String> allMethods = new HashSet<>();
//    private static final Map<String, List<String>> modifiedTargetCodeMap = new HashMap<>(TARGET_CODE_MAP);
//    protected static final Map<String, Map<String, List<List<String>>>> vulnerableCodeExecutionMap = new HashMap<>();
//    protected static final Map<String, Map<String, List<List<String>>>> reachableVulnerableCodeExecutionMap = new HashMap<>();
//    private static final Map<String, Set<String>> interfaceImplementations = new HashMap<>();
//    private static final Map<String, Set<String>> overriddenMethods = new HashMap<>();
//    private static final Map<String, String> interfaceMap = new HashMap<>();
//    private static final List<String> interfaces = new ArrayList<>();
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
//        CodeReachabilityAnalyzer analyzer = new CodeReachabilityAnalyzer();
//        analyzer.analyzeJar(serviceJar, true);
//        analyzer.analyzeJar(dependenciesJar, false);
//        //analyzer.analyzeJar(classpathDependenciesJar, false);
//        //analyzer.analyzeJar(testDependenciesJar, false);
//        //analyzer.readCallGraphFromGzipFile("input\\CallGraph.csv.gz");
//        //analyzer.writeCallGraphToGzipFile("input\\CallGraph.csv.gz");
//        analyzer.modifyVulnerableCodeSources();
//        analyzer.getVulnerableCodeExecutionPaths();
//        analyzer.writeCodeExecutionPaths(vulnerableCodeExecutionMap, Constants.EXECUTION_PATHS_OUTPUT_DIR);
//        analyzer.writeCodeExecutionPaths(reachableVulnerableCodeExecutionMap, Constants.REACHABLE_PATHS_OUTPUT_DIR);
//        for (Map.Entry<String, Set<String>> entry : interfaceImplementations.entrySet()) {
//            String key = entry.getKey();
//            Set<String> values = entry.getValue();
//
//            if (key.contains("postProcessBeanDefinitionRegistry")) {
//                System.out.println("breakpoint");
//            } else if (values.contains("postProcessBeanDefinitionRegistry")) {
//                System.out.println("breakpoint");
//            }
//        }
//
//        System.out.println("breakpoint");
//    }
//
//    /**
//     * Loops fat jar file contents to find all classes and sends
//     * the classes to the anaylzeClass method for further analysis.
//     * @param jarFile Fat jar containing source code and dependency source code
//     * @throws IOException N/A
//     */
//    protected void analyzeJar(File jarFile, Boolean analyzeAnnotations) throws IOException {
//        try (JarFile jar = new JarFile(jarFile)) {
//            Enumeration<JarEntry> entries = jar.entries();
//            while (entries.hasMoreElements()) {
//                JarEntry entry = entries.nextElement();
//                if (entry.getName().endsWith(".class") && !entry.getName().contains("META-INF/")) {
//                    try {
//                        analyzeClass(jar, entry, analyzeAnnotations);
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
//    private void analyzeClass(JarFile jar, JarEntry entry, Boolean analyzeAnnotations) throws IOException {
//        try (InputStream inputStream = jar.getInputStream(entry)) {
//            ClassReader classReader = new ClassReader(inputStream);
//            ClassNode classNode = new ClassNode();
//            classReader.accept(classNode, 0);
//
////            if (classNode.name.contains("BeanDefinitionRegistryPostProcessor")) {
////                System.out.println("breakpoint");
////            }
//
//            boolean isInterface = (classNode.access & Opcodes.ACC_INTERFACE) != 0;
//
//            for (MethodNode method : classNode.methods) {
//                String methodName = classNode.name + "." + method.name + method.desc;
//                String interfaceName = null;
//                //allMethods.add(methodName);
//                // Record overridden methods
//                if (methodName.contains("org/springframework/context/annotation/ConfigurationClassPostProcessor.postProcessBeanDefinitionRegistry(Lorg/springframework/beans/factory/support/BeanDefinitionRegistry;)V")) {
//                    System.out.println("breakpoint");
//                    //findInterfaceOfMethod(classNode, method);
//                    //interfaceName = findMethodInInterfaces(jar, classNode, method);
//                    //interfaceMap.put(methodName, interfaceName);
//                }
//                if (methodName.contains("org/springframework/beans/factory/support/BeanDefinitionRegistryPostProcessor.postProcessBeanDefinitionRegistry(Lorg/springframework/beans/factory/support/BeanDefinitionRegistry;)V")) {
//                    System.out.println("breakpoint");
//                    //findInterfaceOfMethod(classNode, method);
//                    //interfaceName = findMethodInInterfaces(jar, classNode, method);
//                    //interfaceMap.put(methodName, interfaceName);
//                }
//                if (isInterface) {
//                    interfaces.add(classNode.name + "." + method.name + method.desc);
//                }
//
//                collectOverriddenMethods(classNode, method);
//                Set<String> calledMethods = new HashSet<>();
//                if (method.instructions != null) {
//                    for (AbstractInsnNode insn : method.instructions) {
//                        if (insn.getType() == AbstractInsnNode.METHOD_INSN) {
//                            MethodInsnNode methodInsn = (MethodInsnNode) insn;
//                            calledMethods.add(methodInsn.owner + "." + methodInsn.name + methodInsn.desc);
//                        }
//                    }
//                }
//
//                callGraph.put(methodName, calledMethods);
////                if (interfaceName == null) {
////                    callGraph.put(methodName, calledMethods);
////                }
////                else {
////                    callGraph.put(interfaceName, calledMethods);
////                }
//
//            }
//
////            if (isInterface) {
////                for (String interfaceName2 : classNode.interfaces) {
////                    interfaceImplementations.computeIfAbsent(interfaceName2, k -> new HashSet<>()).add(classNode.name);
////                }
////            }
//        }
//    }
//
//    private static void findInterfaceOfMethod(ClassNode classNode, MethodNode method) {
//        for (String interfaceName : classNode.interfaces) {
//            if (method.name.equals(interfaceName)) {
//                String fullInterfaceName = interfaceName + "." + method.name + method.desc;
//                interfaceMap.put(method.name, fullInterfaceName);
//                System.out.println("Found interface: " + fullInterfaceName);
//            }
//        }
//    }
//
//    private static String findMethodInInterfaces(JarFile jar, ClassNode classNode, MethodNode method) {
//        for (String interfaceName : classNode.interfaces) {
//            try {
//                // Debugging information
//                System.out.println("Attempting to load interface: " + interfaceName);
//
//                // Load the interface class from the JAR file
//                ClassNode interfaceNode = loadInterfaceFromJar(jar, interfaceName + ".class");
//                for (MethodNode interfaceMethod : interfaceNode.methods) {
//                    if (method.name.equals(interfaceMethod.name) && method.desc.equals(interfaceMethod.desc)) {
//                        System.out.println("Found in interface: " + interfaceNode.name);
//                        return interfaceName + "." + interfaceMethod.name + interfaceMethod.desc;
//                    }
//                }
//            } catch (IOException e) {
//                System.err.println("Failed to load interface: " + interfaceName);
//                e.printStackTrace();
//            }
//        }
//        return null;
//    }
//
//    private static ClassNode loadInterfaceFromJar(JarFile jar, String classFilePath) throws IOException {
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
//            throw new RuntimeException(e);
//        }
//    }
//
//    private void collectOverriddenMethods(ClassNode classNode, MethodNode method) {
//        if (classNode.superName != null) {
//            String superClassName = classNode.superName;
//            String superMethod = superClassName + "." + method.name + method.desc;
//            overriddenMethods.computeIfAbsent(superMethod, k -> new HashSet<>()).add(classNode.name + "." + method.name + method.desc);
//        }
//        for (String interfaceName : classNode.interfaces) {
//            String interfaceMethod = interfaceName + "." + method.name + method.desc;
//            overriddenMethods.computeIfAbsent(interfaceMethod, k -> new HashSet<>()).add(classNode.name + "." + method.name + method.desc);
//        }
//    }
//
//    /**
//     * Takes user inputted class/methods and retrieves matching
//     * class/methods from the allMethods data structure.  The retrieved
//     * class/methods are used for evaluation in place of the user inputted class/methods.
//     */
//    protected void modifyVulnerableCodeSources() {
//        for (Map.Entry<String, List<String>> targetMapEntry : modifiedTargetCodeMap.entrySet()) {
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
//            modifiedTargetCodeMap.put(vulnerabilityId, updatedCodeTargets);
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
//        return callGraph.keySet().stream().filter(method -> method.startsWith(className + ".") &&
//                (methodName == null || methodName.isEmpty() ||
//                        method.contains("." + methodName + "("))).collect(Collectors.toList());
//    }
//
//    /**
//     * Creates code execution paths for the class/methods in the fat jar
//     * that match the user inputted class/methods
//     */
//    protected void getVulnerableCodeExecutionPaths() {
//        for (Map.Entry<String, List<String>> codeTargetMapEntry : modifiedTargetCodeMap.entrySet()) {
//            Map<String, List<List<String>>> vulnerableCodeExecutionPathsMap = new HashMap<>();
//            String vulnerabilityId = codeTargetMapEntry.getKey();
//            List<String> codeTargets = codeTargetMapEntry.getValue();
//            for (String codeTarget : codeTargets) {
//                System.out.println("Getting execution paths for: " + codeTarget);
//                TreeNode<String> vulnerableCode = new TreeNode<>(codeTarget);
//                long startTime = System.nanoTime();
//                TreeUtil.createVulnerableCodeExecutionTree(vulnerableCode);
//                long endTime = System.nanoTime();
//                long duration = endTime - startTime;
//                System.out.println("Execution time in milliseconds: " + (duration / 1_000_000));
//                List<List<String>> vulnerableCodeExecutionPaths = TreeUtil.retrieveVulnerableCodeExecutionPathsFromTree(vulnerableCode);
//                getReachableVulnerableCodeExecutionPaths(vulnerableCodeExecutionPaths, vulnerableCode, vulnerabilityId);
//                vulnerableCodeExecutionPathsMap.put(vulnerableCode.data, vulnerableCodeExecutionPaths);
//            }
//            vulnerableCodeExecutionMap.put(vulnerabilityId, vulnerableCodeExecutionPathsMap);
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
//    private void getReachableVulnerableCodeExecutionPaths(List<List<String>> vulnerableCodeExecutionPaths, TreeNode<String> vulnerableCode, String vulnerabilityId) {
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
//            reachableVulnerableCodeExecutionPathsMap.put(vulnerableCode.data, reachableVulnerableCodePaths);
//        }
//        if (isReachable) {
//            reachableVulnerableCodeExecutionMap.put(vulnerabilityId, reachableVulnerableCodeExecutionPathsMap);
//        }
//    }
//
//    /**
//     * Writes vulnerable code execution paths to a text file
//     * @param codeExecutionMap Map that links Vulnerability Id, vulnerable code, and vulnerable code execution paths together
//     * @param filePath Directory of the generated text file
//     */
//    protected void writeCodeExecutionPaths(Map<String, Map<String, List<List<String>>>> codeExecutionMap, String filePath) {
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
//     * Getter method for callGraph
//     * @return callGraph
//     */
//    public static Map<String, Set<String>> getCallGraph() {
//        return callGraph;
//    }
//
//    public static Map<String, Set<String>> getInterfaceImplementations() {
//        return interfaceImplementations;
//    }
//
//    public static Map<String, Set<String>> getOverriddenMethods() {
//        return overriddenMethods;
//    }
//
//    public static Map<String, String> getInterfaceMap() {
//        return interfaceMap;
//    }
//
//    /**
//     *
//     * @param filename
//     * @return
//     * @throws IOException
//     */
//    public Map<String, Set<String>> readCallGraphFromGzipFile(String filename) throws IOException {
//        Map<String, Set<String>> newCallGraph = new HashMap<>();
//        try (GZIPInputStream gzipInputStream = new GZIPInputStream(new FileInputStream(filename));
//             BufferedReader reader = new BufferedReader(new InputStreamReader(gzipInputStream))) {
//            String line;
//            while ((line = reader.readLine()) != null) {
//                String[] parts = line.split(",", 2);
//                if (parts.length == 2) {
//                    String key = parts[0];
//                    String value = parts[1];
//                    callGraph.computeIfAbsent(key, k -> new HashSet<>()).add(value);
//                }
//            }
//        }
//        return newCallGraph;
//    }
//
//    /**
//     *
//     * @param filename
//     * @throws IOException
//     */
//    private void writeCallGraphToGzipFile(String filename) throws IOException {
//        try (GZIPOutputStream gzipOutputStream = new GZIPOutputStream(new FileOutputStream(filename));
//             BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(gzipOutputStream))) {
//            for (Map.Entry<String, Set<String>> entry : callGraph.entrySet()) {
//                String key = entry.getKey();
//                for (String value : entry.getValue()) {
//                    writer.write(key + "," + value + "\n");
//                }
//            }
//        }
//    }
//}