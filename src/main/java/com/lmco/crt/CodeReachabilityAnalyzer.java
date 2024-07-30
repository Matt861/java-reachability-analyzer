package com.lmco.crt;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.tree.*;

import java.io.*;
import java.util.*;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.stream.Collectors;

/**
 * Class that performs a static code analysis of a fat jar.
 * Generates all code execution paths to user inputted class/methods.
 * Determines if generated execution paths are reachable by the main application of the jar.
 */
public class CodeReachabilityAnalyzer {

    private static final Map<String, List<String>> TARGET_CODE_MAP = Utilities.readCsvFromResources(Constants.CSV_FILE_NAME);
    private static final Map<String, Set<String>> callGraph = new HashMap<>();
    private static final Set<String> allMethods = new HashSet<>();
    private static final Map<String, List<String>> modifiedTargetCodeMap = new HashMap<>(TARGET_CODE_MAP);
    protected static final Map<String, Map<String, List<List<String>>>> vulnerableCodeExecutionMap = new HashMap<>();
    protected static final Map<String, Map<String, List<List<String>>>> reachableVulnerableCodeExecutionMap = new HashMap<>();

    /**
     * Main execution:
     * 1) Read fat jar contents and create code call graph
     * 2) Modify user inputted class/method names to be more defined
     * 3) Use call graph to create a tree of vulnerable code execution paths
     * 4) Write all vulnerable execution paths to output file
     * 5) Write reachable vulnerable execution paths to output file
     * @param args None
     * @throws IOException N/A
     */
    public static void main(String[] args) throws IOException {
        File serviceJar = new File(Constants.SERVICE_JAR_PATH);
        File dependenciesJar = new File(Constants.CRT_DEPENDENCIES_JAR_PATH);
        File testDependenciesJar = new File(Constants.CRT_TEST_DEPENDENCIES_JAR_PATH);
        File classpathDependenciesJar = new File(Constants.CRT_CLASSPATH_DEPENDENCIES_JAR_PATH);
        CodeReachabilityAnalyzer analyzer = new CodeReachabilityAnalyzer();
        analyzer.analyzeJar(serviceJar);
        analyzer.analyzeJar(dependenciesJar);
        analyzer.analyzeJar(testDependenciesJar);
        analyzer.analyzeJar(classpathDependenciesJar);
        analyzer.modifyVulnerableCodeSources();
        analyzer.getVulnerableCodeExecutionPaths();
        analyzer.writeCodeExecutionPaths(vulnerableCodeExecutionMap, Constants.EXECUTION_PATHS_OUTPUT_DIR);
        analyzer.writeCodeExecutionPaths(reachableVulnerableCodeExecutionMap, Constants.REACHABLE_PATHS_OUTPUT_DIR);
    }

    private void handleAnnotations(ClassNode classNode) {
        if (classNode.visibleAnnotations != null) {
            for (AnnotationNode annotation : classNode.visibleAnnotations) {
                if (annotation.desc.contains("org/springframework/boot/autoconfigure/SpringBootApplication")) {
                    // Simulate the behavior of @SpringBootApplication
                    simulateSpringBootApplicationBehavior(classNode.name);
                }
                if (annotation.desc.contains("org/springframework/stereotype/Component")) {
                    // Handle @Component annotation
                    handleComponentAnnotation(classNode);
                }
            }
        }

        // Check for @Bean annotations on methods
        for (MethodNode method : classNode.methods) {
            if (method.visibleAnnotations != null) {
                for (AnnotationNode annotation : method.visibleAnnotations) {
                    if (annotation.desc.contains("org/springframework/context/annotation/Bean")) {
                        // Handle @Bean annotation
                        handleBeanAnnotation(classNode, method);
                    }
                }
            }
        }
    }

    private void handleComponentAnnotation(ClassNode classNode) {
        // Simulate component scanning and initialization
        String className = classNode.name;
        // Assuming @Component classes have a default constructor
        String constructorMethod = className + ".<init>()V";
        callGraph.computeIfAbsent("org/springframework/context/annotation/ClassPathBeanDefinitionScanner.scan", k -> new HashSet<>())
                .add(constructorMethod);
    }

    private void handleBeanAnnotation(ClassNode classNode, MethodNode method) {
        // Simulate bean initialization
        String methodName = classNode.name + "." + method.name + method.desc;
        callGraph.computeIfAbsent("org/springframework/context/annotation/ConfigurationClassBeanDefinitionReader.loadBeanDefinitionsForBeanMethod", k -> new HashSet<>())
                .add(methodName);
    }

    private void simulateSpringBootApplicationBehavior(String className) {
        // Simulate SpringApplication.run
        String springApplicationRunMethod = "org/springframework/boot/SpringApplication.run";
        String runSignature = "(Ljava/lang/Class;[Ljava/lang/String;)Lorg/springframework/context/ConfigurableApplicationContext;";
        callGraph.computeIfAbsent(className + ".<init>()V", k -> new HashSet<>())
                .add(springApplicationRunMethod + runSignature);
    }

    /**
     * Loops fat jar file contents to find all classes and sends
     * the classes to the anaylzeClass method for further analysis.
     * @param jarFile Fat jar containing source code and dependency source code
     * @throws IOException N/A
     */
    protected void analyzeJar(File jarFile) throws IOException {
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
     * Retrieve all methods from the class and adds them as keys to the callGraph.
     * Additionally, retrieves all called methods, constructors, etc. from the classes methods
     * and adds them as values to the callGraph.
     * @param jar Fat jar containing source code and dependency source code
     * @param entry Class file from jar
     * @throws IOException N/A
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

            // Handle specific annotations
            handleAnnotations(classNode);
        }
    }

    /**
     * Takes user inputted class/methods and retrieves matching
     * class/methods from the allMethods data structure.  The retrieved
     * class/methods are used for evaluation in place of the user inputted class/methods.
     */
    protected void modifyVulnerableCodeSources() {
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
     * Searches allMethods data structure for class/methods that match
     * the class/method parameters
     * @param className Name of class being evaluated for execution paths
     * @param methodName Name of method being evaluated for execution paths
     * @return Matching class/methods
     */
    public static List<String> findMethodsByClassAndName(String className, String methodName) {
        return allMethods.stream().filter(method -> method.startsWith(className + ".") &&
                (methodName == null || methodName.isEmpty() ||
                        method.contains("." + methodName + "("))).collect(Collectors.toList());
    }

    /**
     * Creates code execution paths for the class/methods in the fat jar
     * that match the user inputted class/methods
     */
    protected void getVulnerableCodeExecutionPaths() {
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
     * Determines if a code execution path is reachable by the main application.
     * The logic is if a class/method in the execution path derives from the main application,
     * then the execution path is reachable.
     * @param vulnerableCodeExecutionPaths List of class/methods that are linked together to form a path of code execution
     * @param vulnerableCode class/method that contains vulnerable code
     * @param vulnerabilityId ID of the vulnerability that has a compromised class/method being evaluated
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
     * Writes vulnerable code execution paths to a text file
     * @param codeExecutionMap Map that links Vulnerability Id, vulnerable code, and vulnerable code execution paths together
     * @param filePath Directory of the generated text file
     */
    protected void writeCodeExecutionPaths(Map<String, Map<String, List<List<String>>>> codeExecutionMap, String filePath) {
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
     * Getter method for callGraph
     * @return callGraph
     */
    public static Map<String, Set<String>> getCallGraph() {
        return callGraph;
    }
}