//package com.lmco.crt;
//
//import org.objectweb.asm.*;
//import org.objectweb.asm.tree.*;
//
//import java.io.*;
//import java.util.*;
//import java.util.jar.JarEntry;
//import java.util.jar.JarFile;
//import java.util.stream.Collectors;
//
//public class MethodInterfaceMapper {
//
//    public static void main(String[] args) throws IOException {
//        String serviceJarPath = Constants.SERVICE_JAR_PATH;
//        String dependenciesJarPath = Constants.CRT_DEPENDENCIES_JAR_PATH;
//        //Map<String, List<String>> methodInterfaceMap = analyzeJarFile(jarFilePath);
//        analyzeJarFile(serviceJarPath);
//        analyzeJarFile(dependenciesJarPath);
//        analyzeClasses();
////        Constants.methodInterfaceMap.forEach((method, interfaces) -> {
////            System.out.println("Class Method: " + method);
////            interfaces.forEach(iface -> System.out.println("  Overrides Interface Method: " + iface));
////        });
//        Map<String, byte[]> classBytesMap = Constants.classBytesMap;
//        Map<String, List<String>> methodInterfaceMap = Constants.methodInterfaceMap;
//        Map<String, Set<String>> callGraph = Constants.callGraph;
//        modifyVulnerableCodeSources();
//        getVulnerableCodeExecutionPaths();
//        writeCodeExecutionPaths(Constants.vulnerableCodeExecutionMap, Constants.EXECUTION_PATHS_OUTPUT_DIR);
//        writeCodeExecutionPaths(Constants.reachableVulnerableCodeExecutionMap, Constants.REACHABLE_PATHS_OUTPUT_DIR);
//        System.out.println("breakpoint");
//    }
//
//    public static void analyzeJarFile(String jarFilePath) throws IOException {
//        Map<String, List<String>> methodInterfaceMap = new HashMap<>();
//
//        try (JarFile jarFile = new JarFile(jarFilePath)) {
//            Enumeration<JarEntry> entries = jarFile.entries();
//            while (entries.hasMoreElements()) {
//                JarEntry entry = entries.nextElement();
//                if (entry.getName().endsWith(".class")) {
//                    try (InputStream inputStream = jarFile.getInputStream(entry)) {
//                        byte[] classBytes = readAllBytes(inputStream);
//                        Constants.classBytesMap.put(entry.getName().replace(".class", ""), classBytes);
//                    }
//                }
//            }
//        }
//    }
//
//    public static void analyzeClasses() {
//        for (Map.Entry<String, byte[]> entry : Constants.classBytesMap.entrySet()) {
//            ClassReader classReader = new ClassReader(entry.getValue());
//            ClassNode classNode = new ClassNode();
//            classReader.accept(classNode, 0);
//
//            for (MethodNode methodNode : classNode.methods) {
//                String methodName = classNode.name + "." + methodNode.name + methodNode.desc;
//                Set<String> calledMethods = new HashSet<>();
//                //calledMethods.add(methodName);
//                if (methodNode.instructions != null) {
//                    for (AbstractInsnNode insn : methodNode.instructions) {
//                        if (insn.getType() == AbstractInsnNode.METHOD_INSN) {
//                            MethodInsnNode methodInsn = (MethodInsnNode) insn;
//                            calledMethods.add(methodInsn.owner + "." + methodInsn.name + methodInsn.desc);
//                        }
//                    }
//                }
//                if (classNode.interfaces != null) {
//                    List<String> interfaces = getOverriddenInterfaceMethods(Constants.classBytesMap, classNode, methodNode);
//                    if (!interfaces.isEmpty()) {
//                        Constants.methodInterfaceMap.put(classNode.name + "." + methodNode.name + methodNode.desc, interfaces);
//                    }
//                }
//                Constants.callGraph.put(methodName, calledMethods);
//            }
//        }
//    }
//
//
////    public static Map<String, List<String>> analyzeJarFile(String jarFilePath) throws IOException {
////        Map<String, List<String>> methodInterfaceMap = new HashMap<>();
////        Map<String, byte[]> classBytesMap = new HashMap<>();
////
////        try (JarFile jarFile = new JarFile(jarFilePath)) {
////            Enumeration<JarEntry> entries = jarFile.entries();
////            while (entries.hasMoreElements()) {
////                JarEntry entry = entries.nextElement();
////                if (entry.getName().endsWith(".class")) {
////                    try (InputStream inputStream = jarFile.getInputStream(entry)) {
////                        byte[] classBytes = readAllBytes(inputStream);
////                        classBytesMap.put(entry.getName().replace(".class", ""), classBytes);
////                    }
////                }
////            }
////        }
////
////        for (Map.Entry<String, byte[]> entry : classBytesMap.entrySet()) {
////            ClassReader classReader = new ClassReader(entry.getValue());
////            ClassNode classNode = new ClassNode();
////            classReader.accept(classNode, 0);
////
////            if (classNode.interfaces != null) {
////                for (MethodNode methodNode : classNode.methods) {
////                    List<String> interfaces = getOverriddenInterfaceMethods(classBytesMap, classNode, methodNode);
////                    if (!interfaces.isEmpty()) {
////                        Constants.methodInterfaceMap.put(classNode.name + "." + methodNode.name + methodNode.desc, interfaces);
////                        String methodName = classNode.name + "." + methodNode.name + methodNode.desc;
////                        if (methodName.contains("org/springframework/context/annotation/ConfigurationClassPostProcessor.postProcessBeanDefinitionRegistry(Lorg/springframework/beans/factory/support/BeanDefinitionRegistry;)V")) {
////                            System.out.println("breakpoint");
////                        }
////                    }
////                }
////            }
////        }
////
////        return methodInterfaceMap;
////    }
//
//    private static byte[] readAllBytes(InputStream inputStream) throws IOException {
//        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
//        int nRead;
//        byte[] data = new byte[16384];
//        while ((nRead = inputStream.read(data, 0, data.length)) != -1) {
//            buffer.write(data, 0, nRead);
//        }
//        buffer.flush();
//        return buffer.toByteArray();
//    }
//
//    private static List<String> getOverriddenInterfaceMethods(Map<String, byte[]> classBytesMap, ClassNode classNode, MethodNode methodNode) {
//        List<String> overriddenInterfaceMethods = new ArrayList<>();
//        for (String interfaceName : classNode.interfaces) {
//            byte[] interfaceBytes = classBytesMap.get(interfaceName);
//            if (interfaceBytes != null) {
//                try {
//                    ClassReader interfaceReader = new ClassReader(interfaceBytes);
//                    ClassNode interfaceNode = new ClassNode();
//                    interfaceReader.accept(interfaceNode, 0);
//
//                    for (MethodNode interfaceMethod : interfaceNode.methods) {
//                        if (methodNode.name.equals(interfaceMethod.name) && methodNode.desc.equals(interfaceMethod.desc)) {
//                            overriddenInterfaceMethods.add(interfaceName + "." + interfaceMethod.name + interfaceMethod.desc);
//                        }
//                    }
//                } catch (Exception e) {
//                    System.err.println("Failed to read interface: " + interfaceName);
//                    e.printStackTrace();
//                }
//            }
//        }
//        return overriddenInterfaceMethods;
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
//}
//