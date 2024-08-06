package com.lmco.crt;

import java.util.*;

public class TreeUtil {
    private static final Map<String, TreeNode<String>> memorizedTrees = new HashMap<>();
    private static final Set<String> visitedNodes = new HashSet<>();

    /**
     *
     * @param vulnerableCode
     * @return
     */
    public static List<List<String>> retrieveVulnerableCodeExecutionPathsFromTree(TreeNode<String> vulnerableCode) {
        List<List<String>> result = new ArrayList<>();
        if (vulnerableCode == null) {
            return result;
        }

        List<String> currentPath = new ArrayList<>();
        depthFirstSearch(vulnerableCode, currentPath, result);
        return result;
    }

    /**
     *
     * @param vulnerableCode
     * @param currentPath
     * @param result
     */
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

    /**
     *
     * @param codeTarget
     * @return
     */
    public static TreeNode<String> createVulnerableCodeExecutionTree(String codeTarget) {
        // Clear the visitedNodes and memorizedTrees before starting the recursive method
        visitedNodes.clear();
        memorizedTrees.clear();

        TreeNode<String> vulnerableCode = null;
        boolean isInterfaceMapping = false;
        for (Map.Entry<String, List<String>> entry : Constants.methodInterfaceMap.entrySet()) {
            String key = entry.getKey();
            List<String> values = entry.getValue();
            if (values.contains(codeTarget)) {
                vulnerableCode = new TreeNode<>(codeTarget, true);
                createVulnerableCodeExecutionTreeRecursive(vulnerableCode, 0, true);
                isInterfaceMapping = true;
                break;
            }
            // Condition to check if tree starts with a method overridden by an interface
            else if (key.equals(codeTarget)) {
                if (!values.isEmpty()) {
                    vulnerableCode = new TreeNode<>(codeTarget, false);
                    for (String interfaceName : Constants.methodInterfaceMap.get(codeTarget)) {
                        TreeNode<String> child = vulnerableCode.addChild(interfaceName, true);
                        createVulnerableCodeExecutionTreeRecursive(child, 0, true);
                        isInterfaceMapping = true;
                    }
                    break;
                }
            }
        }
        if (!isInterfaceMapping) {
            vulnerableCode = new TreeNode<>(codeTarget, false);
            createVulnerableCodeExecutionTreeRecursive(vulnerableCode, 0, false);
        }

        return vulnerableCode;
    }

    /**
     *
     * @param vulnerableCode
     * @param depth
     * @param isInterface
     */
    public static void createVulnerableCodeExecutionTreeRecursive(TreeNode<String> vulnerableCode, int depth, Boolean isInterface) {

        if (vulnerableCode.data.equals("org/apache/commons/compress/archivers/zip/ZipArchiveInputStream.bufferContainsSignature(Ljava/io/ByteArrayOutputStream;III)Z")) {
            System.out.println("breakpoint");
        }

        // Avoid infinite loops by checking visited nodes first
        if (visitedNodes.contains(vulnerableCode.data)) {
            return;
        }

        visitedNodes.add(vulnerableCode.data);

        // Check for memoized results
        if (memorizedTrees.containsKey(vulnerableCode.data)) {
            TreeNode<String> memorizedSubtree = cloneTree(memorizedTrees.get(vulnerableCode.data));
            for (TreeNode<String> child : memorizedSubtree.children) {
                if (!vulnerableCode.containsChild(child.data)) {
                    vulnerableCode.addChild(String.valueOf(cloneTree(child)), isInterface);
                }
            }
            return;
        }

        for (Map.Entry<String, Set<String>> entry : Constants.callGraph.entrySet()) {
            String callingCode = entry.getKey();
            if (entry.getValue().contains(vulnerableCode.data)) {
                // Get the interface for a method
                if (Constants.methodInterfaceMap.containsKey(callingCode)) {
                    if (Constants.methodInterfaceMap.get(callingCode).size() > 1) {
                        System.out.println("Method has multiple interfaces");
                    }
                    for (String interfaceName : Constants.methodInterfaceMap.get(callingCode)) {
                        TreeNode<String> child = vulnerableCode.addChild(interfaceName, true);
                        createVulnerableCodeExecutionTreeRecursive(child, depth + 1, true);
                    }
                }
                TreeNode<String> child = vulnerableCode.addChild(callingCode, false);
                createVulnerableCodeExecutionTreeRecursive(child, depth + 1, false);
            }
        }

        // Memoize the result for the current vulnerableCode node
        memorizedTrees.put(vulnerableCode.data, cloneTree(vulnerableCode));
    }

    /**
     *
     * @param node
     * @return
     */
    private static TreeNode<String> cloneTree(TreeNode<String> node) {
        TreeNode<String> newNode = new TreeNode<>(node.data, node.isInterfaceNode);
        for (TreeNode<String> child : node.children) {
            newNode.addChild(String.valueOf(cloneTree(child)), child.isInterfaceNode);
        }
        return newNode;
    }
}
