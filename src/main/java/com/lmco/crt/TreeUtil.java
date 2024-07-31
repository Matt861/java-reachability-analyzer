package com.lmco.crt;

import java.util.*;

public class TreeUtil {

    private static final Map<String, Set<String>> callGraph = CodeReachabilityAnalyzer.getCallGraph();
    private static final Map<String, TreeNode<String>> memoizedTrees = new HashMap<>();
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

        currentPath.add(vulnerableCode.data);

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
     * @param vulnerableCode
     * @param depth
     */
    public static void createVulnerableCodeExecutionTree(TreeNode<String> vulnerableCode, int depth) {
        //System.out.println("createVulnerableCodeExecutionTree recursion depth: " + depth);

        // Avoid infinite loops by checking visited nodes first
        if (visitedNodes.contains(vulnerableCode.data)) {
            return;
        }

        visitedNodes.add(vulnerableCode.data);

        // Check for memoized results
        if (memoizedTrees.containsKey(vulnerableCode.data)) {
            TreeNode<String> memoizedSubtree = memoizedTrees.get(vulnerableCode.data);
            for (TreeNode<String> child : memoizedSubtree.children) {
                vulnerableCode.addChild(cloneTree(child).data);
            }
            return;
        }

        for (Map.Entry<String, Set<String>> entry : callGraph.entrySet()) {
            String callingCode = entry.getKey();
            if (entry.getValue().contains(vulnerableCode.data)) {
                boolean alreadyHasChild = false;
                for (TreeNode<String> child : vulnerableCode.children) {
                    if (child.data.equals(callingCode)) {
                        alreadyHasChild = true;
                        break;
                    }
                }
                if (!alreadyHasChild) {
                    TreeNode<String> child = vulnerableCode.addChild(callingCode);
                    createVulnerableCodeExecutionTree(child, depth + 1);
                } else {
                    System.out.println("Tree children already contain callingCode");
                }
            }
        }

        // Memoize the result for the current vulnerableCode node
        memoizedTrees.put(vulnerableCode.data, cloneTree(vulnerableCode));
    }

    public static void removeConsecutiveDuplicates(TreeNode<String> node) {
        Set<String> uniqueChildren = new HashSet<>();
        Iterator<TreeNode<String>> iterator = node.children.iterator();
        while (iterator.hasNext()) {
            TreeNode<String> child = iterator.next();
            if (uniqueChildren.contains(child.data)) {
                iterator.remove();
            } else {
                uniqueChildren.add(child.data);
                removeConsecutiveDuplicates(child);
            }
        }
    }

    private static TreeNode<String> cloneTree(TreeNode<String> node) {
        TreeNode<String> newNode = new TreeNode<>(node.data);
        for (TreeNode<String> child : node.children) {
            newNode.addChild(cloneTree(child).data);
        }
        return newNode;
    }
}
