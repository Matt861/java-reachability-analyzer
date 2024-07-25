package com.lmco.crt;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class TreeUtil {

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
     */
    public static void createVulnerableCodeExecutionTree(TreeNode<String> vulnerableCode) {
        Map<String, Set<String>> callGraph = CodeReachabilityAnalyzer.getCallGraph();
        for (Map.Entry<String, Set<String>> entry : callGraph.entrySet()) {
            String callingCode = entry.getKey();
            if (entry.getValue().contains(vulnerableCode.data)) {
                // This is actually the parent because it is code that calls the vulnerable code.
                // However, the tree will be reversed later so that the execution order is correct.
                TreeNode<String> child = vulnerableCode.addChild(callingCode);
                createVulnerableCodeExecutionTree(child);
            }
        }
    }
}
