package com.lmco.crt;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.RecursiveAction;

public class ParallelTreeCreator {

    private static final Map<String, TreeNode<String>> memorizedTrees = new ConcurrentHashMap<>();
    private static final Set<String> visitedNodes = Collections.newSetFromMap(new ConcurrentHashMap<>());

    /**
     *
     * @param codeTarget
     * @return
     */
    public static TreeNode<String> createVulnerableCodeExecutionTree(String codeTarget) {
        // Clear the visitedNodes before starting the recursive method
        synchronized (visitedNodes) {
            visitedNodes.clear();
        }

        TreeNode<String> vulnerableCode = null;
        boolean isInterfaceMapping = false;

        synchronized (memorizedTrees) {
            if (memorizedTrees.containsKey(codeTarget)) {
                vulnerableCode = memorizedTrees.get(codeTarget);
                return vulnerableCode;
            }
        }

        for (Map.Entry<String, List<String>> entry : Constants.METHOD_INTERFACE_MAP.entrySet()) {
            String key = entry.getKey();
            List<String> values = entry.getValue();
            if (values.contains(codeTarget)) {
                vulnerableCode = new TreeNode<>(codeTarget, true);
                executeTask(vulnerableCode);
                isInterfaceMapping = true;
                break;
            } else if (key.equals(codeTarget)) {
                if (!values.isEmpty()) {
                    vulnerableCode = new TreeNode<>(codeTarget, false);
                    for (String interfaceName : Constants.METHOD_INTERFACE_MAP.get(codeTarget)) {
                        TreeNode<String> child = vulnerableCode.addChild(interfaceName, true);
                        executeTask(child);
                        isInterfaceMapping = true;
                    }
                    break;
                }
            }
        }
        if (!isInterfaceMapping) {
            vulnerableCode = new TreeNode<>(codeTarget, false);
            executeTask(vulnerableCode);
        }

        return vulnerableCode;
    }

    /**
     *
     * @param vulnerableCode
     */
    private static void executeTask(TreeNode<String> vulnerableCode) {
        ForkJoinPool forkJoinPool = new ForkJoinPool();
        VulnerableCodeTreeTask task = new VulnerableCodeTreeTask(vulnerableCode);
        forkJoinPool.invoke(task);
        task.join(); // Ensure the task and its subtasks complete
    }

    /**
     *
     */
    private static class VulnerableCodeTreeTask extends RecursiveAction {
        private final TreeNode<String> vulnerableCode;

        /**
         *
         * @param vulnerableCode
         */
        public VulnerableCodeTreeTask(TreeNode<String> vulnerableCode) {
            this.vulnerableCode = vulnerableCode;
        }

        /**
         *
         */
        @Override
        protected void compute() {

//            if (vulnerableCode.data.equals("org/apache/commons/compress/archivers/zip/ZipArchiveInputStream.bufferContainsSignature(Ljava/io/ByteArrayOutputStream;III)Z")) {
//                System.out.println("breakpoint");
//            }

            // Avoid infinite loops by checking visited nodes first
            synchronized (visitedNodes) {
                if (visitedNodes.contains(vulnerableCode.data)) {
                    return;
                }
                visitedNodes.add(vulnerableCode.data);
            }

            List<VulnerableCodeTreeTask> subTasks = new ArrayList<>();

            for (Map.Entry<String, Set<String>> entry : Constants.CALL_GRAPH.entrySet()) {
                String callingCode = entry.getKey();
                if (entry.getValue().contains(vulnerableCode.data)) {
                    // Get the interface for a method
                    if (Constants.METHOD_INTERFACE_MAP.containsKey(callingCode)) {
                        if (Constants.METHOD_INTERFACE_MAP.get(callingCode).size() > 1) {
                            System.out.println("Method: " + callingCode + " has multiple interfaces");
                        }
                        for (String interfaceName : Constants.METHOD_INTERFACE_MAP.get(callingCode)) {
                            TreeNode<String> child = vulnerableCode.addChild(interfaceName, true);
                            VulnerableCodeTreeTask task = new VulnerableCodeTreeTask(child);
                            subTasks.add(task);
                        }
                    }
                    TreeNode<String> child = vulnerableCode.addChild(callingCode, false);
                    VulnerableCodeTreeTask task = new VulnerableCodeTreeTask(child);
                    subTasks.add(task);
                }
            }

            // Execute all subtasks and wait for their completion
            invokeAll(subTasks);

            // Memorize the result for the current vulnerableCode node
            synchronized (vulnerableCode) {
                try {
                    TreeNode<String> memorizedSubtree = vulnerableCode.clone();
                    memorizedTrees.put(vulnerableCode.data, memorizedSubtree);
                } catch (CloneNotSupportedException e) {
                    throw new RuntimeException(e);
                }
            }
        }
    }
}



