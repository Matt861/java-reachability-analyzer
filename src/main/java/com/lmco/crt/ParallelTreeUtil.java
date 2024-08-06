package com.lmco.crt;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.RecursiveAction;

public class ParallelTreeUtil {

    private static final Map<String, TreeNode<String>> memorizedTrees = new ConcurrentHashMap<>();
    private static final Set<String> visitedNodes = Collections.newSetFromMap(new ConcurrentHashMap<String, Boolean>());

    public static TreeNode<String> createVulnerableCodeExecutionTree(String codeTarget) {
        // Clear the visitedNodes and memorizedTrees before starting the recursive method
        synchronized (visitedNodes) {
            visitedNodes.clear();
        }
        //memorizedTrees.clear();

        TreeNode<String> vulnerableCode = null;
        boolean isInterfaceMapping = false;

        if (memorizedTrees.containsKey(codeTarget)) {
            vulnerableCode = memorizedTrees.get(codeTarget);
            return vulnerableCode;
        }

        for (Map.Entry<String, List<String>> entry : Constants.methodInterfaceMap.entrySet()) {
            String key = entry.getKey();
            List<String> values = entry.getValue();
            if (values.contains(codeTarget)) {
                vulnerableCode = new TreeNode<>(codeTarget, true);
                executeTask(vulnerableCode, true);
                isInterfaceMapping = true;
                break;
            } else if (key.equals(codeTarget)) {
                if (!values.isEmpty()) {
                    vulnerableCode = new TreeNode<>(codeTarget, false);
                    for (String interfaceName : Constants.methodInterfaceMap.get(codeTarget)) {
                        TreeNode<String> child = vulnerableCode.addChild(interfaceName, true);
                        executeTask(child, true);
                        isInterfaceMapping = true;
                    }
                    break;
                }
            }
        }
        if (!isInterfaceMapping) {
            vulnerableCode = new TreeNode<>(codeTarget, false);
            executeTask(vulnerableCode, false);
        }

        return vulnerableCode;
    }

    private static void executeTask(TreeNode<String> vulnerableCode, Boolean isInterface) {
        ForkJoinPool forkJoinPool = new ForkJoinPool();
        VulnerableCodeTreeTask task = new VulnerableCodeTreeTask(vulnerableCode, isInterface);
        forkJoinPool.invoke(task);
        task.join(); // Ensure the task and its subtasks complete
    }

    private static class VulnerableCodeTreeTask extends RecursiveAction {
        private TreeNode<String> vulnerableCode;
        private Boolean isInterface;

        public VulnerableCodeTreeTask(TreeNode<String> vulnerableCode, Boolean isInterface) {
            this.vulnerableCode = vulnerableCode;
            this.isInterface = isInterface;
        }

        @Override
        protected void compute() {
            // Avoid infinite loops by checking visited nodes first
//            if (visitedNodes.contains(vulnerableCode.data)) {
//                return;
//            }

            //visitedNodes.add(vulnerableCode.data);

//            if (vulnerableCode.data.equals("org/apache/commons/compress/archivers/zip/ZipArchiveInputStream.bufferContainsSignature(Ljava/io/ByteArrayOutputStream;III)Z")) {
//                System.out.println("breakpoint");
//            }

            synchronized (visitedNodes) {
                if (visitedNodes.contains(vulnerableCode.data)) {
                    return;
                }
                visitedNodes.add(vulnerableCode.data);
            }

            List<VulnerableCodeTreeTask> subTasks = new ArrayList<>();

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
                            VulnerableCodeTreeTask task = new VulnerableCodeTreeTask(child, true);
                            subTasks.add(task);
                        }
                    }
                    TreeNode<String> child = vulnerableCode.addChild(callingCode, false);
                    VulnerableCodeTreeTask task = new VulnerableCodeTreeTask(child, false);
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

//    private static Boolean isMemorizedTree(TreeNode<String> vulnerableCode, Boolean isMemorized) {
//        if (memorizedTrees.containsKey(vulnerableCode.data)) {
//            TreeNode<String> memorizedSubtree = cloneTree(memorizedTrees.get(vulnerableCode.data));
//            for (TreeNode<String> child : memorizedSubtree.children) {
//                if (!vulnerableCode.containsChild(child.data)) {
//                    vulnerableCode.addChild(String.valueOf(cloneTree(child)), child.isInterfaceNode);
//                    isMemorized = true;
//                }
//            }
//        }
//        return isMemorized;
//    }
//
//    private static TreeNode<String> cloneTree(TreeNode<String> node) {
//        TreeNode<String> newNode = new TreeNode<>(node.data, node.isInterfaceNode);
//        for (TreeNode<String> child : node.children) {
//            newNode.addChild(String.valueOf(cloneTree(child)), child.isInterfaceNode);
//        }
//        return newNode;
//    }



