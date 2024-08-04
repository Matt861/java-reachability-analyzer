package com.lmco.crt;

import java.util.*;

public class TreeNode<T> implements Iterable<TreeNode<T>> {

    T data;
    TreeNode<T> parent;
    List<TreeNode<T>> children;
    Set<T> childDataSet;
    Boolean isInterfaceNode;

    public boolean isRoot() {
        return parent == null;
    }

    public boolean isLeaf() {
        return children.size() == 0;
    }

    private List<TreeNode<T>> elementsIndex;

    public TreeNode(T data, Boolean isInterface) {
        this.data = data;
        this.children = new LinkedList<TreeNode<T>>();
        this.childDataSet = new HashSet<>();
        this.isInterfaceNode = isInterface;
    }

    public TreeNode<T> addChild(T child, Boolean isInterface) {
        TreeNode<T> childNode = new TreeNode<T>(child, isInterface);
        childNode.parent = this;
        this.children.add(childNode);
        this.childDataSet.add(child);
        childNode.isInterfaceNode = isInterface;
        return childNode;
    }

    public boolean containsChild(T childData) {
        return this.childDataSet.contains(childData);
    }

    public boolean contains(T childData) {
        for (TreeNode<T> child : children) {
            if (child.data.equals(childData)) {
                return true;
            }
        }
        return false;
    }

    public int getLevel() {
        if (this.isRoot())
            return 0;
        else
            return parent.getLevel() + 1;
    }

    private void registerChildForSearch(TreeNode<T> node) {
        elementsIndex.add(node);
        if (parent != null)
            parent.registerChildForSearch(node);
    }

    public TreeNode<T> findTreeNode(Comparable<T> cmp) {
        for (TreeNode<T> element : this.elementsIndex) {
            T elData = element.data;
            if (cmp.compareTo(elData) == 0)
                return element;
        }

        return null;
    }

    @Override
    public String toString() {
        return data != null ? data.toString() : "[data null]";
    }

    @Override
    public Iterator<TreeNode<T>> iterator() {
        return new TreeNodeIterator<T>(this);
    }
}
