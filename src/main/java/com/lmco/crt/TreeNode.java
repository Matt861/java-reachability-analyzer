package com.lmco.crt;

import java.util.*;

public class TreeNode<T> implements Cloneable, Iterable<TreeNode<T>> {

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
        this.children = new LinkedList<>();
        this.childDataSet = new HashSet<>();
        this.isInterfaceNode = isInterface;
    }

    public TreeNode<T> addChild(T child, Boolean isInterface) {
        TreeNode<T> childNode = new TreeNode<T>(child, isInterface);
        childNode.parent = this;
        synchronized (this) {
            this.children.add(childNode);
        }
        this.childDataSet.add(child);
        childNode.isInterfaceNode = isInterface;
        //this.registerChildForSearch(childNode);
        return childNode;
    }

    public boolean containsChild(T childData) {
        synchronized (this) {
            return children.stream().anyMatch(child -> child.data.equals(data));
        }
        //return this.childDataSet.contains(childData);
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

    public TreeNode<T> findNodeByData(T data) {
        if (this.data.equals(data)) {
            return this;
        }
        for (TreeNode<T> child : children) {
            TreeNode<T> result = child.findNodeByData(data);
            if (result != null) {
                return result;
            }
        }
        return null;
    }

    @Override
    public TreeNode<T> clone() throws CloneNotSupportedException {
        try {
            TreeNode<T> cloned = (TreeNode<T>) super.clone();
            cloned.data = this.data;
            cloned.children = new LinkedList<>();
            for (TreeNode<T> child : this.children) {
                cloned.children.add(child.clone());
            }
            cloned.childDataSet = new HashSet<>(this.childDataSet);
            cloned.isInterfaceNode = this.isInterfaceNode;
            return cloned;
        } catch (CloneNotSupportedException e) {
            throw new AssertionError(); // Can't happen
        }
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
