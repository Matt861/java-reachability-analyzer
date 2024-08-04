//package com.lmco.crt.stuff.old;
//
//import com.github.javaparser.JavaParser;
//import com.github.javaparser.ast.CompilationUnit;
//import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
//import com.github.javaparser.ast.body.MethodDeclaration;
//import com.github.javaparser.ast.expr.AnnotationExpr;
//import com.github.javaparser.ast.visitor.VoidVisitorAdapter;
//
//import java.io.File;
//import java.util.List;
//
//public class ClassAndMethodVisitor {
//    public static void main(String[] args) throws Exception {
//        // Create a JavaParser instance
//        JavaParser javaParser = new JavaParser();
//
//        // Specify the decompiled source file
//        File sourceFile = new File("extractedJars\\crt-service\\decompiled\\com\\lmco\\crt\\Main.java");
//
//        // Parse the file using the instance
//        CompilationUnit cu = javaParser.parse(sourceFile).getResult().orElseThrow(() -> new RuntimeException("Parsing failed"));
//
//        // Visit classes and methods in the parsed file
//        cu.accept(new ClassVisitor(), null);
//    }
//
//    private static class ClassVisitor extends VoidVisitorAdapter<Void> {
//        @Override
//        public void visit(ClassOrInterfaceDeclaration cid, Void arg) {
//            System.out.println("Class: " + cid.getName());
//
//            // Get and print class annotations
//            List<AnnotationExpr> annotations = cid.getAnnotations();
//            for (AnnotationExpr annotation : annotations) {
//                System.out.println("Class Annotation: " + annotation.getName());
//            }
//
//            super.visit(cid, arg);
//
//            // Visit methods within the class
//            cid.getMethods().forEach(m -> m.accept(new MethodVisitor(), null));
//        }
//    }
//
//    private static class MethodVisitor extends VoidVisitorAdapter<Void> {
//        @Override
//        public void visit(MethodDeclaration md, Void arg) {
//            System.out.println("Method: " + md.getName());
//
//            // Get and print method annotations
//            List<AnnotationExpr> annotations = md.getAnnotations();
//            for (AnnotationExpr annotation : annotations) {
//                System.out.println("Method Annotation: " + annotation.getName());
//            }
//
//            super.visit(md, arg);
//        }
//    }
//}
//
//
//
