//package com.lmco.crt.stuff;
//
//import java.lang.reflect.Method;
//import java.net.URL;
//import java.net.URLClassLoader;
//
//public class JarClassAnalyzer {
//    public static void main(String[] args) throws Exception {
//        URL jarUrl = new URL("file:path/to/your.jar");
//        URLClassLoader classLoader = new URLClassLoader(new URL[]{jarUrl});
//        Class<?> clazz = classLoader.loadClass("your.package.YourClass");
//
//        System.out.println("Class: " + clazz.getName());
//        for (Method method : clazz.getDeclaredMethods()) {
//            System.out.println("Method: " + method.getName());
//        }
//
//        classLoader.close();
//    }
//}
//
