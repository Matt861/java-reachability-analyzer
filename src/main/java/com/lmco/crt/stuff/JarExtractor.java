//package com.lmco.crt.stuff;
//
//import java.util.jar.JarFile;
//import java.util.zip.ZipEntry;
//import java.io.InputStream;
//import java.io.FileOutputStream;
//import java.io.File;
//
//public class JarExtractor {
//    public static void extractJar(String jarFilePath, String outputDir) throws Exception {
//        JarFile jarFile = new JarFile(jarFilePath);
//        jarFile.stream().forEach(entry -> {
//            try {
//                File file = new File(outputDir, entry.getName());
//                if (entry.isDirectory()) {
//                    file.mkdirs();
//                } else {
//                    file.getParentFile().mkdirs();
//                    try (InputStream is = jarFile.getInputStream(entry);
//                         FileOutputStream fos = new FileOutputStream(file)) {
//                        byte[] buffer = new byte[1024];
//                        int bytesRead;
//                        while ((bytesRead = is.read(buffer)) != -1) {
//                            fos.write(buffer, 0, bytesRead);
//                        }
//                    }
//                }
//            } catch (Exception e) {
//                e.printStackTrace();
//            }
//        });
//    }
//
//    public static void main(String[] args) throws Exception {
//        extractJar("jars\\crt-service-3.0-SNAPSHOT.jar", "extractedJars\\crt-service");
//    }
//}
//
