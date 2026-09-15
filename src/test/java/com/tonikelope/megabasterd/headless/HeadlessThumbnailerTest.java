package com.tonikelope.megabasterd.headless;

import java.awt.Color;
import java.awt.image.BufferedImage;
import java.nio.file.*;
import javax.imageio.ImageIO;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

class HeadlessThumbnailerTest {
    @TempDir Path root;
    @Test void scalesImageAndPreservesSource() throws Exception {
        assertTrue(java.awt.GraphicsEnvironment.isHeadless());
        BufferedImage image=new BufferedImage(1600,800,BufferedImage.TYPE_INT_RGB);
        java.awt.Graphics2D graphics=image.createGraphics();graphics.setColor(Color.RED);graphics.fillRect(0,0,1600,800);graphics.dispose();
        Path source=root.resolve("image.png");ImageIO.write(image,"png",source.toFile());byte[] original=Files.readAllBytes(source);
        Path thumbnail=HeadlessThumbnailer.create(source,root,null);BufferedImage preview=ImageIO.read(thumbnail.toFile());
        assertEquals(320,preview.getWidth());assertEquals(160,preview.getHeight());assertArrayEquals(original,Files.readAllBytes(source));
        assertTrue(thumbnail.startsWith(root.resolve("thumbnails")));assertFalse(preview.getColorModel().hasAlpha());
    }
    @Test void transparentPixelsBecomeWhiteWithoutUpscaling() throws Exception {
        Path source=root.resolve("alpha.png");ImageIO.write(new BufferedImage(40,20,BufferedImage.TYPE_INT_ARGB),"png",source.toFile());
        BufferedImage preview=ImageIO.read(HeadlessThumbnailer.create(source,root,null).toFile());
        assertEquals(40,preview.getWidth());assertEquals(20,preview.getHeight());Color pixel=new Color(preview.getRGB(10,10));assertTrue(pixel.getRed()>245 && pixel.getGreen()>245 && pixel.getBlue()>245);
    }
    @Test void createsVideoPreviewWithBundledFfmpegWhenConfigured() throws Exception {
        String configured=System.getenv("ANYDOWN_FFMPEG_PATH");org.junit.jupiter.api.Assumptions.assumeTrue(configured!=null && Files.isExecutable(Paths.get(configured)),"FFmpeg integration needs ANYDOWN_FFMPEG_PATH");
        Path source=root.resolve("video.mp4");Process fixture=new ProcessBuilder(configured,"-hide_banner","-loglevel","error","-nostdin","-f","lavfi","-i","color=c=blue:s=640x360:d=1","-frames:v","1","-c:v","mpeg4",source.toString()).redirectOutput(ProcessBuilder.Redirect.DISCARD).redirectError(ProcessBuilder.Redirect.DISCARD).start();
        try{assertTrue(fixture.waitFor(15,java.util.concurrent.TimeUnit.SECONDS));assertEquals(0,fixture.exitValue());}finally{fixture.destroyForcibly();}
        byte[] original=Files.readAllBytes(source);Path thumbnail=HeadlessThumbnailer.create(source,root);assertNotNull(thumbnail);BufferedImage preview=ImageIO.read(thumbnail.toFile());
        assertEquals(320,preview.getWidth());assertEquals(180,preview.getHeight());assertArrayEquals(original,Files.readAllBytes(source));
    }
    @Test void unsupportedAndCorruptFilesLeaveNoPartialThumbnails() throws Exception {
        Path source=root.resolve("data.bin");Files.write(source,new byte[]{1,2,3,4});assertNull(HeadlessThumbnailer.create(source,root,null));
        Path corrupt=root.resolve("broken.mp4");Files.write(corrupt,new byte[]{1});assertNull(HeadlessThumbnailer.create(corrupt,root,null));
        try(java.util.stream.Stream<Path> files=Files.list(root.resolve("thumbnails"))){assertEquals(0,files.count());}
    }
}
