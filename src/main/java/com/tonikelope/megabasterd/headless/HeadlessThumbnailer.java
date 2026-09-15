/* AnyDown headless integration. GPL-3.0. */
package com.tonikelope.megabasterd.headless;

import java.awt.Color;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Iterator;
import java.util.Locale;
import java.util.concurrent.TimeUnit;
import javax.imageio.*;
import javax.imageio.stream.ImageInputStream;

/** Creates private JPEG previews without constructing a window or exposing provider links. */
public final class HeadlessThumbnailer {
    private static final int SIZE=320;
    private HeadlessThumbnailer() { }
    public static Path create(Path source,Path profile) throws IOException {
        String configured=System.getenv("ANYDOWN_FFMPEG_PATH");
        return create(source,profile,configured==null || configured.isBlank()?null:Paths.get(configured));
    }
    static Path create(Path source,Path profile,Path ffmpeg) throws IOException {
        if(!Files.isRegularFile(source))return null;
        Path directory=profile.resolve("thumbnails");Files.createDirectories(directory);
        try{Files.setPosixFilePermissions(directory,PosixFilePermissions.fromString("rwx------"));}catch(UnsupportedOperationException ignored){}
        Path output=Files.createTempFile(directory,"preview-",".jpg");boolean complete=false;
        try {
            BufferedImage image=readImage(source);
            if(image!=null){try{writeImage(image,output);}finally{image.flush();}complete=true;return output;}
            if(ffmpeg==null || !Files.isRegularFile(ffmpeg) || !Files.isExecutable(ffmpeg) || !videoExtension(source))return null;
            // Format and protocol restrictions exclude playlists and external network fetches.
            Process process=new ProcessBuilder(ffmpeg.toAbsolutePath().toString(),"-hide_banner","-loglevel","error","-nostdin","-y",
                "-protocol_whitelist","file,pipe","-format_whitelist","mov,matroska,webm,avi,mpeg,mpegts,flv,ogg,gif,asf,image2,webp_pipe",
                "-i",source.toAbsolutePath().toString(),"-map","0:v:0","-frames:v","1","-vf","scale=320:320:force_original_aspect_ratio=decrease",
                "-threads","1","-c:v","mjpeg",output.toAbsolutePath().toString())
                .redirectOutput(ProcessBuilder.Redirect.DISCARD).redirectError(ProcessBuilder.Redirect.DISCARD).start();
            try {
                if(!process.waitFor(30,TimeUnit.SECONDS)){process.destroyForcibly();process.waitFor(5,TimeUnit.SECONDS);return null;}
                if(process.exitValue()!=0 || Files.size(output)==0 || Files.size(output)>5*1024*1024)return null;
                BufferedImage preview=readImage(output);if(preview==null)return null;
                // Validate and normalize ffmpeg output through the same bounded JPEG path.
                try{writeImage(preview,output);}finally{preview.flush();}complete=true;return output;
            } catch(InterruptedException ex){process.destroyForcibly();Thread.currentThread().interrupt();return null;}
            finally {
                if(process.isAlive()) {
                    process.destroyForcibly();boolean interrupted=Thread.interrupted();
                    try{if(!process.waitFor(5,TimeUnit.SECONDS))throw new IOException("Thumbnail process did not stop");}
                    catch(InterruptedException ex){interrupted=true;throw new IOException("Interrupted while stopping thumbnail process");}
                    finally{if(interrupted)Thread.currentThread().interrupt();}
                }
            }
        } finally {if(!complete)Files.deleteIfExists(output);}
    }
    private static boolean videoExtension(Path source) {
        String name=source.getFileName().toString().toLowerCase(Locale.ROOT);
        return name.matches(".*\\.(mp4|m4v|mov|mkv|webm|avi|mpeg|mpg|ts|flv|ogv|ogg|wmv|asf|gif|webp|avif|heic)$");
    }
    private static BufferedImage readImage(Path source) {
        try(ImageInputStream stream=ImageIO.createImageInputStream(source.toFile())) {
            if(stream==null)return null;Iterator<ImageReader> readers=ImageIO.getImageReaders(stream);if(!readers.hasNext())return null;
            ImageReader reader=readers.next();
            try {
                reader.setInput(stream,true,true);int width=reader.getWidth(0),height=reader.getHeight(0);
                if(width<1 || height<1 || (long)width*height>100000000L)return null;
                ImageReadParam params=reader.getDefaultReadParam();int subsample=Math.max(1,Math.max(width,height)/(SIZE*2));params.setSourceSubsampling(subsample,subsample,0,0);
                return reader.read(0,params);
            } finally {reader.dispose();}
        } catch(IOException | RuntimeException | LinkageError | java.util.ServiceConfigurationError ex){return null;}
    }
    private static void writeImage(BufferedImage source,Path output) throws IOException {
        double scale=Math.min(1,Math.min((double)SIZE/source.getWidth(),(double)SIZE/source.getHeight()));
        int width=Math.max(1,(int)Math.round(source.getWidth()*scale)),height=Math.max(1,(int)Math.round(source.getHeight()*scale));
        BufferedImage jpeg=new BufferedImage(width,height,BufferedImage.TYPE_INT_RGB);Graphics2D graphics=jpeg.createGraphics();
        try{graphics.setColor(Color.WHITE);graphics.fillRect(0,0,width,height);graphics.setRenderingHint(RenderingHints.KEY_INTERPOLATION,RenderingHints.VALUE_INTERPOLATION_BICUBIC);graphics.drawImage(source,0,0,width,height,null);}
        finally{graphics.dispose();}
        try{if(!ImageIO.write(jpeg,"jpg",output.toFile()))throw new IOException("JPEG encoder unavailable");}
        finally{jpeg.flush();}
    }
}
