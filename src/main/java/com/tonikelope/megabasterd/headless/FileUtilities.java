/* AnyDown headless integration. GPL-3.0. */
package com.tonikelope.megabasterd.headless;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.*;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.Consumer;
import static com.tonikelope.megabasterd.headless.EngineMain.*;

/** Cancellable file operations. Outputs are published only after successful copies. */
public final class FileUtilities implements AutoCloseable {
    private final ExecutorService executor=Executors.newSingleThreadExecutor(r->{Thread t=new Thread(r,"file-utilities");t.setDaemon(true);return t;});
    private final LinkedHashMap<String,Task> tasks=new LinkedHashMap<>();
    private final Consumer<Map<String,Object>> events;
    private volatile boolean closing;
    private static final class Task {
        final String id=UUID.randomUUID().toString(),kind;
        volatile boolean cancel;
        volatile String status="queued",error;
        volatile long completed,total;
        volatile List<String> outputs=Collections.emptyList();
        Task(String kind) { this.kind=kind; }
        Map<String,Object> snapshot(){return map("id",id,"kind",kind,"status",status,"completedBytes",completed,"totalBytes",total,"outputs",outputs,"error",error);}
    }
    public FileUtilities(){this(event->{});}
    public FileUtilities(Consumer<Map<String,Object>> events){this.events=events;}
    public synchronized boolean isActive(){return tasks.values().stream().anyMatch(t->t.status.equals("queued") || t.status.equals("running"));}
    public synchronized List<Map<String,Object>> list(){List<Map<String,Object>> result=new ArrayList<>();for(Task task:tasks.values())result.add(task.snapshot());return result;}
    public synchronized Object call(String method,JsonNode params) throws Exception {
        if(method.equals("utility.list"))return list();
        if(method.equals("utility.status") || method.equals("utility.cancel")) {
            String id=text(params,params.has("id")?"id":"utilityId");Task task=tasks.get(id);if(task==null)throw new RpcException(-32602,"Unknown utility operation");
            if(method.equals("utility.cancel"))task.cancel=true;return task.snapshot();
        }
        if(!method.equals("utility.split") && !method.equals("utility.merge"))throw new RpcException(-32601,"Unknown utility method");
        if(closing)throw new RpcException(-32000,"Engine is shutting down");
        if(tasks.size()>=128) { Iterator<Task> iterator=tasks.values().iterator();while(iterator.hasNext()){Task task=iterator.next();if(!task.status.equals("queued") && !task.status.equals("running")){iterator.remove();break;}} }
        if(tasks.size()>=128)throw new RpcException(-32000,"Too many queued utility operations");
        Task task=new Task(method.substring(8));
        if(method.equals("utility.split")) {
            Path source=regular(text(params,"path"));Path directory=Paths.get(text(params,params.has("outputDirectory")?"outputDirectory":"directory")).toAbsolutePath().normalize();
            if(!Files.isDirectory(directory))throw new RpcException(-32602,"Output directory does not exist");
            JsonNode part=params.path(params.has("partBytes")?"partBytes":"partSize");if(!part.isIntegralNumber() || !part.canConvertToLong() || part.longValue()<1)throw new RpcException(-32602,"partBytes must be a positive integer");
            long size=Files.size(source),partBytes=part.longValue(),count=size==0?1:1+(size-1)/partBytes;
            if(count>10000)throw new RpcException(-32602,"Split would create more than 10000 parts");
            task.total=size;tasks.put(task.id,task);executor.submit(()->run(task,()->split(task,source,directory,partBytes)));
        } else {
            JsonNode parts=params.path(params.has("parts")?"parts":"paths");if(!parts.isArray() || parts.isEmpty() || parts.size()>10000)throw new RpcException(-32602,"Provide an ordered list of 1 to 10000 parts");
            List<Path> inputs=new ArrayList<>();Set<Path> unique=new HashSet<>();
            for(JsonNode part:parts){if(!part.isTextual())throw new RpcException(-32602,"Part paths must be strings");Path source=regular(part.asText());if(!unique.add(source.toRealPath()))throw new RpcException(-32602,"Duplicate merge part");inputs.add(source);task.total=Math.addExact(task.total,Files.size(source));}
            Path output=Paths.get(text(params,params.has("outputPath")?"outputPath":"output")).toAbsolutePath().normalize();
            if(!Files.isDirectory(output.getParent()) || Files.exists(output,LinkOption.NOFOLLOW_LINKS))throw new RpcException(-32602,"Choose a new output file in an existing directory");
            tasks.put(task.id,task);executor.submit(()->run(task,()->merge(task,inputs,output)));
        }
        return task.snapshot();
    }
    private interface Work { void execute() throws Exception; }
    private void run(Task task,Work work){
        task.status="running";emit(task);
        try { check(task);work.execute();task.status="completed"; }
        catch(CancellationException ex){task.status="cancelled";}
        catch(Exception ex){task.status="failed";task.error=ex instanceof RpcException?ex.getMessage():"File operation failed ("+ex.getClass().getSimpleName()+")";}
        finally{emit(task);}
    }
    private void split(Task task,Path source,Path directory,long partBytes) throws Exception {
        List<Path> temporary=new ArrayList<>(),outputs=new ArrayList<>(),published=new ArrayList<>();BasicFileAttributes before=Files.readAttributes(source,BasicFileAttributes.class);
        try(InputStream input=Files.newInputStream(source)) {
            long remaining=task.total;int index=1;
            do {
                check(task);Path output=directory.resolve(source.getFileName()+String.format(Locale.ROOT,".part%05d",index++));
                if(Files.exists(output,LinkOption.NOFOLLOW_LINKS))throw new RpcException(-32602,"A split output already exists");
                Path temp=Files.createTempFile(directory,".anydown-split-",".tmp");temporary.add(temp);outputs.add(output);
                long count=Math.min(remaining,partBytes);try(OutputStream out=Files.newOutputStream(temp)){copy(task,input,out,count);}remaining-=count;
            } while(remaining>0);
            if(input.read()!=-1 || !unchanged(before,Files.readAttributes(source,BasicFileAttributes.class)))throw new RpcException(-32000,"Source changed while splitting");
            check(task);for(int i=0;i<outputs.size();i++){check(task);Files.createLink(outputs.get(i),temporary.get(i));published.add(outputs.get(i));}
            List<String> names=new ArrayList<>();for(Path output:outputs)names.add(output.toString());task.outputs=names;
        } catch(Exception ex) { for(int i=0;i<published.size();i++){if(Files.isSameFile(published.get(i),temporary.get(i)))Files.delete(published.get(i));}throw ex; }
        finally{for(Path temp:temporary)Files.deleteIfExists(temp);}
    }
    private void merge(Task task,List<Path> sources,Path output) throws Exception {
        Path temp=Files.createTempFile(output.getParent(),".anydown-merge-",".tmp");
        try {
            try(OutputStream out=Files.newOutputStream(temp)) {
                for(Path source:sources){check(task);BasicFileAttributes before=Files.readAttributes(source,BasicFileAttributes.class);
                    try(InputStream input=Files.newInputStream(source)){copy(task,input,out,before.size());if(input.read()!=-1 || !unchanged(before,Files.readAttributes(source,BasicFileAttributes.class)))throw new RpcException(-32000,"Part changed while merging");}
                }
            }
            check(task);Files.createLink(output,temp);task.outputs=Collections.singletonList(output.toString());
        } finally {Files.deleteIfExists(temp);}
    }
    private void copy(Task task,InputStream input,OutputStream output,long count) throws Exception {
        byte[] buffer=new byte[256*1024];long remaining=count,lastEvent=System.nanoTime();
        while(remaining>0){check(task);int read=input.read(buffer,0,(int)Math.min(buffer.length,remaining));if(read<0)throw new EOFException("Input file was truncated");if(read==0)continue;output.write(buffer,0,read);remaining-=read;task.completed+=read;
            if(System.nanoTime()-lastEvent>=100000000L){emit(task);lastEvent=System.nanoTime();}}
    }
    private static boolean unchanged(BasicFileAttributes a,BasicFileAttributes b){return a.size()==b.size() && a.lastModifiedTime().equals(b.lastModifiedTime()) && Objects.equals(a.fileKey(),b.fileKey());}
    private static void check(Task task){if(task.cancel || Thread.currentThread().isInterrupted())throw new CancellationException();}
    private void emit(Task task){try{events.accept(map("type","utility.updated","utility",task.snapshot()));}catch(RuntimeException ignored){}}
    private static String text(JsonNode params,String key) throws RpcException{if(!params.path(key).isTextual() || params.path(key).asText().isEmpty())throw new RpcException(-32602,"Missing "+key);return params.path(key).asText();}
    private static Path regular(String path) throws Exception{Path source=Paths.get(path).toAbsolutePath().normalize();if(!Files.isRegularFile(source))throw new RpcException(-32602,"Input must be an existing regular file");return source;}
    @Override public void close(){
        synchronized(this){closing=true;for(Task task:tasks.values()){task.cancel=true;if(task.status.equals("queued"))task.status="cancelled";}executor.shutdownNow();}
        try{if(!executor.awaitTermination(35,TimeUnit.SECONDS))throw new IllegalStateException("File utilities did not quiesce");}
        catch(InterruptedException ex){Thread.currentThread().interrupt();throw new IllegalStateException("Interrupted while stopping file utilities");}
    }
}
