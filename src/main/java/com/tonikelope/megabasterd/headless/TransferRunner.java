package com.tonikelope.megabasterd.headless;
import com.tonikelope.megabasterd.*;
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import javax.crypto.*;
import static com.tonikelope.megabasterd.CryptTools.*;
import static com.tonikelope.megabasterd.MiscTools.*;

/** Headless execution controller sharing upstream API, encryption, chunk sizing and proxy pool. */
public final class TransferRunner {
    final EngineContext context;
    TransferRunner(EngineContext context) { this.context=context; }
    void check(Transfer t) throws InterruptedException { if(t.stop||context.closed||Thread.currentThread().isInterrupted())throw new InterruptedException(); }
    void download(Transfer t) throws Exception {
        MegaAPI api=context.api(t.accountId);
        String[] metadata=t.sourceKind.equals("megacrypter")?new String[]{t.name,Long.toString(t.totalBytes),t.fileKey}:api.getMegaFileMetadata(t.url);String encodedKey=metadata[2];
        if(t.totalBytes!=Long.parseLong(metadata[1]))throw new RpcException(-32010,"MEGA file size changed");
        Path directory=Paths.get(t.directory).toAbsolutePath().normalize();
        Path target=directory.resolve(t.name).normalize();
        if(!target.startsWith(directory))throw new RpcException(-32602,"Destination escapes download directory");
        Files.createDirectories(target.getParent());
        Path partial;
        if(t.temporaryPath!=null)partial=Paths.get(t.temporaryPath);
        else {String configured=context.string("tempDirectory");Path tempRoot=configured.isEmpty()?target.getParent():Paths.get(configured).resolve("anydown-mega");if(configured.isEmpty())Files.createDirectories(tempRoot);else EngineContext.privateDirectory(tempRoot);partial=tempRoot.resolve(".anydown-"+t.id+".part");t.temporaryPath=partial.toString();context.changed(t);}
        if(Files.exists(target)){if(t.publishPending&&Files.size(target)==t.totalBytes){MegaFileCrypto.verify(target,encodedKey);t.outputPath=target.toString();t.completedBytes=t.totalBytes;Files.deleteIfExists(partial);return;}throw new RpcException(-32012,"Destination already exists");}
        if(!Files.exists(partial)) { synchronized(t) { t.completedChunks.clear();t.completedBytes=0; } }
        try(RandomAccessFile file=new RandomAccessFile(partial.toFile(),"rw")) { file.setLength(t.totalBytes); }
        if(t.totalBytes>0) {
            final String downloadUrl=downloadUrl(t,api);
            ExecutorService workers=Executors.newFixedThreadPool(context.integer("workerSlots",4));
            CompletionService<Void> completions=new ExecutorCompletionService<>(workers);
            int pending=0;long offset=0,chunkId=1;
            try {
                while(offset<t.totalBytes) {
                    check(t);long size=ChunkWriterManager.calculateChunkSize(chunkId,t.totalBytes,offset,1);
                    final long id=chunkId,start=offset,length=size;
                    boolean complete; synchronized(t){complete=t.completedChunks.contains(id);}
                    if(!complete) { completions.submit(()->{ downloadChunk(t,api,downloadUrl,encodedKey,partial,id,start,length);return null; });pending++; }
                    offset+=size;chunkId++;
                    // Bound queued tasks so very large files do not allocate one Future per chunk.
                    if(pending>=context.integer("workerSlots",4)*2) { completions.take().get();pending--; }
                }
                while(pending-->0)completions.take().get();
            } finally { workers.shutdownNow();workers.awaitTermination(35,TimeUnit.SECONDS); }
        }
        check(t);t.status="verifying";context.changed(t);
        // Verify before publication by default, including an empty file's zero MAC; explicit preferences may disable it.
        try { if(context.bool("verifyIntegrity",true)){MegaFileCrypto.verify(partial,encodedKey);t.integrityVerified=true;} }
        catch(RpcException integrity){synchronized(t){t.completedChunks.clear();t.completedBytes=0;}Files.deleteIfExists(partial);throw integrity;}
        check(t);
        t.publishPending=true;context.changed(t);
        Path publication=partial;
        if(!Files.getFileStore(partial).equals(Files.getFileStore(target.getParent()))){publication=target.resolveSibling(".anydown-publish-"+t.id);Files.deleteIfExists(publication);Files.copy(partial,publication);try(java.nio.channels.FileChannel channel=java.nio.channels.FileChannel.open(publication,StandardOpenOption.WRITE)){channel.force(true);}}
        try {Files.createLink(target,publication);Files.delete(publication);}
        catch(UnsupportedOperationException|FileSystemException noHardLinks){if(Files.exists(target))throw new RpcException(-32012,"Destination already exists");Files.move(publication,target);}
        if(!publication.equals(partial))Files.delete(partial);
        t.outputPath=target.toString();t.completedBytes=t.totalBytes;
    }
    String downloadUrl(Transfer t,MegaAPI api)throws Exception{return "megacrypter".equals(t.sourceKind)?HeadlessMegaCrypter.downloadUrl(t.url,t.passHash,t.noexpire,null):api.getMegaFileDownloadUrl(t.url);}
    private void downloadChunk(Transfer t,MegaAPI api,String initialUrl,String key,Path partial,long chunkId,long offset,long length) throws Exception {
        byte[] data=null;String url=initialUrl;int failures=0;
        while(data==null) {
            check(t);context.awaitPayload(t);HttpURLConnection connection=null;
            try {
                connection=context.open(ChunkWriterManager.genChunkUrl(url,t.totalBytes,offset,length),failures>0||t.quotaUntil>System.currentTimeMillis());
                int status=connection.getResponseCode();
                if(status!=200&&status!=206) {
                    if(status==403){url=downloadUrl(t,api);}
                    if(status==509)t.quotaUntil=System.currentTimeMillis()+context.integer("smartProxyRecheckSeconds",300)*1000L;
                    throw new IOException(status==509?"quota":"http");
                }
                try(InputStream in=connection.getInputStream();ByteArrayOutputStream bytes=new ByteArrayOutputStream((int)length)) {
                    byte[] buffer=new byte[65536];int read;
                    while((read=in.read(buffer))!=-1) {check(t);if(bytes.size()+read>length)throw new IOException("Oversized chunk");context.throttle(t,"download",read);bytes.write(buffer,0,read);}
                    if(bytes.size()!=length)throw new EOFException("Short chunk");data=bytes.toByteArray();
                }
            } catch(IOException e) {
                if(connection!=null)context.connectionFailed(connection);
                if(++failures>context.integer("retryLimit",8))throw new RpcException(-32013,"MEGA chunk failed after retries; resume to retry");
                t.status="retrying";t.error="Waiting for MEGA availability or transfer quota";context.changed(t);
                long delay=Math.min(60000L,MiscTools.getWaitTimeExpBackOff(failures)*1000L);
                for(long waited=0;waited<delay;waited+=200){check(t);Thread.sleep(Math.min(200,delay-waited));}
            } finally {if(connection!=null)connection.disconnect();}
        }
        byte[] decrypted=aes_ctr_decrypt_nopadding(data,initMEGALinkKey(key),forwardMEGALinkKeyIV(initMEGALinkKeyIV(key),offset));
        check(t);
        try(RandomAccessFile file=new RandomAccessFile(partial.toFile(),"rw")) {file.seek(offset);file.write(decrypted);file.getFD().sync();}
        synchronized(t){t.completedChunks.add(chunkId);t.completedBytes+=length;t.status="running";t.error=null;}
        context.changed(t);
    }
    void upload(Transfer t) throws Exception {
        try {uploadInternal(t);}catch(RpcException ex){if(ex.code==-32016){t.uploadUrl=null;t.completionHandle=null;t.completedBytes=0;context.changed(t);}throw ex;}
    }
    void uploadInternal(Transfer t) throws Exception {
        MegaAPI api=context.api(t.accountId);Path path=Paths.get(t.path);
        if(Files.size(path)!=t.totalBytes||Files.getLastModifiedTime(path).toMillis()!=t.modifiedTime)
            throw new RpcException(-32014,"Upload source changed since it was queued");
        if(t.uploadKey==null)t.uploadKey=api.genUploadKey();
        byte[] key=i32a2bin(Arrays.copyOfRange(t.uploadKey,0,4));
        byte[] iv=i32a2bin(new int[]{t.uploadKey[4],t.uploadKey[5],0,0});
        if(t.uploadUrl==null) {t.uploadUrl=api.initUploadFile(t.path);t.completedBytes=0;context.changed(t);}
        if(t.uploadUrl==null)throw new RpcException(-32015,"MEGA upload session could not be created");
        try(RandomAccessFile source=new RandomAccessFile(path.toFile(),"r")) {
            long chunkId=1,offset=0;
            do {
                check(t);long length=ChunkWriterManager.calculateChunkSize(chunkId,t.totalBytes,offset,1);
                if(offset>=t.completedBytes&&t.completionHandle==null) {
                    byte[] data=new byte[(int)length];source.seek(offset);source.readFully(data);
                    byte[] encrypted=aes_ctr_encrypt_nopadding(data,key,forwardMEGALinkKeyIV(iv,offset));
                    byte[] response=uploadChunk(t,t.uploadUrl+"/"+offset,encrypted);
                    if(response.length>0) {
                        String error=new String(response,java.nio.charset.StandardCharsets.US_ASCII);
                        if(error.equals("-8")||error.equals("-9"))throw new RpcException(-32016,"Upload session expired; retry starts a fresh session");
                        if(error.matches("-\\d+"))throw new RpcException(-32015,"MEGA rejected upload chunk ("+error+")");
                        t.completionHandle=MiscTools.Bin2UrlBASE64(response);
                    }
                    t.completedBytes=offset+length;context.changed(t);
                }
                offset+=length;chunkId++;
            } while(offset<t.totalBytes);
        }
        check(t);checkSource(t,path);t.status="verifying";context.changed(t);
        int[] mac=MegaFileCrypto.mac(path,key,iv),ul=t.uploadKey;
        int[] nodeKey={ul[0]^ul[4],ul[1]^ul[5],ul[2]^mac[0],ul[3]^mac[1],ul[4],ul[5],mac[0],mac[1]};
        checkSource(t,path);
        if(t.completionHandle==null)throw new RpcException(-32015,"MEGA did not acknowledge upload completion");
        if(t.nodeHandle==null)t.nodeHandle=api.findOwnNodeHeadless(t.parentNode==null?api.getRoot_id():t.parentNode,path.getFileName().toString(),0,i32a2bin(nodeKey));
        if(t.nodeHandle==null) {
            Map result=t.shareKey==null?api.finishUploadFileHeadless(path.getFileName().toString(),ul,nodeKey,t.completionHandle,t.parentNode==null?api.getRoot_id():t.parentNode):api.finishUploadFileHeadless(path.getFileName().toString(),ul,nodeKey,t.completionHandle,t.parentNode,t.rootNode,MiscTools.UrlBASE642Bin(t.shareKey));
            if(result==null||!(result.get("f") instanceof List)||((List)result.get("f")).isEmpty())throw new RpcException(-32015,"MEGA node publication failed");
            t.nodeHandle=(String)((Map)((List)result.get("f")).get(0)).get("h");context.changed(t);
        }
        if(t.thumbnailEnabled&&!t.thumbnailComplete){
            Path thumbnail=HeadlessThumbnailer.create(path,context.profile);
            if(thumbnail!=null)try{
                String result=api.uploadThumbnailsHeadless(key,t.nodeHandle,thumbnail.toString(),thumbnail.toString(),()->t.stop||context.closed,out->new FilterOutputStream(out){
                    @Override public void write(byte[] b,int off,int len)throws IOException{try{context.throttle(t,"upload",len);out.write(b,off,len);}catch(InterruptedException ex){Thread.currentThread().interrupt();throw new IOException("Thumbnail upload interrupted");}}
                });
                if(result==null||result.isEmpty())context.events.accept(EngineMain.map("type","thumbnail","id",t.id,"status","failed"));
            }finally{Files.deleteIfExists(thumbnail);}
            t.thumbnailComplete=true;context.changed(t);
        }
        if(t.publicLinkEnabled)t.publicLink=api.getPublicFileLink(t.nodeHandle,i32a2bin(nodeKey));
    }
    void checkSource(Transfer t,Path path) throws Exception {if(Files.size(path)!=t.totalBytes||Files.getLastModifiedTime(path).toMillis()!=t.modifiedTime)throw new RpcException(-32014,"Upload source changed during transfer; no file was published");}
    byte[] uploadChunk(Transfer t,String url,byte[] bytes) throws Exception {
        int failures=0;
        while(true) {
            check(t);context.awaitPayload(t);HttpURLConnection connection=null;
            try {
                connection=context.open(url,failures>0);connection.setRequestMethod("POST");connection.setDoOutput(true);connection.setFixedLengthStreamingMode(bytes.length);
                try(OutputStream out=connection.getOutputStream()){for(int offset=0;offset<bytes.length;){check(t);int length=Math.min(65536,bytes.length-offset);context.throttle(t,"upload",length);out.write(bytes,offset,length);offset+=length;}}
                int status=connection.getResponseCode();if(status==403||status==404||status==410)throw new RpcException(-32016,"Upload session expired; retry starts a fresh session");if(status!=200)throw new IOException();
                try(InputStream in=connection.getInputStream();ByteArrayOutputStream result=new ByteArrayOutputStream()){byte[] buf=new byte[128];int n;while((n=in.read(buf))!=-1){if(result.size()+n>1024)throw new IOException();result.write(buf,0,n);}return result.toByteArray();}
            } catch(IOException e){if(++failures>context.integer("retryLimit",8))throw new RpcException(-32015,"MEGA upload failed after retries; resume to retry");for(int i=0;i<Math.min(300,failures*10);i++){check(t);Thread.sleep(100);}}
            finally {if(connection!=null)connection.disconnect();}
        }
    }
}
