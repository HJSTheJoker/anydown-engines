package com.tonikelope.megabasterd.headless;
import java.util.*;
/** Durable private transfer state. Only snapshot() may cross the public boundary. */
public final class Transfer {
    public String id, direction="download",status="queued",name="",url,directory,path,accountId,parentNode;
    public String temporaryPath,rootNode,shareKey;
    public String sourceKind="mega",fileKey,passHash,noexpire;
    public String outputPath,error,uploadUrl,completionHandle,nodeHandle,publicLink;
    public long totalBytes,completedBytes,modifiedTime;
    public int[] uploadKey;
    public int order;
    public volatile Long rateLimitBytesPerSecond;
    public boolean integrityVerified;
    public transient volatile long quotaUntil;
    public transient long nextRateNanos, speedWindowNanos, speedWindowBytes;
    public List<Long> completedChunks=new ArrayList<>();
    public boolean publicLinkEnabled;
    public boolean thumbnailEnabled=true,thumbnailComplete;
    public boolean publishPending;
    public transient volatile boolean stop;
    public transient volatile boolean running;
    public transient volatile Thread worker;
    public transient volatile long speedBytesPerSecond;
    public Map<String,Object> snapshot() {
        return EngineMain.map("id",id,"direction",direction,"status",status,"name",name,
            "totalBytes",totalBytes,"completedBytes",completedBytes,"speedBytesPerSecond",speedBytesPerSecond,
            "error",error,"integrityVerified",integrityVerified,"outputPath",outputPath,"order",order,"accountId",accountId);
    }
}
