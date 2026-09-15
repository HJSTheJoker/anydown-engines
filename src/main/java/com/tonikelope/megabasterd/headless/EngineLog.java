package com.tonikelope.megabasterd.headless;
import java.nio.file.*;
import java.util.*;
import java.io.*;
import static com.tonikelope.megabasterd.headless.EngineMain.*;
/** Bounded diagnostic history containing only events already safe for AnyDown's UI. */
final class EngineLog {
    private final Path path;
    private final Deque<Map<String,Object>> recent=new ArrayDeque<>();
    EngineLog(Path profile)throws IOException{path=profile.resolve("events.jsonl");if(Files.exists(path)){try(BufferedReader reader=Files.newBufferedReader(path)){String line;while((line=reader.readLine())!=null){if(line.length()>65536)continue;try{recent.addLast(JSON.readValue(line,LinkedHashMap.class));if(recent.size()>1000)recent.removeFirst();}catch(IOException ignored){}}}}}
    synchronized void append(Map<String,Object> event){
        // Progress is already persisted by transfer checkpoints; recording every block wastes disk.
        Object type=event.get("type");if("transfer".equals(type)){Object transfer=event.get("transfer");if(transfer instanceof Map&&!Arrays.asList("completed","failed","cancelled","paused").contains(((Map)transfer).get("status")))return;}
        Map<String,Object> entry=map("time",java.time.Instant.now().toString(),"event",event);recent.addLast(entry);if(recent.size()>1000)recent.removeFirst();
        try{if(Files.exists(path)&&Files.size(path)>1024*1024){Path rotated=path.resolveSibling("events.previous.jsonl");Files.move(path,rotated,StandardCopyOption.REPLACE_EXISTING);}Files.write(path,(JSON.writeValueAsString(entry)+"\n").getBytes(java.nio.charset.StandardCharsets.UTF_8),StandardOpenOption.CREATE,StandardOpenOption.APPEND);EngineContext.privateFile(path);}catch(IOException ignored){}
    }
    synchronized List<Object> list(int limit){List<Object> all=new ArrayList<>(recent);return all.subList(Math.max(0,all.size()-Math.min(1000,Math.max(1,limit))),all.size());}
}
