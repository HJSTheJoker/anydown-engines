/* AnyDown headless integration. GPL-3.0, like the MegaBasterd engine. */
package com.tonikelope.megabasterd.headless;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.logging.*;

/** Private, line-framed JSON-RPC. stdout is reserved exclusively for protocol data. */
public final class EngineMain {
    public static final ObjectMapper JSON = new ObjectMapper();
    private static final int MAX_REQUEST = 4 * 1024 * 1024;
    private final PrintWriter output;
    private final ExecutorService requests = Executors.newFixedThreadPool(8);
    private final EngineContext context;
    private volatile boolean closing;

    EngineMain(Path profile, PrintWriter output) throws Exception {
        this.output = output;
        this.context = new EngineContext(profile, this::event);
    }
    public static Map<String,Object> map(Object... pairs) {
        Map<String,Object> result = new LinkedHashMap<>();
        for (int i=0;i<pairs.length;i+=2) result.put((String)pairs[i], pairs[i+1]);
        return result;
    }
    synchronized void send(Object value) {
        try { output.println(JSON.writeValueAsString(value)); output.flush(); }
        catch (IOException e) { System.err.println("Protocol serialization failed"); }
    }
    void event(Map<String,Object> value) { send(map("jsonrpc","2.0","method","event","params",value)); }
    void handle(String line) {
        JsonNode id = null;
        try {
            JsonNode request = JSON.readTree(line);
            id = request.get("id");
            if (!"2.0".equals(request.path("jsonrpc").asText()) || !request.path("method").isTextual())
                throw new RpcException(-32600,"Invalid JSON-RPC request");
            String method = request.path("method").asText();
            JsonNode params = request.path("params");
            if (!params.isMissingNode() && !params.isObject()) throw new RpcException(-32602,"params must be an object");
            Object result = context.call(method, params);
            if (id != null) send(map("jsonrpc","2.0","id",id,"result",result));
            if ("engine.shutdown".equals(method)) { closing=true; context.close(); System.exit(0); }
        } catch (Exception ex) {
            Throwable error = ex instanceof CompletionException ? ex.getCause() : ex;
            if (!(error instanceof RpcException)) { System.err.println(error.getClass().getName()); for(StackTraceElement frame:error.getStackTrace()) System.err.println(" at "+frame); }
            int code = error instanceof RpcException ? ((RpcException)error).code : -32000;
            // Network exceptions frequently contain secret capability URLs. Never serialize them.
            String message = error instanceof RpcException ? error.getMessage() : "Engine operation failed ("+error.getClass().getSimpleName()+")";
            send(map("jsonrpc","2.0","id",id,"error",map("code",code,"message",message)));
        }
    }
    void run(Reader input) throws IOException {
        StringBuilder line = new StringBuilder();
        try (Reader reader = new BufferedReader(input)) {
            int c;
            while (!closing && (c=reader.read()) != -1) {
                if (c=='\n') { String request=line.toString(); line.setLength(0); if (!request.trim().isEmpty()) requests.submit(()->handle(request)); }
                else if (c!='\r') { if (line.length()>=MAX_REQUEST) throw new IOException("Request exceeds limit"); line.append((char)c); }
            }
        } finally {
            requests.shutdown();
            try { requests.awaitTermination(5,TimeUnit.SECONDS); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
            context.close();
        }
    }
    public static void main(String[] args) throws Exception {
        System.setProperty("java.awt.headless","true");
        Path profile=null;
        for (int i=0;i<args.length;i++) if (("--profile".equals(args[i]) || "--data-dir".equals(args[i])) && i+1<args.length) profile=Paths.get(args[++i]);
        if (profile==null) throw new IllegalArgumentException("--profile PATH is required");
        PrintStream protocol=System.out;
        System.setOut(System.err); // upstream diagnostic println calls must never corrupt JSON-RPC.
        // Upstream detailed logs include account ids, node keys and provider URLs. Headless logs
        // use our redacted state events; upstream logging stays disabled until redacted upstream.
        Logger.getLogger("com.tonikelope.megabasterd").setLevel(Level.OFF);
        EngineMain engine=new EngineMain(profile,new PrintWriter(new OutputStreamWriter(protocol,StandardCharsets.UTF_8),true));
        Runtime.getRuntime().addShutdownHook(new Thread(engine.context::close,"engine-checkpoint"));
        engine.run(new InputStreamReader(System.in,StandardCharsets.UTF_8));
    }
}
