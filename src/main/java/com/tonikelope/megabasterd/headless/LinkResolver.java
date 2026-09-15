package com.tonikelope.megabasterd.headless;
import com.tonikelope.megabasterd.*;
import java.util.*;
import java.net.URI;
import java.util.regex.*;
import static com.tonikelope.megabasterd.headless.EngineMain.map;

/** Link decryption stays private; clients select nodes using opaque IDs. */
public final class LinkResolver {
    public static final class Node {
        public String id,name,type,parentId,url,sourceKind="mega",fileKey,passHash,noexpire;
        public long size;
        public Map<String,Object> snapshot() { return map("id",id,"name",name,"type",type,"size",size,"parentId",parentId); }
    }
    public static final class Resolution {
        public String resolutionId,name,type;
        public long size;
        public List<Node> children=new ArrayList<>();
        public Map<String,Object> snapshot() { List<Object> nodes=new ArrayList<>(); for(Node n:children) nodes.add(n.snapshot()); return map("resolutionId",resolutionId,"name",name,"type",type,"size",size,"children",nodes); }
    }
    public static Resolution resolve(String input,boolean cache) throws Exception { return resolve(input,cache,new MegaAPI()); }
    static Resolution resolve(String input,boolean cache,MegaAPI api) throws Exception {
        if(input==null||input.length()>16384) throw new RpcException(-32602,"A valid MEGA link is required");
        String normalized=input.trim().replaceFirst("(?i)^(https?://)www\\.(?=mega\\.(?:co\\.)?nz(?:/|$))","$1");
        String url=MiscTools.newMegaLinks2Legacy(CryptTools.decryptMegaDownloaderLink(normalized)).trim().replace("#f!","#F!");
        URI uri=URI.create(url);
        if(!"https".equals(uri.getScheme())||!("mega.nz".equalsIgnoreCase(uri.getHost())||"mega.co.nz".equalsIgnoreCase(uri.getHost())))
            throw new RpcException(-32602,"A HTTPS MEGA link is required");
        Resolution result=new Resolution(); result.resolutionId=UUID.randomUUID().toString();

        Matcher folder=Pattern.compile("#F!([A-Za-z0-9_-]+)(?:@([A-Za-z0-9_-]+))?!([A-Za-z0-9_-]+)$").matcher(url);
        Matcher selected=Pattern.compile("#F\\*([A-Za-z0-9_-]+)!([A-Za-z0-9_-]+)!([A-Za-z0-9_-]+)$").matcher(url);
        boolean selectedFile=selected.find();
        if(folder.find()||selectedFile) {
            String folderId=selectedFile?selected.group(2):folder.group(1);
            String key=selectedFile?selected.group(3):folder.group(3);
            String selectedId=selectedFile?selected.group(1):folder.group(2);
            if(MiscTools.UrlBASE642Bin(key).length!=16) throw new RpcException(-32602,"Folder key is invalid");
            Map<String,Object> raw=api.getFolderNodes(folderId,key,null,cache);
            Map<String,String> ids=new HashMap<>(); for(String id:raw.keySet()) ids.put(id,UUID.randomUUID().toString());
            for(Map.Entry<String,Object> entry:raw.entrySet()) {
                Map node=(Map)entry.getValue();
                if(selectedId!=null&&!belongsTo(entry.getKey(),selectedId,raw,selectedFile)) continue;
                Node n=new Node(); n.id=ids.get(entry.getKey()); n.parentId=ids.get((String)node.get("parent"));
                n.name=(String)node.get("name"); n.type=((Number)node.get("type")).intValue()==0?"file":"folder";
                n.size=((Number)node.get("size")).longValue();
                n.url="https://mega.nz/#N!"+entry.getKey()+"!"+node.get("key")+"###n="+folderId;
                result.children.add(n); if("file".equals(n.type)) result.size+=n.size;
                if(entry.getKey().equals(selectedId!=null?selectedId:folderId)) result.name=n.name;
            }
            result.type=selectedFile?"file":"folder";
            if(result.name==null) result.name="MEGA folder";
        } else {
            if(!url.matches("https://mega\\.(?:co\\.)?nz/#![A-Za-z0-9_-]+![A-Za-z0-9_-]+")) throw new RpcException(-32602,"Unsupported MEGA link format");
            String[] metadata=api.getMegaFileMetadata(url);
            Node node=new Node(); node.id=UUID.randomUUID().toString(); node.name=metadata[0]; node.size=Long.parseLong(metadata[1]); node.type="file"; node.url=url;
            result.children.add(node); result.name=node.name;result.type="file";result.size=node.size;
        }
        if(result.children.isEmpty()) throw new RpcException(-32010,"The MEGA folder contains no accessible nodes");
        return result;
    }
    private static boolean belongsTo(String id,String selected,Map<String,Object> raw,boolean file) {
        Set<String> visited=new HashSet<>();
        while(id!=null&&visited.add(id)) { if(id.equals(selected))return true; if(file)return false; Map n=(Map)raw.get(id);id=n==null?null:(String)n.get("parent"); }
        return false;
    }
    public static String relativeName(Node node,Resolution resolution) throws RpcException {
        Map<String,Node> byId=new HashMap<>(); for(Node n:resolution.children)byId.put(n.id,n);
        LinkedList<String> parts=new LinkedList<>();Set<String> seen=new HashSet<>();
        while(node!=null&&seen.add(node.id)) { String safe=MiscTools.cleanFilename(node.name); if(safe==null||safe.isEmpty()||safe.equals(".")||safe.equals(".."))throw new RpcException(-32010,"Unsafe filename in MEGA folder"); parts.addFirst(safe);node=byId.get(node.parentId); }
        return String.join(java.io.File.separator,parts);
    }
}
