package com.tonikelope.megabasterd.headless;
import java.util.*;
/** Checkpoint remote folder keys BEFORE creation so retries can discover the exact node. */
public final class TransferGroup {
    public String id,path,accountId,parentNode,shareKey,publicLink;
    public List<String> children=new ArrayList<>();
    public Map<String,String> folders=new LinkedHashMap<>();
    public Map<String,String> folderKeys=new LinkedHashMap<>();
    public boolean complete;
}
