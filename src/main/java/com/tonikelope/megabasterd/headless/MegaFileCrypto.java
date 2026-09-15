package com.tonikelope.megabasterd.headless;
import com.tonikelope.megabasterd.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import javax.crypto.Cipher;
import static com.tonikelope.megabasterd.CryptTools.*;
import static com.tonikelope.megabasterd.MiscTools.*;

/** The chunk CBC-MAC algorithm extracted from upstream UploadMACGenerator. */
public final class MegaFileCrypto {
    public static int[] mac(Path path,byte[] key,byte[] iv) throws Exception {
        int[] nonce=bin2i32a(iv),fileMac=new int[4];
        Cipher cryptor=genCrypter("AES","AES/CBC/NoPadding",key,AES_ZERO_IV);
        long size=Files.size(path),offset=0,chunkId=1;
        try(InputStream in=Files.newInputStream(path)) {
            while(offset<size) {
                if(Thread.currentThread().isInterrupted())throw new InterruptedException("Integrity verification interrupted");
                long chunkSize=ChunkWriterManager.calculateChunkSize(chunkId,size,offset,1);
                int[] chunkMac={nonce[0],nonce[1],nonce[0],nonce[1]};
                long read=0;
                while(read<chunkSize) {
                    if(Thread.currentThread().isInterrupted())throw new InterruptedException("Integrity verification interrupted");
                    byte[] block=new byte[16];int length=(int)Math.min(16,chunkSize-read),n=0;
                    while(n<length) { int r=in.read(block,n,length-n);if(r<0)throw new EOFException();n+=r; }
                    int[] words=bin2i32a(block);for(int i=0;i<4;i++)chunkMac[i]^=words[i];
                    chunkMac=bin2i32a(cryptor.doFinal(i32a2bin(chunkMac)));read+=length;
                }
                for(int i=0;i<4;i++)fileMac[i]^=chunkMac[i];
                fileMac=bin2i32a(cryptor.doFinal(i32a2bin(fileMac)));offset+=chunkSize;chunkId++;
            }
        }
        return new int[]{fileMac[0]^fileMac[1],fileMac[2]^fileMac[3]};
    }
    public static void verify(Path path,String encodedKey) throws Exception {
        int[] key=bin2i32a(MiscTools.UrlBASE642Bin(encodedKey));
        if(key.length!=8)throw new RpcException(-32010,"File key length is invalid");
        int[] actual=mac(path,initMEGALinkKey(encodedKey),initMEGALinkKeyIV(encodedKey));
        if(!java.security.MessageDigest.isEqual(i32a2bin(actual),i32a2bin(new int[]{key[6],key[7]})))
            throw new RpcException(-32011,"MEGA integrity verification failed");
    }
}
