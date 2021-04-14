package io.pe.crypto.mycoin.model;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;

@Data
@Getter
public class Block {
    
    private static Logger logger = Logger.getLogger(Block.class.getName());
    
    private final String data;
    private final String previousHash;
    private final long timeStamp;
    private String hash;
    private int nonce;
    
    public Block(String data, String previousHash, long timeStamp) {
        this.data = data;
        this.previousHash = previousHash;
        this.timeStamp = timeStamp;
        this.hash = calculateBlockHash();
    }
    
    public String calculateBlockHash() {
        String dataToHash = previousHash 
          + Long.toString(timeStamp) 
          + Integer.toString(nonce) 
          + data;

        MessageDigest digest = null;
        byte[] bytes = null;
        
        try {
            digest = MessageDigest.getInstance("SHA-256");
            bytes = digest.digest(dataToHash.getBytes("UTF-8"));
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException ex) {
            logger.log(Level.SEVERE, ex.getMessage());
        }
        
        StringBuffer buffer = new StringBuffer();
        for (byte b : bytes) {
            buffer.append(String.format("%02x", b));
        }
        return buffer.toString();
    }
    
    public String mineBlock(int prefix) {
        String prefixString = new String(new char[prefix]).replace('\0', '0');
        while (!hash.substring(0, prefix).equals(prefixString)) {
            logger.log(Level.INFO, String.format("prefix[ %d ], hash[ %s ] | hash.substr[ %s ] !== prefixString[ %s ]", prefix, hash, hash.substring(0, prefix), prefixString));
            nonce++;
            hash = calculateBlockHash();
        }
        logger.log(Level.INFO, String.format("prefix[ %d ], hash[ %s ] | hash.substr[ %s ] !== prefixString[ %s ]", prefix, hash, hash.substring(0, prefix), prefixString));
        return hash;
    }

}
