package HA2;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.net.Socket;
import java.io.ByteArrayOutputStream;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;


public class Client {
    private static final int PORT = 1337;
    private static final String SRVPUBKEY = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCDAZzhQdUIHkWLtDIe0rXONPYAwGY8WxiOqc7DAfJL/xoXQkYG0zep766kqkCHFOzuu5EKU2g03QbbWINgxGt6t2LM6ZyqoRJhM7g3mLxZ4TsH5hwElc6eq/KHGRuPE/f/eOmBWAVOVLgKdpHDZGzdA7MZjuvjYEgRhISr3/YKnQIDAQAB";

    public static void main(String[] args) throws IOException {
	//put your code here;
    }
}
