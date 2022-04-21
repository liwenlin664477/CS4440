package HA2;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Random;
import java.net.Socket;
import java.net.ServerSocket;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;
import java.util.logging.FileHandler;

public class Server {
	private static final int PORT = 1337;
	private static final String AESKEY = "1234567890123456";
	private static final String OKMSG = "OK.";
	private static final String SRVPRIKEY = "MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBAIMBnOFB1QgeRYu0Mh7Stc409gDAZjxbGI6pzsMB8kv/GhdCRgbTN6nvrqSqQIcU7O67kQpTaDTdBttYg2DEa3q3YszpnKqhEmEzuDeYvFnhOwfmHASVzp6r8ocZG48T9/946YFYBU5UuAp2kcNkbN0DsxmO6+NgSBGEhKvf9gqdAgMBAAECgYBxkb5ckOOLLCMCH26rxeMSJlt0/1Yh0J8TXiX+a/uO4lHOBAgM9qJ00XHHEkjqUbusojH0j6Xw3gOJt8v84YqCFDJ6YgigKkmCGCytsoAHdxS8tMXDY+Tncrh8kh7mvcvdmU1sgxDmnZh3VkAzm+PPlyL5oC3NeJFd9IgGCBmkCQJBAL1UqgHlRV6uYoaCSyOaLIKEhI4LeGILgt1nkbpP151T0Od54FbbTQkirEUr4RvupJs/H6HvAONgHD9ax0rwgJcCQQCxI0HuQSQXJzVFm1WxWh0wTQoHTFc0eQZqEeDWqjmE/pd1/9QeHOKd214uQ5E/gsYPrLPYIw+AIOkkAlQKUADrAkEAmNRM33bZBlKyCW4HhVegckLSVW8A3/P20Q4XXlOw8riDuzZwVuxzRNqOQM/oyIlcqkzMFgU9rE0awDFhCicVRQJBAJZqG/gWdHD8qC29I1z/6j0zjcp4tqwmAJ5dJBDkZwdZsH9Qh2wylvP4bNbYJSRLBagVvHlR/D2OtKoRGA/Rs5UCQQCQe1vmjkkuesFy6RXIZoVlMcrJwXqoS4a9EHBmR8tF6UHdN8r4CWu2SX1oqY2xI9EzqoAP+nIdKuPVJ+ItrMhO";
	private ServerSocket serverSocket;
	private Socket connSocket;
	private BufferedReader socketIn;
	private DataOutputStream socketOut;

	public void runServer() throws IOException {

		Logger logger = Logger.getLogger("MyLog");  
		FileHandler fh;  

		try {  

			// This block configure the logger with handler and formatter  
			fh = new FileHandler("/tmp/MyServerLogFile.log");  
			logger.addHandler(fh);
			SimpleFormatter formatter = new SimpleFormatter();  
			fh.setFormatter(formatter);  

			// the following statement is used to log any messages  
			logger.info("==== RSA server log ==== ");  

		} catch (SecurityException e) {  
			e.printStackTrace();  
		} catch (IOException e) {  
			e.printStackTrace();  
		}  

		while (true) {
			try {
				System.out.printf("[*] Listening on port %d...\n", PORT);
				serverSocket = new ServerSocket(PORT);
				connSocket = serverSocket.accept();
				socketIn = new BufferedReader(new InputStreamReader(connSocket.getInputStream()));
				socketOut = new DataOutputStream(connSocket.getOutputStream());

				// Recv 
				String clientIP = connSocket.getRemoteSocketAddress().toString();
				logger.info("Got Client's connetion: " + clientIP);
				String pubKeySig = socketIn.readLine().trim();
				String pubKey = socketIn.readLine().trim();
				System.out.println("Public key (Client):" + pubKey);
				System.out.println("Public key's signature: " + pubKeySig);
				PublicKey CliPublicKey = RSAUtils.getPublicKey(pubKey);
				logger.info("Got Client's signature and public key\n (+20)");

				boolean sigClient1 = RSAUtils.verify(pubKey, CliPublicKey, pubKeySig);

				System.out.println("Signature check: " + sigClient1);
				if (!sigClient1) {
					System.out.println("Client Signature (1) mismatch!");
					closeConn();
					continue;
				}
				logger.info("Client's Signature (1) verification passed \n(+20) ");

				String encAESKey = RSAUtils.encryptByPublicKey(AESKEY, RSAUtils.getPublicKey(pubKey));
				String randomStr = RSAUtils.randomAlphabeticString();
				String srvSig = RSAUtils.sign(encAESKey + randomStr, RSAUtils.getPrivateKey(SRVPRIKEY));

				// 1st Response to client
				socketOut.writeBytes(encAESKey + "\n" + randomStr + " " + clientIP + "\n" + srvSig + "\n");

				// Recv 2
				String sigRand = socketIn.readLine().replace("\n", "").replace("\r", "");
				String encRandomStr = socketIn.readLine().replace("\n", "").replace("\r", "");
				boolean sigClient2 = RSAUtils.verify(encRandomStr, CliPublicKey, sigRand);

				if (!sigClient2) {
					System.out.println("Client Signature (2) mismatch!");
					closeConn();
					continue;
				}

				logger.info("Client's Signature (2) verification passed \n (+20) ");
				String decRandStr = RSAUtils.aesDecrypt(encRandomStr, AESKEY);

				if (decRandStr.equals(randomStr)) {
					System.out.println("Aes decrypted successfully");
					logger.info("Decryption of Client's message succeeded. \n (+20) ");
				}


				// send OK
				String okSig = RSAUtils.sign(OKMSG, RSAUtils.getPrivateKey(SRVPRIKEY));
				socketOut.writeBytes(OKMSG + "\n" + okSig + "\n" + clientIP);

				// while(!(serverSocket.isClosed())){
				//     // Listen for and validate client incoming message
				//     String input = socketIn.readLine();
				//     if (input != null && !input.trim().equals("")){

				//         // Stream to console
				//         System.out.println("message received: " + input);
				//     }
				// }

				closeConn();
				System.out.println("Server connection closed");
				logger.info("Connection closed.\n (+20)\n========");


			} catch (Exception e) {
				e.printStackTrace();
				continue;
			} finally {
				closeConn();
			}
		}
	}

	public void closeConn() throws IOException {
		serverSocket.close();
		connSocket.close();
		socketIn.close();
		socketOut.close();
	}

	public static void main(String[] args) throws IOException {
		Server server = new Server();
		server.runServer();
	}
}
