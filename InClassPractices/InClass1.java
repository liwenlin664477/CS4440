package InClass;

import java.util.Scanner;



public class InClass1 {
	

	public static String table = "AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz";
	
	public static void main(String[] args) {
		
		InClass1 class1 =  new InClass1();
		String plainText = "";
		String ciphertext = "ebiiltloia";
		
		
		System.out.println("Cipher Text£º " + decrypt(ciphertext, 23));
		
		
	}
	
	   public static String encrypt(String plaintext, int key) {
	        char[] plain = plaintext.toCharArray();
	        for(int  i=0;i<plain.length;i++){
	            if(!Character.isLetter(plain[i])){
	                continue;
	            }
	            plain[i]=cipher(plain[i],key);
	        }
	        return new String(plain);
		   }
	   
	   private static char cipher(char c, int k) {
		      
	        int position = (table.indexOf(c)+k)%52;
	        return table.charAt(position);
		   }
	   

	   public static String decrypt(String ciphertext, int shift) {
		      
	        char[] plain = ciphertext.toCharArray();
	        for(int  i=0;i<plain.length;i++){
	            if(!Character.isLetter(plain[i])){
	                continue;
	            }
	            plain[i]=decCipher(plain[i],shift);
	        }
	        return new String(plain);
		   }
	   
	    private static  char decCipher(char str,int k){
	        int position = (table.indexOf(str)-k)%52;
	        position = position<0?52+position:position;
	        return table.charAt(position);

	    }
		
		
	
}
