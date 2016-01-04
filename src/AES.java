import java.util.Arrays;
import java.util.Base64;
import java.util.Base64.*;
import java.util.Scanner;

public class AES {
	private static final int KEY_SIZE = 128;
	private static final int BLOCK_SIZE = 128;
	private static final int ENCRYPTION_ROUNDS = 9;
	private static final int ROUND_KEYS_NEEDED = 11;
	
	public static String Encrypt(String text, String key) {
		//Getting all the round keys needed
		byte[] expandedKeys = KeyExpansion(key);
			
		//Getting the text to be encrypted into matrix form
		byte[][] stateMatrix = Helper.toMatrix(text.getBytes());
		
		//Initial AddRoundKey step
		stateMatrix = AddRoundKey(stateMatrix, Helper.toMatrix(Arrays.copyOfRange(expandedKeys, 0, 16)));
				
		//Goes through the first 9 rounds for a 128 bit key in AES
		for (int i = 1; i <= ENCRYPTION_ROUNDS; i++) {
			//Each round of AES cipher, copy over the round key being used
			stateMatrix = encryptionRound(stateMatrix, Helper.toMatrix(Arrays.copyOfRange(expandedKeys, 16*i, 16*i+16)));
		}
		
		//Last round of AES cipher, copy over the last round key to be used
		stateMatrix = encryptionFinalRound(stateMatrix, Helper.toMatrix(Arrays.copyOfRange(expandedKeys, 160, 176)));

		return new String(Helper.toArray(stateMatrix));
	}
	
	private static byte[][] encryptionRound(byte[][] stateMatrix, byte[][] roundKeyByteMatrix) {
		 
		stateMatrix = SubBytes(stateMatrix);
		stateMatrix = ShiftRows(stateMatrix);
		stateMatrix = MixColumns(stateMatrix);
		stateMatrix = AddRoundKey(stateMatrix, roundKeyByteMatrix);
		
		return stateMatrix;
	}
	
	private static byte[][] encryptionFinalRound(byte[][] stateMatrix, byte[][] roundKeyByteMatrix) {
		
		stateMatrix = SubBytes(stateMatrix);
		stateMatrix = ShiftRows(stateMatrix);
		stateMatrix = AddRoundKey(stateMatrix, roundKeyByteMatrix);
		
		return stateMatrix;
	}
	
	private static byte[] KeyExpansion(String key) {		
		byte[] keyByteArray = Helper.toByteArray(key);
		byte[] expandedKeyBytes = new byte[ROUND_KEYS_NEEDED*KEY_SIZE/8];
		
		int currentSize = 0;  	//Current size of the expanded keys in bytes
		int rconIterator = 1;   //Round constant counter
		byte t[] = new byte[4]; //Temp 4-byte variable
		
		// First 16 bytes of the expanded key is the input key
		for (int i = 0; i < KEY_SIZE/8; i++) {
			expandedKeyBytes[i] = keyByteArray[i];
		}
		currentSize += KEY_SIZE/8;
		
		while (currentSize < ROUND_KEYS_NEEDED*KEY_SIZE/8) {
			//t is set as the previous 4 bytes
			for (int i = 0; i < 4; i++) {
				t[i] = expandedKeyBytes[(currentSize - 4) + i];
			}
			//Perform the core operations of the key schedule and increment rcon
			if ((currentSize % (KEY_SIZE/8)) == 0) {
				t = keyScheduleCore(t, rconIterator++);
			}
			//XOR the key with t
			for (int i = 0; i < 4; i++) {
				expandedKeyBytes[currentSize] = (byte) (expandedKeyBytes[currentSize - KEY_SIZE/8] ^ t[i]);
				currentSize++;
			}
		}
		return expandedKeyBytes;
	}
	
	private static byte[] keyScheduleCore(byte[] word, int rconIterator) {
		//Rotate to the left by 1 byte
		Helper.shiftLeft(word);
		
		//Apply SBox substitution
		for (int i = 0; i < 4; i++) {
			word[i] = SBox(word[i]);
		}
		//XOR the first byte with the RCon
		word[0] ^= RCon((byte) rconIterator);
		
		return word;
	}
	
	private static byte[][] AddRoundKey(byte[][] stateMatrix, byte[][] roundKeyByteMatrix) {		
		//XORing each state matrix byte with the key's byte
		int matrixLength = roundKeyByteMatrix.length;
		
		for (int col = 0; col < matrixLength; col++) {
			for (int row = 0; row < matrixLength; row++) {
				stateMatrix[row][col] ^= roundKeyByteMatrix[row][col];
			}
		}
		return stateMatrix;
	}
	
	private static byte[][] SubBytes(byte[][] stateMatrix) {		
		int matrixLength = stateMatrix.length;
		
		//Traverse the state matrix and do SBox substitutions
		for (int col = 0; col < matrixLength; col++) {
			for (int row = 0; row < matrixLength; row++) {
				stateMatrix[row][col] = SBox(stateMatrix[row][col]);
			}
		}
		return stateMatrix;
	}
	
	private static byte[][] ShiftRows(byte[][] stateMatrix) {
		//AES Shift row steps
		byte[][] output = new byte[4][4];
		
		//Row #0 is left alone 
		output[0][0] = stateMatrix[0][0];
		output[0][1] = stateMatrix[0][1];
		output[0][2] = stateMatrix[0][2];
		output[0][3] = stateMatrix[0][3];
		
		//Rotate row #1, 1 positions to the left
	    output[1][0] = stateMatrix[1][1];
	    output[1][1] = stateMatrix[1][2];
	    output[1][2] = stateMatrix[1][3];
	    output[1][3] = stateMatrix[1][0];
	    
	    // Rotate row #2, 2 positions to the left
	    output[2][0] = stateMatrix[2][2];
	    output[2][2] = stateMatrix[2][0];
	    output[2][1] = stateMatrix[2][3];
	    output[2][3] = stateMatrix[2][1];
	    
	    // Rotate row #3, 3 positions to the left
	    output[3][0] = stateMatrix[3][3];
	    output[3][3] = stateMatrix[3][2];
	    output[3][2] = stateMatrix[3][1];
	    output[3][1] = stateMatrix[3][0];
	    
		return output;
	}
	
	private static byte[][] MixColumns(byte[][] stateMatrix) {
		//The mix columns step is just a matrix multiplication 
		//of the state matrix and mix columns matrix below
		byte[][] mixColumnMatrix = {{0x02, 0x03, 0x01, 0x01},
				{0x01, 0x02, 0x03, 0x01},
				{0x01, 0x01, 0x02, 0x03}, 
				{0x03, 0x01, 0x01, 0x02}};

		return Helper.matrixMultiplication(mixColumnMatrix, stateMatrix);
	}
	
	private static byte SBox(byte input) {
		if (input == 0) {
			return 0x63;
		} else {
			byte inverse = Helper.galoisMultiplicativeInverse(Byte.toUnsignedInt(input));
			
			//Reverses inverse to get the least significant bit order (LSB)
			byte LSB = (byte) (Integer.reverse(inverse << 24) & 0xff);
			
			//Setting up the 0x1F AES affine transformation matrix
			byte[] affineMatrix = new byte[8];
			for (int i = 0; i < 8; i++) {
				byte row = Byte.valueOf("-113");
				for (int j = 0; j < i; j++) {
					row = Helper.rotateByte(row);
				}
				affineMatrix[i] = row;
			}
			//Going through the affine matrix
			byte[] resultBitArray = new byte[8];
			for (int i = 0; i < 8; i++) {
				//ANDing the input and each row of the affine matrix
				byte bit = (byte) (affineMatrix[i] & LSB);
				//XORing the bits of the result to get the bit in position i
				resultBitArray[i] = Helper.xorByte(bit);
			}
			//MSB first of resultBitArray combined to byte
			byte result = (byte) (Integer.reverse(Helper.toByte(resultBitArray) << 24) & 0xff);
			
			return (byte) (result ^ 0x63);
		}
	}
	
	private static byte RCon(byte input) {
		//Calculate the round constant on the fly
		byte c = 1;
		if(input == 0)  
            return 0; 
	    while(input != 1) {
	            c = Helper.galoisMultiply(c,(byte) 2);
	            input--;
	    }
	    return c;
	}
	
	public static void main(String[] args) {
		Encoder base64Encoder = Base64.getEncoder();
		Scanner scanner = new Scanner(System.in);

		//Getting text to be encrypted from the user
		int textBitLength = 0;
		String text = "";
		
		while (textBitLength != BLOCK_SIZE) {
			System.out.print("Plaintext to Encrypt: ");
			text = scanner.nextLine();
			 
			textBitLength = text.getBytes().length*8;
			
			if (textBitLength != BLOCK_SIZE) {
				System.out.println("Please enter a valid length of text (128 bits)");
			}
		}
		
		//Getting the encryption key from the user
		int keyBitLength = 0;
		String key = "";
		
		while (keyBitLength != KEY_SIZE) {
			System.out.print("Key to Encrypt With (in Hex with no spaces): ");
			key = scanner.nextLine();
			 
			keyBitLength = key.getBytes().length*4;
			
			if (keyBitLength != KEY_SIZE) {
				System.out.println("Please enter a key with valid length (128 bits)");
			}
		}
		scanner.close();

		long startTime = System.currentTimeMillis();
		//Encrypt the text
		String encryptedText = Encrypt(text, key);
		long endTime = System.currentTimeMillis();
		
		System.out.println("\nOriginal Text: " + text);
		System.out.println("Encryption Key in Hex: " + key);
		System.out.println("\nEncrypted Text: " + encryptedText);
		System.out.println("Encrypted Text in Base64: " + base64Encoder.encodeToString(encryptedText.getBytes()));
		System.out.println("\nTime to Encrypt: " + (endTime - startTime) + "ms");
	}
}
