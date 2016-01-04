import java.util.Arrays;
import java.util.Base64;
import java.util.Base64.*;
import java.util.Scanner;

public class AES {
	private static final int KEY_SIZE = 128;
	private static final int BLOCK_SIZE = 128;
	private static final int ENCRYPTION_ROUNDS = 9;
	private static final int ROUND_KEYS_NEEDED = 11;

	private static byte[] RCON;
	
	public static String Encrypt(String text, String key) {		
		//Getting all the round keys needed
		byte[] expandedKeys = KeyExpansion(key);
			
		//Getting the text to be encrypted into matrix form
		byte[][] stateMatrix = Helper.toMatrix(text.getBytes());
		
		//Initial AddRoundKey step
		byte[][] roundKeyByteMatrix = Helper.toMatrix(Arrays.copyOfRange(expandedKeys, 0, 16));
		stateMatrix = AddRoundKey(stateMatrix, roundKeyByteMatrix);
				
		//Goes through the first 9 rounds for a 128 bit key in AES
		for (int i = 1; i <= ENCRYPTION_ROUNDS; i++) {
			byte[] roundKeyByteArray = Arrays.copyOfRange(expandedKeys, 16*i, 16*i+16);
			roundKeyByteMatrix = Helper.toMatrix(roundKeyByteArray);
						
			stateMatrix = SubBytes(stateMatrix);
			stateMatrix = ShiftRows(stateMatrix);
			stateMatrix = MixColumns(stateMatrix);
			stateMatrix = AddRoundKey(stateMatrix, roundKeyByteMatrix);
		}
		
		//Last round of AES
		roundKeyByteMatrix = Helper.toMatrix(Arrays.copyOfRange(expandedKeys, 160, 176));
		
		stateMatrix = SubBytes(stateMatrix);
		stateMatrix = ShiftRows(stateMatrix);
		stateMatrix = AddRoundKey(stateMatrix, roundKeyByteMatrix);

		return new String(Helper.toArray(stateMatrix));
	}
	
	public static String Decrypt(String text, String key) {		
		//TODO: Decryption end
		byte[] expandedKeys = KeyExpansion(key);

		//Getting the text to be decrypted into matrix form
		byte[][] stateMatrix = Helper.toMatrix(text.getBytes());

		//Initial AddRoundKey step
		byte[][] roundKeyByteMatrix = Helper.toMatrix(Arrays.copyOfRange(expandedKeys, 160, 176));
		
		stateMatrix = SubBytesReverse(stateMatrix);
		stateMatrix = ShiftRowsReverse(stateMatrix);
		stateMatrix = AddRoundKey(stateMatrix, roundKeyByteMatrix);
		
		//Goes through rounds 1-9
		for (int i = ENCRYPTION_ROUNDS; i > 0; i--) {
			//Setting the key for each round
			roundKeyByteMatrix = Helper.toMatrix(Arrays.copyOfRange(expandedKeys, 16*i, 16*i+16));
			MixColumnsReverse(roundKeyByteMatrix);
			
			stateMatrix = SubBytesReverse(stateMatrix);
			stateMatrix = ShiftRowsReverse(stateMatrix);
			stateMatrix = MixColumnsReverse(stateMatrix);
			stateMatrix = AddRoundKey(stateMatrix, roundKeyByteMatrix);
		}
		
		//Setting final key for round 10
		roundKeyByteMatrix = Helper.toMatrix(Arrays.copyOfRange(expandedKeys, 0, 16));
		
		//Final AddKeyRound round
		stateMatrix = AddRoundKey(stateMatrix, roundKeyByteMatrix);
		
		return new String(Helper.toArray(stateMatrix));
	}
	
	private static byte[] KeyExpansion(String key) {		
		byte[] keyByteArray = Helper.toByteArray(key);
		
		byte[] expandedKeyBytes = new byte[ROUND_KEYS_NEEDED*KEY_SIZE/8];
		
		//Generating the round constants
		generateRCON();
		
		int currentSize = 0;  	//Current size of the expanded keys in bytes
		int rconIterator = 0;
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
		word[0] ^= RCON[rconIterator];
		
		return word;
	}
	
	private static byte[][] AddRoundKey(byte[][] stateMatrix, byte[][] roundKeyByteMatrix) {		
		//XORing each text's byte with the key's equivalent byte
		int matrixLength = roundKeyByteMatrix.length;
		for (int j = 0; j < matrixLength; j++) {
			for (int k = 0; k < matrixLength; k++) {
				stateMatrix[j][k] ^= roundKeyByteMatrix[j][k];
			}
		}
		return stateMatrix;
	}
	
	private static byte[][] SubBytes(byte[][] stateMatrix) {		
		int matrixLength = stateMatrix.length;
		//Go through the state matrix and do SBox substitutions
		for (int col = 0; col < matrixLength; col++) {
			for (int row = 0; row < matrixLength; row++) {
				stateMatrix[row][col] = SBox(stateMatrix[row][col]);
			}
		}
		return stateMatrix;
	}
	
	private static byte[][] SubBytesReverse(byte[][] stateMatrix) {
		int matrixLength = stateMatrix.length;
		//Go through the state matrix and do inverse SBox substitutions
		for (int col = 0; col < matrixLength; col++) {
			for (int row = 0; row < matrixLength; row++) {
				stateMatrix[row][col] = inverseSBox(stateMatrix[row][col]);
			}
		}
		return stateMatrix;
	}
	
	private static byte[][] ShiftRows(byte[][] stateMatrix) {
		//AES Shift row steps
		int matrixLength = stateMatrix.length;
		for (int row = 0; row < matrixLength; row++) {
			//Will shift the row i times left
			for (int i = 0; i < row; i++) {
				Helper.shiftLeft(stateMatrix[row]);
			}
		}
		return stateMatrix;
	}
	
	private static byte[][] ShiftRowsReverse(byte[][] stateMatrix) {
		//Reverses AES shift rows
		int matrixLength = stateMatrix.length;
		for (int row = 0; row < matrixLength; row++) {
			//Will shift the row i times right
			for (int i = 0; i < row; i++) {
				Helper.shiftRight(stateMatrix[row]);
			}
		}
		return stateMatrix;
	}
	
	private static byte[][] MixColumns(byte[][] stateMatrix) {
		byte[][] mixColumnMatrix = {{0x02, 0x03, 0x01, 0x01},
									{0x01, 0x02, 0x03, 0x01},
									{0x01, 0x01, 0x02, 0x03}, 
									{0x03, 0x01, 0x01, 0x02}};
		
		return Helper.matrixMultiplication(mixColumnMatrix, stateMatrix);
	}
	
	private static byte[][] MixColumnsReverse(byte[][] stateMatrix) {
		byte[][] mixColumnMatrix = {{0x0E, 0x0B, 0x0D, 0x09}, 
									{0x09, 0x0E, 0x0B, 0x0D},
									{0x0D, 0x09, 0x0E, 0x0B}, 
									{0x0B, 0x0D, 0x09, 0x0E}};
		
		return stateMatrix = Helper.matrixMultiplication(mixColumnMatrix, stateMatrix);
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
	
	private static byte inverseSBox(byte val) {		
		//Setting up the 0x25 AES affine transformation matrix
		byte[] affineMatrix = new byte[8];
		for (int i = 0; i < 8; i++) {
			byte row = Byte.valueOf("37");
			for (int j = 0; j < i; j++) {
				row = Helper.rotateByte(row);
			}
			affineMatrix[i] = row;
		}
		
		//LSB first of resultBitArray combined to byte
		byte LSB = (byte) (Integer.reverse(val << 24) & 0xff);
		
		//Going through the affine matrix
		byte[] resultBitArray = new byte[8];
		for (int i = 0; i < 8; i++) {
			//ANDing the input and each row of the affine matrix
			byte bit = (byte) (affineMatrix[i] & LSB);
			//XORing the bits of the result to get the bit in position i
			resultBitArray[i] = Helper.xorByte(bit);
		}
		
		//MSB first of resultBitArray combined to byte
		byte resultByte = Helper.toByte(resultBitArray);
		byte reverse = (byte) ((byte) (Integer.reverse( resultByte << 24) & 0xff) ^ (byte)0x05);
		
		//Multiplicative inverse of the reverse
		byte inverse = Helper.galoisMultiplicativeInverse(Byte.toUnsignedInt(reverse));
		
		return inverse;
	}
	
	private static void generateRCON() {
		RCON = new byte[11];
		RCON[0] = 1;
		for (int i = 1; i < 8; i++) {
			RCON[i] = (byte) (2*RCON[i-1]);
		}
		RCON[8] = (byte) 0x1B;
		RCON[9] = (byte) 0x36;
		RCON[10] = (byte) 0x6c;
	}
	
	public static void main(String[] args) {
		Scanner scanner = new Scanner(System.in);
		
		//Getting text to be encrypted from user
		int textBitLength = 0;
		String text = "";
		
		
		while (textBitLength != BLOCK_SIZE) {
			System.out.print("Text to Encrypt: ");
			text = scanner.nextLine();
			 
			textBitLength = text.getBytes().length*8;
			
			if (textBitLength != BLOCK_SIZE) {
				System.out.println("Please enter a valid length of text (128 bits)");
			}
		}
		
		//Getting the encryption key
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
		
		//Encrypt the text
		String encryptedText = Encrypt(text, key);
		
		//Decrypt the text
		String decryptedText = Decrypt(encryptedText, key);
		
		Encoder decoder = Base64.getEncoder();
		
		System.out.println("Original Text: " + text);
		System.out.println("Encryption Key: " + key);
		System.out.println("Encrypted Text: " + encryptedText);
		System.out.println("Encrypted Text: " + decoder.encodeToString(encryptedText.getBytes()));
		System.out.println("Decrypted Text: " + decryptedText);
	}
}
