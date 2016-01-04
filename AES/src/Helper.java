import java.math.BigInteger;
import javax.xml.bind.DatatypeConverter;

public class Helper {
	
	//Converts hex string to a byte array
	public static byte[] toByteArray(String s) {
	    return DatatypeConverter.parseHexBinary(s);
	}
	
	//Turns 1x16 1d array into 4x4 2d array
	static byte[][] toMatrix(byte[] array) {
		byte[][] matrix = new byte[4][4];
		int matrixLength = 4;
		
		for (int i = 0, j = 0; j < matrixLength; j++) {
			for (int k = 0; k < matrixLength; k++) {
				matrix[j][k] = array[i++];
			}
		}
		return matrix;
	}
	
	//Turns 4x4 2d array into 1x16 1d array
	static byte[] toArray(byte[][] matrix) {
		byte[] array = new byte[16];
		int matrixLength = matrix.length;
		
		for(int i = 0, j = 0; j < matrixLength; j++) {
			for (int k = 0; k < matrixLength; k++) {
				array[i++] = matrix[j][k];
			}
		}
		
		return array;
	}
	
	//Prints out matrix in structured form
	static void printMatrix(byte[][] matrix) {
		int row = matrix.length;
		int col = matrix[0].length;
		for (int i = 0; i < col; i++) {
			for (int j = 0; j < row; j++) {
				System.out.print( matrix[i][j] + ", ");
			}
			System.out.println();
		}
	}
	
	//Combines an array of 8 bits to 1 byte
	static byte toByte(byte[] array) {
		StringBuilder stringBuilder = new StringBuilder();
		int arrayLength = array.length;
		
		for (int i = 0; i < arrayLength; i++) {
			if (array[i] == 1) { 
				stringBuilder.append('1');
			} else {
				stringBuilder.append('0');
			}
		}
		int returnVal = Integer.valueOf(stringBuilder.toString(), 2);
		return (byte)returnVal;
	}
	
	//Rotates byte one bit to the right with wrap around
	static byte rotateByte(byte input) {
		byte output = 0;
		int rightBit = 0;
		
		//Check if the right-most bit is 1 or 0
		if ((input & 1) == 1) {
			rightBit = 1;
		}
		
		//Shift byte to the right by 1
		output = (byte) ((0xFF & input) >>> 1);
		
		//Add back the right-most bit if it was 1
		if (rightBit == 1) {
			output |= -128;
		}
		return output;
	}
	
	//XOR the each bit with each other in a byte
	static byte xorByte(byte input) {
		String bits = Integer.toBinaryString(input & 255 | 256).substring(1);;
		byte output = 0;
		for (int i = 0; i < 8; i++) {
			if (bits.charAt(i) == '1') {
				output ^= 1;
			} else {
				output ^= 0;
			}
		}
		return output;
	}
	
	//Shifts row #i one position to the right
	static void shiftRight(byte[] array) {
        int m = array.length;
        byte temp = array[m-1];
        for (int k=m-1; k>=1; k--){
            array[k] = array[k-1];
        }
        array[0] = temp;
    }

    //Shifts row #i one position to the left.
	static void shiftLeft(byte[] array) {
        int m = array.length;
        byte temp = array[0];
        for (int k=0; k<m-1; k++){
            array[k] = array[k+1];
        }
        array[m-1] = temp;
    }
	
	//Multiplies two matrices in the order a*b
	static byte[][] matrixMultiplication(byte[][] a, byte[][] b) {
		byte[][] result = new byte[4][4];
		
        int aRows = a.length;
        int aColumns = a[0].length;
        int bColumns = b[0].length;

        for (int i = 0; i < aRows; i++) {
            for (int j = 0; j < bColumns; j++) {
                for (int k = 0; k < aColumns; k++) {
                    result[i][j] ^= galoisMultiply(a[i][k], b[k][j]);
                }
            }
        }
        
		return result;	
	}
	
	//Addition in the Galois  Field
	static byte galoisAdd(byte a, byte b) {
		return (byte) (a ^ b);
	}
	
	//Multiplication in the Galois Field
	static byte galoisMultiply(byte a, byte b) {
		byte p = 0;
		boolean aHighBit = false;
		
		for (int i = 0; i < 8; i++) {
			//Is low bit of b set?
			if ((b & 1) == 1) {
				p ^= a;
			}
			
			//Keep track if high bit of a is set to 1
			aHighBit = (a & 0x80) == 0x80;
			
			//Rotating a one bit to the left
			//Discard high bit and make low bit equal to 0
			a <<= 1;
			
			//High bit of a was set
			if (aHighBit) {
				a ^= 0x1b;
			}
			
			//Rotating b one bit to the right
			//Discard low bit and make high bit equal to 0
			b >>= 1;
		}
		
		return p;
	}
	
	//Galois Multiplicative Inverse using the Extended Euclidean Algorithm
	public static byte galoisMultiplicativeInverse(int input) {
	    int old_s = 0; 
	    int s = 1; 
	    int new_s = 0;
	    int old_t = 0; 
	    int t = 0; 
	    int new_t = 1;
	    int old_r = 0x11B; 
	    int r = 0x11B; 
	    int new_r = input;
	    
	    while (new_r > 0) {
		    int r_msb = (int)(Math.log(r)/Math.log(2));
	        int new_r_msb = (int)(Math.log(new_r)/Math.log(2));
	
	        int quotient = r_msb - new_r_msb;
	
	        if (quotient >= 0) {
	        	old_s = s;
	            s = new_s;
	            new_s = old_s ^ (s << quotient);
	
	            old_t = t;
	            t = new_t;
	            new_t = old_t ^ (t << quotient);
	
	            old_r = r;
	            r = new_r;
	            new_r = old_r ^ (r << quotient);
	        } else {
	            new_s = s ^ new_s;
	            s = s ^ new_s;
	            new_s = s ^ new_s;
	
	            new_t = t ^ new_t;
	            t = t ^ new_t;
	            new_t = t ^ new_t;
	
	            new_r = r ^ new_r;
	            r = r ^ new_r;
	            new_r = r ^ new_r;
	        }
	    }

	    if (r > 1) { 
	    	return 0;
    	}

	    if (t > 0xFF) {
	    	t ^= 0x11B;
	    }
	    
	    return (byte)t;
	}
	
}
