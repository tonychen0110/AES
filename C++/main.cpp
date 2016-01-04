// Reynante Matias
// CSE-178: Laboratory #1
// AES Implementation

#include <iostream>
#include <fstream>
#include <stdio.h>
#include <stdlib.h>

#define num_col 4 // # of columns making up an AES state
#define x_time(x) ((x<<1) ^ (((x>>7) & 1) * 0x1b)) // finds product of {02} and arg {1b}

using namespace std;

int num_key = 0; // # of 32-bit words in the key
int num_rounds = 0; // # number of rounds in AES Cipher
unsigned char key[16]; // Key input
unsigned char round_key[240]; // Holds round keys
unsigned char input[16]; // Holds plaintext
unsigned char state[4][4]; // Holds intermediate results during encryption
unsigned char output[16]; // Holds key

int sbox_val(int num)
{
    int sbox[256] =
    {
        // 0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, // 0
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, // 1
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, // 2
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, // 3
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, // 4
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, // 5
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, // 6
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, // 7
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, // 8
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, // 9
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, // A
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, // B
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, // C
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, // D
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, // E
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16  // F
    };
    
    return sbox[num];
}

int round_const[255] =
{
    // 0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, // 0
    0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, // 1
    0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, // 2
    0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, // 3
    0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, // 4
    0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, // 5
    0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, // 6
    0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, // 7
    0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, // 8
    0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, // 9
    0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, // A
    0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, // B
    0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, // C
    0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, // D
    0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, // E
    0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb  	// F
};

// Produce num_col(num_round+1) round keys.
// Keys are used in each round to encrypt the states.
void key_expansion()
{
    int i;
    unsigned char temp[4], k;
    
    // First round key is the key itself
    for(i = 0; i < num_key; i++)
    {
        round_key[i*4] = key[i*4];
        round_key[i*4 + 1] = key[i*4 + 1];
        round_key[i*4 + 2] = key[i*4 + 2];
        round_key[i*4 + 3] = key[i*4 + 3];
    }
    
    // All other round keys found in previous round keys
    while (i < (num_col*(num_rounds + 1)))
    {
        for(int j = 0; j < 4; j++)
        {
            temp[j] = round_key[(i - 1)*4 + j];
        }
        
        if(i % num_key == 0) {
            // Rotate the 4 bytes to the left.
            // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]
            k = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = k;
            
            // Applies the S-box to 4-byte input
            temp[0] = sbox_val(temp[0]);
            temp[1] = sbox_val(temp[1]);
            temp[2] = sbox_val(temp[2]);
            temp[3] = sbox_val(temp[3]);
            
            temp[0] = temp[0] ^ round_const[i / num_key];
            
        } else if (num_key > 6 && i % num_key == 4) {
            // Applies the S-box to 4-byte input
            temp[0] = sbox_val(temp[0]);
            temp[1] = sbox_val(temp[1]);
            temp[2] = sbox_val(temp[2]);
            temp[3] = sbox_val(temp[3]);
        }
        
        round_key[i*4 + 0] = round_key[(i-num_key)*4 + 0] ^ temp[0];
        round_key[i*4 + 1] = round_key[(i-num_key)*4 + 1] ^ temp[1];
        round_key[i*4 + 2] = round_key[(i-num_key)*4 + 2] ^ temp[2];
        round_key[i*4 + 3] = round_key[(i-num_key)*4 + 3] ^ temp[3];
        i++;
    }
}

// Apply S-box
void byte_substitution()
{
    for(int i = 0; i < 4; i++)
    {
        for(int j = 0; j < 4; j++)
        {
            state[i][j] = sbox_val(state[i][j]);
            
        }
    }
}

// Shift each row to the left with different offsets,
// where offset = row_number. First row is not shifted.
void shift_rows()
{
    unsigned char temp;
    
    // Rotate first row 1 column to left
    temp = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = temp;
    
    // Rotate second row 2 columns to left
    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;
    
    // Rotate third row 3 columns to left
    temp = state[3][0];
    state[3][0] = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = temp;
}

// Mix columns in the current state
void mix_columns()
{
    unsigned char temp, temp_2, val;
    
    for(int i = 0; i < 4; i++)
    {
        val = state[0][i];
        temp = state[0][i] ^ state[1][i] ^ state[2][i] ^ state[3][i];
        
        temp_2 = state[0][i] ^ state[1][i];
        temp_2 = x_time(temp_2);
        state[0][i] ^= temp_2 ^ temp;
        
        temp_2 = state[1][i] ^ state[2][i];
        temp_2 = x_time(temp_2);
        state[1][i] ^= temp_2 ^ temp;
        
        temp_2 = state[2][i] ^ state[3][i];
        temp_2 = x_time(temp_2);
        state[2][i] ^= temp_2 ^ temp;
        temp_2 = state[3][i] ^ val;
        
        temp_2 = x_time(temp_2);
        state[3][i] ^= temp_2 ^ temp;
    }
}

// Add round key to a state using XOR
void add_roundkey(int round)
{
    for(int i = 0; i < 4; i++)
    {
        for(int j = 0; j < 4; j++)
        {
            state[j][i] ^= round_key[round*num_col*4 + i*num_col + j];
        }
    }
}

// Encrypt plaintext
void cipher()
{
    // Copy plaintext into state array
    for(int i = 0; i < 4; i++)
    {
        for(int j = 0; j < 4; j++)
        {
            state[j][i] = input[i*4 + j];
        }
    }
    
    // Add first round key to the state
    add_roundkey(0);
	
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			printf("%02x ", state[j][i]);
		}
	}
	
    // Complete rounds
    for(int round = 1; round < 2; round++)
    {
		cout << "ROUND " << round << endl;
		
        byte_substitution();
		
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				printf("%02x ", state[j][i]);
			}
		}
		printf("/n");
        shift_rows();
		
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				printf("%02x ", state[j][i]);
			}
		}
		printf("/n");
        mix_columns();
		
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				printf("%02x ", state[j][i]);
			}
		}
		printf("/n");
        add_roundkey(round);
		
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				printf("%02x ", state[j][i]);
			}
		}
		printf("/n");
    }
    
	cout << "FINAL ROUND" << endl;
    // Final round
    byte_substitution();
	
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			printf("%02x ", state[j][i]);
		}
	}
	printf("/n");
    shift_rows();
	
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			printf("%02x ", state[j][i]);
		}
	}
	printf("/n");
    add_roundkey(num_rounds);
	
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			printf("%02x ", state[j][i]);
		}
	}
    printf("/n");
    // Encryption complete.
    // Copy state array into output array.
    for(int i = 0; i < 4; i++)
    {
        for(int j = 0; j < 4; j++)
        {
            output[i*4 + j] = state[j][i];
        }
    }
}

int main()
{
    printf("Reynante Matias\nCSE-178 Lab: AES Implementation:\n");
    
    // Calculate num_key and num_rounds
    num_key = 128 / 32;
    num_rounds = num_key + 6;
    
    // Create & print key
    //4D 79 20 6E 61 6D 65 20 69 73 00 00 00 00 00 00
    unsigned char test_key[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    //unsigned char test_key[17] = "super secure key";
    printf("\nTest Case #1\n       Key: ");
    for(int i = 0; i < num_col*4; i++) {
        printf("%02x ", test_key[i]);
    }
    
    
    // Create & print plaintext
      //                                  00  11  22  33  44  55  66  77 88 99 aa bb cc dd ee ff
    unsigned char test1_plaintext[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    //unsigned char test1_plaintext[17] = "My name is Ethan";
    printf("\n Plaintext: ");
    for(int i = 0; i < num_col*4; i++) {
        printf("%02x ", test1_plaintext[i]);
    }
    
    // Copy the key and plaintext
    for(int i = 0; i < num_col*4; i++){
        key[i] = test_key[i];
        input[i] = test1_plaintext[i];
    }
    
    key_expansion(); // Expand key before encryption
    cipher(); // AES algorithm
    
    // Print ciphertext
    printf("\nCiphertext: ");
    for(int i = 0; i < num_col*4; i++) {
        printf("%02x ", output[i]);
    }
    
    std::cout <<"\n";
    
    
    
    return 0;
}