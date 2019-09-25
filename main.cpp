/*
 *  This is a demonstration of AES encryption. The intention is educational, to learn how the
 *  process works.  It is not intended to do actual encryption.  It is intentional to have muiltple\
 *  variable in the encryption function versus just one containing the current state.  This is so inputs can be
 *  manually substituted at certain places to see the interaction at certain steps.
 *  Input must be 128-bit in hexadecimal, as there is not padding added and will result in seg faults if not.
 *  This uses the 128-bit key and is not made to use other AES keylengths.
 *
 *  Created on: Sep 17, 2019
 *      Author: Tim Reed
 *
 */


#include "encrypt.h"

int main (int argc, char** argv)
{
	// Input is a string of hexademical.  Must be hexademical format, 128-bit. Default provided
	string plaintext = "00112233445566778899aabbccddeeff";
	// Key string.  must be hexademical and 128-bit. Default provided
	string key = "000102030405060708090a0b0c0d0e0f";
	string filename;
	ofstream outfile;

	if (argc > 1)
	{
		if (argc < 3 || argc > 4)
		{
			cout << "Usage: aes [plaintext] [key] [output file]" << endl;
			return 1;
		}
		plaintext = argv[1];
		key = argv [2];
		if (argc == 4)
		{
			filename = argv[3];
			outfile.open (filename);
		}
		if (plaintext.length() != 32 || key.length () != 32)
		{
			cout << "Usage: plaintext and key must be hexadecimal 128-bit" << endl;
			return 3;
		}
	}
	if (outfile.is_open())
	{
		string out = encrypt (plaintext, key, outfile);
	}
	else
	{
		string out = encrypt (plaintext, key, cout);
	}
	outfile.close ();
	return 0;
}

string encrypt (string pt, string key, ostream& os)
{

	// Variables.  Only one could have been used, but this approach allows step by step analysis
	// or in-place substitution of values for testing or learning.
	byte input [NUM_BYTES];
	byte roundkey [11][16];
	byte bitsub [NUM_BYTES];
	byte shiftrow [NUM_BYTES];
	byte mixcolumn [NUM_BYTES];
	byte roundOut [NUM_BYTES];

	// convert string to bytes for both input and key
	generateBytes (pt, input);
	keyGenerator(key, roundkey);

	os << "Plaintext: " << pt << endl;
	os << "Key:       " << key << "\n" << endl;

	os << "PTinhex:   ";
	print128inHex(input, os);

	os << "Round0Key: ";
	print128inHex(roundkey [0], os);

	//round 0 key insertion
	keyAddition (input, roundOut, roundkey [0]);

	os << "After0key: ";
	print128inHex(roundOut, os);

	// Start rounds 1 thru 9.  Round 10 is different (does not mix columns) so it will
	// be handled separately.
	for (int round = 1; round < 10; ++round)
	{
		byteSub(roundOut, bitsub);
		shiftRows(bitsub, shiftrow);
		mixColumnCALC(shiftrow, mixcolumn);
		keyAddition (mixcolumn, roundOut, roundkey[round]);

		/* print results */
		os << "bitsub:    ";
		print128inHex(bitsub, os);
		os << "shiftrow:  ";
		print128inHex(shiftrow, os);
		os << "mixColumn: ";
		print128inHex(mixcolumn, os);
		os << "Key used:  ";
		print128inHex(roundkey[round], os);
		os << "AfterR " << round <<":  ";
		print128inHex(roundOut, os);
		os << endl;
	}

	//final round, no mixcolumn
	byteSub(roundOut, bitsub);
	shiftRows(bitsub, shiftrow);
	keyAddition (shiftrow, roundOut, roundkey[10]);
	os << "bitsub:    ";
	print128inHex(bitsub, os);
	os << "shiftrow:  ";
	print128inHex(shiftrow, os);
	os << "Key used:  ";
	print128inHex(roundkey [10], os);
	os << "Output:    ";
	print128inHex(roundOut, os);

	/* Convert the output back to a string, for future possible use. */
	ostringstream ss;
	string output;
	for (int i = 0; i < NUM_BYTES; ++i)
	{
		ss << hex << +roundOut [i];
	}
	output.append (ss.str());
	os << "\nFinal Output in string format: " << output << endl;
	return output;
}



void generateBytes (string str,byte in [])
{
	int i = 0;
	while (i < NUM_BYTES)
	{
		// get the first two characters of the string and turn it into a base16 int
		string conv = str.substr (2 * i, 2);
		in [i] = stoi (conv, 0, 16);
		++i;
	}
}

void keyGenerator(string keystr, byte key[][16]) {
	word words[43];
	generateWords(words, keystr); // gets the first words [0] thru word [3] from the key
	// W[4i] = W[4(i - 1)] + g(W[4i-1])
	// Populate the w blocks using the first 4.
	for (int i = 1; i <= 10; ++i) {
		words[4 * i] = words[4 * (i - 1)] ^ g_function(words[4 * i - 1], i);
		for (int j = 1; j <= 3; ++j) {
			words[4 * i + j] = words[4 * i + j - 1] ^ words[4 * (i - 1) + j];
		}
	}
	// converting the blocks into byte sized 2-D array that will be used to XOR with the input data at the byte level
	for (int round = 0; round < 11; ++round) {
		for (int i = 0; i < 4; ++i) {
			//32 bit word to 8 bit key blocks
			for (int j = 3; j >= 0; --j) {
				key[round][4 * i + j] = words[4 * round + i] & 0xFF;
				words[4 * round + i] >>= 8;
			}
		}
	}
}

void generateWords (word k0 [], string key)
{
	int i = 0;
	while (i < 4)
	{
		// get the first two characters of the string and turn it into an int
		string conv = key.substr (8 * i, 8);
		istringstream ss (conv);
		ss >> hex >> k0[i];
		++i;
		}
}

word g_function (word in, int round)
{
	/* This modifies the input into the left most word.
	 * 32 bits come in, split into 4 bytes.
	 * the bytels are rotated left one
	 * then all go through the s-block similar to the main data
	 * the left most byte is then XORed with a round dependant constant
	 */
	byte chunk [4];
		/*
		 *  xxxx xxxx xxxx xxxx xxxx xxxx xxxx xxxx
		 *  0000 0000 0000 0000 0000 0000 1111 1111
		 *
		 *  bitwise addition will give the 8 most bits. The input
		 *  is then bitshifted 8 bits and repeated.
		 *  This puts the 32 bit input into 4 8-bit chunks.
		 *  each chunk gets 8 bits
		 */

	for (int i = 3; i >= 0; --i)
	{
		chunk[i] = in & 0x000000FF;
		in >>= 8;
	}

	// left shift by one all chunks
	byte temp = chunk [0];
	chunk [0] = chunk [1];
	chunk [1] = chunk [2];
	chunk [2] = chunk [3];
	chunk [3] = temp;

	// s-block
	for (int i =0; i < 4; ++i)
	{
		chunk [i] = s_block[chunk [i]];
	}

	//round coefficient.  Only added to left most chunk
	const byte rc [10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};
	chunk[0] ^= rc[round-1];

	/* expand the 4 8-bit chunks into 32 bit output */
	word out = 0;
	for (int i=0; i < 4; ++i)
	{
		out += chunk [i];
		if (i !=3)
			out <<= 8;
	}
	return out;

}

void byteSub (byte in [], byte out [])
{
	int i = 0;
	while (i < NUM_BYTES)
	{
		//takes the input as coordinate in s block array, get s block array value, add to output.
		out [i] = s_block [in[i]];
		++i;
	}
}

void shiftRows (byte in [], byte out [])
{
	//one to one copy function from in to out
	int shift [NUM_BYTES] = {0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11};
	for (int i = 0; i < NUM_BYTES; ++i)
	{
		out [i] = in [shift[i]];
	}
}

void mixColumnCALC (byte in [], byte out [])
{

	/* Matrix multiplication */
	for (int i = 0; i < NUM_BYTES; i +=4)
	{
		out [i] = times(in[i], 2) ^ times(in[i+1], 3) ^ in [i+2] ^ in [i+3];
		out [i+1] = in[i] ^ times(in[i+1], 2) ^ times(in [i+2], 3) ^ in [i+3];
		out [i+2] = in[i] ^ in[i+1] ^ times(in [i+2], 2) ^ times(in [i+3], 3);
		out [i+3] = times(in[i], 3) ^ in[i+1] ^ in [i+2] ^ times(in [i+3], 2);
	}
}

//function that allows GF(2^8) multiplication
byte times (byte in, byte value)
{
	/** This function allows GF(2^8) multiplication, using the AES irreducable polynomial of x^4+x^3+x+1, or 0x1B
	 * For odd values, such as 5, it can be solved by (in * 2 * 2) XOR in.
	 * for values of in > than 0x80 (a number with a 1 in the left most bit), and XOR with the AES poly is required (modulo)
	 * bit shift left << multiplies the number by 2.
	 */
	byte temp = 0x00;
	while (value)
	{
		if (value & 1) // not multiplying by 2, but XOR-ing itself to the temp value; met if odd or value if finally 1.
		{
			temp ^= in;
		}
		// the value of which we are multiplying by is bit shifted right by each loop until it is 0.
		if (in & 0x80) // has a 1 in leftmost bit
		{
			in = in << 1; // multiply by 2
			in = in ^ AESmod; //XOR by the polynomial.
		}
		else
		{
			in = in << 1; //multiply by 2.
		}
		value = value >> 1; // divide multiplier by 2
	}
	return temp;
}

void keyAddition (byte in [], byte out [], byte key [])
{
	for (int i = 0; i < NUM_BYTES; ++i)
	{
		out [i] = in [i] ^ key [i];
	}
}

void print128inHex (byte out [], ostream& os)
{
	int i = 0;
	while (i < NUM_BYTES)
	{
		os << hex << +out [i++] << ' ';
	}
	os << endl;
}


