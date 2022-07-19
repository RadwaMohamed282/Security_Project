using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {

        static byte[] SBOX = new byte[256] {
        //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, //0
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, //1
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, //2
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, //3
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, //4
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, //5
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, //6
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, //7
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, //8
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, //9
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, //A
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, //B
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, //C
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, //D
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, //E
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 //F
         };

        static byte[] INVERSESBOX = new byte[256] {
        //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
        0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB, //0
        0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB, //1
        0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E, //2
        0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25, //3
        0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92, //4
        0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84, //5
        0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06, //6
        0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B, //7
        0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73, //8
        0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E, //9
        0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B, //A
        0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4, //B
        0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F, //C
        0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF, //D
        0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61, //E
        0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D  //F
        };

        static String[,] RCON = new String[4, 10]
        {
            {"01","02","04","08","10","20","40","80","1b","36"},
            {"00","00","00","00","00","00","00","00","00","00"},
            {"00","00","00","00","00","00","00","00","00","00"},
            {"00","00","00","00","00","00","00","00","00","00"}
        };

        static String[,] MATRIX = new String[4, 4]
        {
            { "02", "03", "01", "01"},
            { "01", "02", "03", "01"},
            { "01", "01", "02", "03"},
            { "03", "01", "01", "02"}
        };

        static String[,] _inverse_matrix_hya_kda = new String[,]
        {
            { "0E", "0B", "0D", "09"},
            { "09", "0E", "0B", "0D"},
            { "0D", "09", "0E", "0B"},
            { "0B", "0D", "09", "0E"}
        };
        public override string Decrypt(string cipherText, string key)
        {
            string mainplaintext = "";

            //cipherText = "0x69c4e0d86a7b0430d8cdb78070b4c55a";
            cipherText = cipherText.Remove(0, 2);
            ///////////////////////////////INVERSE////////////////////////////////////
            //key = "0x13111d7fe3944a17f307a78b4d2b30c5";

            key = key.Remove(0, 2);
            int rounds = 0;

            int cipherTextSize = Convert.ToInt32(Math.Sqrt(cipherText.Length / 2)); //4

            //Prepare Inverse Sbox
            String[,] invSbox = new String[16, 16];
            invSbox = Convertsbox(INVERSESBOX);

            //Prepare Cipher text matrix 
            String[,] cipherTextMatrix = new String[cipherTextSize, cipherTextSize];
            cipherTextMatrix = PreparePlainText(cipherText, cipherTextSize);


            //Prepare key matrix
            String[,] keyMatrix = new String[cipherTextSize, cipherTextSize];
            keyMatrix = PreparePlainText(key, cipherTextSize);
            //keyMatrix = CreateInversenewkey(keyMatrix, 11);

            /* Console.WriteLine(" Prepare Key");
             for (int m = 0; m < cipherTextSize; m++)
             {
                 for (int n = 0; n < cipherTextSize; n++)
                 {
                     Console.Write(keyMatrix[m, n] + "  ");
                 }
                 Console.WriteLine();
             }

             Console.WriteLine(" Prepare Cipher");
             for (int m = 0; m < cipherTextSize; m++)
             {
                 for (int n = 0; n < cipherTextSize; n++)
                 {
                     Console.Write(cipherTextMatrix[m, n] + "  ");
                 }
                 Console.WriteLine();
             }*/

            //STEP 1 ADD ROUND 




            if (cipherTextSize == 4)
            {
                rounds = 9;
            }
            else if (cipherTextSize == 16)
            {
                rounds = 11;
            }
            else if (cipherTextSize == 128)
            {
                rounds = 13;
            }

            for (int m = 0; m < rounds + 1; m++)
            {
                keyMatrix = Createnewkey(keyMatrix, m + 1);
            }

            cipherTextMatrix = Addroundkey(cipherTextMatrix, keyMatrix, Math.Pow(cipherTextSize, 2));


            //INV Shift Rows 
            cipherTextMatrix = InvSihftRows(cipherTextMatrix, cipherTextSize);
            //INV sub bytes 
            cipherTextMatrix = Subbytes(cipherTextMatrix, invSbox, cipherTextSize);

            //Main Rounds //Four steps 

            for (int i = 0; i < rounds; i++)
            {

                keyMatrix = CreateInversenewkey(keyMatrix, i + 1);

                for (int m = 0; m < cipherTextSize; m++)
                {
                    for (int n = 0; n < cipherTextSize; n++)
                    {
                        int tmp = Convert.ToInt32(cipherTextMatrix[m, n], 16) ^ Convert.ToInt32(keyMatrix[m, n], 16);
                        cipherTextMatrix[m, n] = tmp.ToString("X2");
                        //Console.Write(cipherTextMatrix[m, n] + " ");
                    }
                    // Console.WriteLine();
                }


                cipherTextMatrix = InvMixcol(cipherTextMatrix, cipherTextSize);

                //STEP 1 Inverse Shift rows 
                cipherTextMatrix = InvSihftRows(cipherTextMatrix, cipherTextSize);

                //STEP 2 Inverse Sub Bytes 
                cipherTextMatrix = Subbytes(cipherTextMatrix, invSbox, cipherTextSize);



            }
            keyMatrix = CreateInversenewkey(keyMatrix, 10);
            for (int m = 0; m < cipherTextSize; m++)
            {
                for (int n = 0; n < cipherTextSize; n++)
                {
                    int tmp = Convert.ToInt32(cipherTextMatrix[m, n], 16) ^ Convert.ToInt32(keyMatrix[m, n], 16);
                    cipherTextMatrix[m, n] = tmp.ToString("X2");
                }
            }
            Console.WriteLine("Cipher After");
            for (int m = 0; m < cipherTextSize; m++)
            {
                for (int n = 0; n < cipherTextSize; n++)
                {
                    Console.Write(keyMatrix[m, n] + "  ");
                }
                Console.WriteLine();
            }

            //LAST ROUND CONTAINS 3 STEPS 




            mainplaintext = "0x";
            for (int m = 0; m < cipherTextSize; m++)
            {
                for (int n = 0; n < cipherTextSize; n++)
                {
                    mainplaintext += cipherTextMatrix[n, m];
                }
            }
            Console.WriteLine(mainplaintext);
            return mainplaintext;



        }


        //Inv Mix Col
        public String[,] InvMixcol(String[,] shiftedMatrix, int size)
        {
            byte[,] result = new byte[size, size];
            String[,] result_str = new String[size, size];

            for (int i = 0; i < size; i++) //rows
            {
                for (int j = 0; j < size; j++) //columns
                {
                    result[i, j] = 0;
                    for (int m = 0; m < size; m++)// number of iterations
                    {

                        byte a = Convert.ToByte(Convert.ToInt32(_inverse_matrix_hya_kda[i, m], 16));
                        byte b = Convert.ToByte(1 * Convert.ToInt32(shiftedMatrix[m, j], 16));

                        result[i, j] ^= get_multiply_inverse(a, b);
                        result_str[i, j] = result[i, j].ToString("X2");
                    }
                }
            }


            return result_str;

        }
        //get which multiply will use "inverse mix"
        public byte get_multiply_inverse(byte a, byte b)
        {
            if (a == 0x09)
            {
                b = multiply_09(b);
            }
            if (a == 0x0b)
            {
                b = multiply_0B(b);
            }
            if (a == 0x0d)
            {
                b = multiply_0D(b);
            }
            if (a == 0x0e)
            {
                b = multiply_0E(b);
            }

            return b;
        }



        // multiply byte by 0E
        public byte multiply_0E(byte b)
        {

            return (byte)((int)multiply_02(multiply_02(multiply_02(b))) ^
                        (int)multiply_02(multiply_02(b)) ^
                        (int)multiply_02(b));
        }


        // multiply byte by 0D
        public byte multiply_0D(byte b)
        {


            return (byte)((int)multiply_02(multiply_02(multiply_02(b))) ^
                        (int)multiply_02(multiply_02(b)) ^
                        (int)(b));
        }


        // multiply byte by 0B
        public byte multiply_0B(byte b)
        {

            return (byte)((int)multiply_02(multiply_02(multiply_02(b))) ^
                        (int)multiply_02(b) ^
                        (int)b);
        }


        // multiply byte by 09
        public byte multiply_09(byte b)
        {

            return (byte)((int)multiply_02(multiply_02(multiply_02(b))) ^
                        (int)b);
        }

        public String[,] InvSihftRows(String[,] plainText, int size)
        {
            string[,] shiftedMatrix = new string[size, size];

            for (int i = 0; i < (size - 1); i++)
            {
                plainText = Shiftrows(plainText, size);
            }


            return plainText;
        }

        public override string Encrypt(string plainText, string key)
        {
            string mainCipherss = "";
            plainText = plainText.Remove(0, 2);
            key = key.Remove(0, 2);
            int rounds = 0;

            int plainTextSize = Convert.ToInt32(Math.Sqrt(plainText.Length / 2)); // = 4

            //prepare sbox
            String[,] sBox = new String[16, 16];
            sBox = Convertsbox(SBOX);

            //prepare plain text matrix
            String[,] plainTextMatrix = new String[plainTextSize, plainTextSize];
            plainTextMatrix = PreparePlainText(plainText, plainTextSize);

            //prepare cipher key matrix 
            String[,] cipherKeyMatrix = new String[plainTextSize, plainTextSize];
            cipherKeyMatrix = PreparePlainText(key, plainTextSize);

            //Initial Round
            for (int i = 0; i < plainTextSize; i++)
            {
                for (int j = 0; j < plainTextSize; j++)
                {
                    int tmp = Convert.ToInt32(plainTextMatrix[i, j], 16) ^ Convert.ToInt32(cipherKeyMatrix[i, j], 16);
                    plainTextMatrix[i, j] = tmp.ToString("X2");
                    //Console.Write(plainTextMatrix[i, j] + " ");
                }
                //Console.WriteLine();
            }


            /* //First type SubBytes
             plainTextMatrix = Subbytes(plainTextMatrix, sBox, plainTextSize);

             //Second type Shift Rows 
             plainTextMatrix = Shiftrows(plainTextMatrix, plainTextSize);

             for (int i = 0; i < plainTextSize; i++)
             {
                 for (int j = 0; j < plainTextSize; j++)
                 {
                     Console.Write(plainTextMatrix[i, j] + " ");
                 }
                 Console.WriteLine();
             }

             //Third type Mix Columns 
             plainTextMatrix = Mixcolumns(plainTextMatrix, plainTextSize);

             /*for (int i = 0; i < plainTextSize; i++)
             {
                 for (int j = 0; j < plainTextSize; j++)
                 {
                     Console.Write(plainTextMatrix[i, j] + " ");
                 }
                 Console.WriteLine();
             }


             //New Key that will used in the fourth step 
             cipherKeyMatrix = Createnewkey(cipherKeyMatrix,  1);

             //Fourth Add    
             Addroundkey(plainTextMatrix, cipherKeyMatrix, plainTextSize);*/



            //Number of rounds 
            if (plainTextSize == 4)
            {
                rounds = 9;
            }
            else if (plainTextSize == 16)
            {
                rounds = 11;
            }
            else if (plainTextSize == 128)
            {
                rounds = 13;
            }


            //Main rounds 
            for (int i = 0; i < rounds; i++)
            {

                //FOUR TYPES OF TRANSFORMATIONS

                //First type SubBytes
                plainTextMatrix = Subbytes(plainTextMatrix, sBox, plainTextSize);

                //Second type Shift Rows 
                plainTextMatrix = Shiftrows(plainTextMatrix, plainTextSize);

                //Third type Mix Columns 
                plainTextMatrix = Mixcolumns(plainTextMatrix, plainTextSize);

                //New Key that will used in the fourth step 
                cipherKeyMatrix = Createnewkey(cipherKeyMatrix, i + 1);

                //Fourth Add    
                Addroundkey(plainTextMatrix, cipherKeyMatrix, Math.Pow(plainTextSize, 2));
                /*Console.WriteLine("Matrix ");

                for (int m = 0; m < plainTextSize; m++)
                {
                    for (int n = 0; n < plainTextSize; n++)
                    {
                        Console.Write(plainTextMatrix[m, n] + " ");

                    }
                    Console.WriteLine();
                }*/
                for (int m = 0; m < plainTextSize; m++)
                {
                    for (int n = 0; n < plainTextSize; n++)
                    {
                        int tmp = Convert.ToInt32(plainTextMatrix[m, n], 16) ^ Convert.ToInt32(cipherKeyMatrix[m, n], 16);
                        plainTextMatrix[m, n] = tmp.ToString("X2");
                    }
                }
                /* Console.WriteLine("Matrix after round");
                 for (int m = 0; m < plainTextSize; m++)
                 {
                     for (int n = 0; n < plainTextSize; n++)
                     {
                         Console.Write(plainTextMatrix[m, n] + " ");

                     }
                     Console.WriteLine();
                 }*/


            }
            //Last Round 
            //STEP 1 //SUBbytes 
            plainTextMatrix = Subbytes(plainTextMatrix, sBox, plainTextSize);

            //STEP 2 //ShiftRows
            plainTextMatrix = Shiftrows(plainTextMatrix, plainTextSize);

            //Create New Key 
            cipherKeyMatrix = Createnewkey(cipherKeyMatrix, 10);

            //STEP 3 //XOR with Key
            for (int m = 0; m < plainTextSize; m++)
            {
                for (int n = 0; n < plainTextSize; n++)
                {
                    int tmp = Convert.ToInt32(plainTextMatrix[m, n], 16) ^ Convert.ToInt32(cipherKeyMatrix[m, n], 16);
                    plainTextMatrix[m, n] = tmp.ToString("X2");
                }
            }

            Console.WriteLine("Key Matrix ");
            for (int m = 0; m < plainTextSize; m++)
            {
                for (int n = 0; n < plainTextSize; n++)
                {
                    Console.Write(cipherKeyMatrix[m, n] + " ");
                }
                Console.WriteLine();
            }

            mainCipherss = "0x";
            for (int m = 0; m < plainTextSize; m++)
            {
                for (int n = 0; n < plainTextSize; n++)
                {
                    mainCipherss += plainTextMatrix[n, m];
                }
            }
            Console.WriteLine(mainCipherss);
            return mainCipherss;

        }



        //STEP FOUR 
        //MIX COLUMNS 
        public String[,] Mixcolumns(String[,] shiftedMatrix, int size)
        {
            byte[,] result = new byte[size, size];
            String[,] result_str = new String[size, size];

            for (int i = 0; i < size; i++) //rows
            {
                for (int j = 0; j < size; j++) //columns
                {
                    result[i, j] = 0;
                    for (int m = 0; m < size; m++)// number of iterations
                    {

                        byte a = Convert.ToByte(Convert.ToInt32(MATRIX[i, m], 16));
                        byte b = Convert.ToByte(1 * Convert.ToInt32(shiftedMatrix[m, j], 16));

                        result[i, j] ^= get_multiply(a, b);
                        result_str[i, j] = result[i, j].ToString("X2");
                    }
                }
            }


            return result_str;
        }


        //get which multiply will use
        public byte get_multiply(byte a, byte b)
        {
            if (a == 0x01)
            {
                b = multiply_01(b);
            }
            if (a == 0x02)
            {
                b = multiply_02(b);
            }
            if (a == 0x03)
            {
                b = multiply_03(b);
            }

            return b;
        }


        // multiply byte by 03 
        public byte multiply_03(byte b)
        {
            b = (byte)(multiply_02(b) ^ multiply_01(b));

            return b;
        }


        // multiply byte by 02 
        public byte multiply_02(byte b)
        {
            bool lastBit_is_1_or_0 = (b & 0x80) != 0;
            b <<= 1;
            if (lastBit_is_1_or_0 == true)
            {
                b ^= 0x1b;
            }

            return b;
        }

        // mutiply byte by 01 
        public byte multiply_01(byte b)
        {
            return b;
        }
        //Step 2 Shift Row 

        public string[,] Shiftrows(string[,] plainText, int size)
        {

            string[,] shiftedMatrix = new string[size, size];

            for (int i = 0; i < size; i++)
            {
                for (int j = 0; j < size; j++)
                {
                    shiftedMatrix[i, j] = plainText[i, j];
                }
            }

            for (int i = 1; i < size; i++)
            {
                for (int j = 0; j < size; j++)
                {
                    plainText[i, j] = shiftedMatrix[i, (j + i) % size];

                }

            }

            return plainText;
        }

        //Convert SBOX to Matrix of string sbox to be used 
        static String[,] Convertsbox(byte[] sBox)
        {

            string sBoxToString = BitConverter.ToString(sBox);
            sBoxToString = sBoxToString.Replace("-", string.Empty);
            //Console.WriteLine(sbox_str);

            byte[,] sBoxMatrixResult = new byte[16, 16];
            string[,] sBoxResult = new string[16, 16];

            int iterator = 0;
            for (int i = 0; i < 16; i++)
            {
                for (int j = 0; j < 16; j++)
                {
                    sBoxMatrixResult[i, j] = sBox[iterator];
                    sBoxResult[i, j] = sBoxToString.Substring(2 * iterator, 2);
                    //Console.Write(sBoxResult[i, j] + "   ");
                    iterator++;
                }
                // Console.WriteLine();
            }
            return sBoxResult;
        }

        //FIRST FUNCTION SubBytes
        // Returns the PlainText matrix after substitution in of the intersection in the SBOX
        //subestitute the pt_matrix using the sbox matrix string 
        public string[,] Subbytes(string[,] plainText, string[,] sBox, int size)
        {
            string[,] newPlainText = new string[size, size];

            for (int i = 0; i < size; i++)
            {
                for (int j = 0; j < size; j++)
                {

                    newPlainText[i, j] = sBox[convertCharToInt16(plainText[i, j][0]), convertCharToInt16(plainText[i, j][1])];
                }
            }
            return newPlainText;
        }


        public string convert_byteArray_to_stringArray(byte[] byte_array)
        {
            string str = BitConverter.ToString(byte_array);
            str = str.Replace("-", string.Empty);

            return str;
        }

        //PREPARATON The PlainText string input
        //To used as a Matrix of strings 
        //Filled Col by Col
        //convert the stirng to 2d string matrix --- k is iterator to the string
        public string[,] PreparePlainText(string plainText, int size)
        {
            string[,] newPlainText = new string[size, size];

            int k = 0;
            for (int i = 0; i < size; i++)
            {
                for (int j = 0; j < size; j++)
                {
                    newPlainText[j, i] = plainText.Substring(2 * k, 2);
                    k++;
                }
            }
            return newPlainText;
        }

        //Convert string array to byte matrix 
        public byte[,] convert_the_stringArray_to_2d_byteArray(string s, int size_matrix, string name)
        {
            byte[,] matrix_str = new byte[size_matrix, size_matrix];

            int k = 0;
            for (int i = 0; i < size_matrix; i++)
            {
                for (int j = 0; j < size_matrix; j++)
                {
                    matrix_str[j, i] = Convert.ToByte(s.Substring(2 * k, 2), 16);
                    //Console.Write(matrix_str[j, i] + "    ");
                    k++;
                }
                //Console.WriteLine();
            }

            return matrix_str;
        }

        public int convertCharToInt16(char x)
        {
            int number = 0;
            if (x >= '0' && x <= '9')
            {
                number = (int)x - '0';
            }
            else if (x >= 'A' && x <= 'Z')
            {
                number = ((int)x - 'A') + 10;
            }
            else if (x >= 'a' && x <= 'z')
            {
                number = ((int)x - 'a') + 10;
            }

            return number;
        }

        //get the old key and the round number and return the NEW Key 
        static String[,] Createnewkey(String[,] key, int round)
        {
            int size = Convert.ToInt32(Math.Sqrt(key.Length));
            String[,] rotWordKey = new String[size, size];
            for (int i = 0; i < size; i++)
            {
                for (int j = 0; j < size; j++)
                {
                    rotWordKey[i, j] = key[i, j];
                }
            }
            String tmp = rotWordKey[0, size - 1];
            //STEP 1
            //swap first cell with last cell and shift the others
            for (int i = 0; i < size; i++)
            {
                if (i != (size - 1))
                    rotWordKey[i, size - 1] = rotWordKey[(i + 1), size - 1];
                else if (i == (size - 1))
                {
                    rotWordKey[size - 1, size - 1] = tmp;
                }
            }
            //STEP 2
            //Convert the first column with the intercetion of each cell in s-box
            for (int i = 0; i < size; i++)
            {

                rotWordKey[i, size - 1] = intersectionSbox(Convertsbox(SBOX), rotWordKey[i, size - 1]);
                //Console.WriteLine("Intersect "+ rotWordKey[i,size-1]);
            }
            //STEP 3
            //fill up the first column in the NEW Key 
            String[,] newKey = new String[size, size];
            int col = 0;
            int colKey = 0;
            if (round == 1)
            {
                col = 0;
            }
            else
            {
                col = round - 1;
            }
            for (int i = 0; i < size; i++)
            {
                int res = Convert.ToInt32(key[i, colKey], 16) ^ Convert.ToInt32(RCON[i, col], 16) ^ Convert.ToInt32(rotWordKey[i, size - 1], 16);
                newKey[i, colKey] = res.ToString("X2");
                //Console.WriteLine(newKey[i, colKey].ToString());
            }
            //STEP 4
            //fill up the remaining columns in the NEW Key 
            for (int j = 1; j < size; j++)
            {
                for (int i = 0; i < size; i++)
                {
                    int res = Convert.ToInt32(key[i, j], 16) ^ Convert.ToInt32(newKey[i, j - 1], 16);
                    newKey[i, j] = res.ToString("X2");
                    //Console.WriteLine("OLD "+key[i, j]+" NEW "+ newKey[i, j - 1]);
                    //Console.WriteLine(newKey[i, j]);

                }
            }

            return newKey;

        }

        //Create Inverse Key 
        static String[,] CreateInversenewkey(String[,] key, int round)
        {

            int size = Convert.ToInt32(Math.Sqrt(key.Length));
            String[,] newKey = new String[size, size];

            //Step 1 XOR the Key matrix Ci^Ci-1
            for (int i = size - 1; i > 0; i--)
            {
                for (int j = 0; j < size; j++)
                {
                    int tmp = Convert.ToInt32(key[j, i], 16) ^ Convert.ToInt32(key[j, i - 1], 16);
                    newKey[j, i] = tmp.ToString("X2");
                }
            }
            //Step 1 Contains 3 steps Finding the First Column 

            //STEP 1of3    Fninding RotWord
            String[] rotWord = new String[size];
            for (int i = 0; i < size; i++)
            {
                rotWord[i] = newKey[i, size - 1];
            }
            String t = rotWord[0];
            for (int i = 0; i < size - 1; i++)
                rotWord[i] = rotWord[i + 1];
            rotWord[size - 1] = t;
            for (int i = 0; i < size; i++)
            {
                rotWord[i] = intersectionSbox(Convertsbox(SBOX), rotWord[i]);

            }

            if (round <= 10)
            {
                round = 10 - round;
            }

            for (int i = 0; i < size; i++)
            {
                //Console.WriteLine(" rot " + rotWord[i], 16);
                //Console.WriteLine(" RCON " + RCON[i, 9 - round]);
                //Console.WriteLine(" Key " + key[i, 0]);
                int tmp = Convert.ToInt32(rotWord[i], 16) ^ Convert.ToInt32(RCON[i, round], 16) ^ Convert.ToInt32(key[i, 0], 16);
                newKey[i, 0] = tmp.ToString("X2");

            }



            return newKey;

        }

        //returns the cell of the intersection in the sbox matrix 
        //SUBBytes function
        static String intersectionSbox(String[,] sBox, String cell)
        {
            int row;
            int col;
            cell = cell.ToUpper();
            if (cell[0] >= '0' && cell[0] <= '9')
            {
                row = cell[0] - '0';
            }
            else
            {
                row = cell[0] - 'A' + 10;
            }
            if (cell[1] >= '0' && cell[1] <= '9')
            {
                col = cell[1] - '0';
            }
            else
            {
                col = cell[1] - 'A' + 10;

            }

            //Console.WriteLine(row + " " + col);
            String returnedCell = sBox[row, col];
            return returnedCell;

        }

        //Step 4 plaintext of type Matrix of string XOR the key of type Matrix of string
        // The result matrix is filled col by col 
        static String[,] Addroundkey(String[,] plainText, String[,] key, double keySize)
        {
            String[,] matrixResult = new string[plainText.Length, plainText.Length];
            for (int i = 0; i < Math.Sqrt(plainText.Length); i++)
            {
                for (int j = 0; j < Math.Sqrt(plainText.Length); j++)
                {
                    int r1 = Convert.ToInt32(plainText[j, i], Convert.ToInt32(keySize));
                    int r2 = Convert.ToInt32(key[j, i], Convert.ToInt32(keySize));

                    int result = r1 ^ r2;
                    matrixResult[j, i] = result.ToString("X2");
                    //Console.WriteLine(matrixResult[j,i]);

                }
            }
            return matrixResult;

        }
    }
}
