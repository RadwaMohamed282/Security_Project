using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher :  ICryptographicTechnique<List<int>, List<int>>
    {
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            int value1,value2,value3;
            List<int> key = new List<int>();
            for (int i = 0; i < 26; i++ )
            {
                for(int j =0; j<26; j++)
                {
                    value1 = (i*plainText[0] + j*plainText[1]) % 26;
                    value2 = (i * plainText[2] + j * plainText[3]) % 26;
                    value3 = (i * plainText[4] + j * plainText[5]) % 26;
                    if(value1 == cipherText[0] && value2 == cipherText[2] && value3 == cipherText[4])
                    {
                        key.Add(i);
                        key.Add(j);
                    }
                }
            }
            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    value1 = (i * plainText[0] + j * plainText[1]) % 26;
                    value2 = (i * plainText[2] + j * plainText[3]) % 26;
                    value3 = (i * plainText[4] + j * plainText[5]) % 26;
                    if (value1 == cipherText[1] && value2 == cipherText[3] && value3 == cipherText[5])
                    {
                        key.Add(i);
                        key.Add(j);
                        
                    }
                }
            }
            return key;
                //throw new NotImplementedException();
        }


        static int Tomodulus(int x)
        {
            while (x < 0)
            {
                x += 26;
            }
            return x;
        }
        static int[,] transpose(int[,] t, int rows, int col)
        {
            int[,] tt = new int[col, rows];

            for (int i = 0; i < rows; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    tt[i, j] = t[j, i];
                }
            }
            return tt;
        }

        static int GCD(int num1, int num2)
        {
            int Remainder;

            while (num2 != 0)
            {
                Remainder = num1 % num2;
                num1 = num2;
                num2 = Remainder;
            }

            return num1;
        }
        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            int keysize = Convert.ToInt32(Math.Sqrt(key.Count));
            int cipherLength = cipherText.Count / keysize;
            int[,] cipherText2D = new int[keysize, cipherLength];
            int[,] key2D = new int[keysize, keysize];
            int[,] key2DtoInverse = new int[keysize, keysize];
            int det = 0;
            int[,] key2DInverse = new int[keysize, keysize];
            List<int> encrypted = new List<int>();

            //converting the key to a 2D array and checking the availability of the array's elements 
            int x = 0;
            for (int i = 0; i < keysize; i++)
            {
                for (int j = 0; j < keysize; j++)
                {
                    if (key[x] < 26 && key[x] >= 0)
                    {
                        key2D[i, j] = key[x];
                        x++;
                    }
                    else
                    {
                        //Output error 
                        //Console.WriteLine("Elements of the  key are invalid");
                        throw new InvalidAnlysisException();
                    }
                }

            }

            //Converting the list of the cipherText to a 2D array 
            x = 0;
            for (int i = 0; i < cipherLength; i++)
            {
                for (int j = 0; j < keysize; j++)
                {
                    cipherText2D[j, i] = cipherText[x];
                    x++;
                }
            }

            //choosing the technique based on the size of the key 
            if (keysize == 2)
            {
                //Calculating the det manullay 
                det = key2D[0, 0] * key2D[1, 1] - key2D[0, 1] * key2D[1, 0];
                //Console.WriteLine("Det" + det);
                //Check the availability of the det result
                if (det != -1 && det != 1)
                {
                    throw new InvalidAnlysisException();
                    //Console.WriteLine("Invalid det");
                }
                //calculating the inverse of the key 
                else
                {
                    int tmp = 1 / det;
                    key2DInverse[0, 0] = key2D[1, 1] * tmp;
                    key2DInverse[0, 1] = key2D[0, 1] * tmp * -1;
                    key2DInverse[1, 0] = key2D[1, 0] * tmp * -1;
                    key2DInverse[1, 1] = key2D[0, 0] * tmp;
                    for (int i = 0; i < keysize; i++)
                    {
                        for (int j = 0; j < keysize; j++)
                        {
                            if (key2DInverse[i, j] < 0)
                            {
                                key2DInverse[i, j] = Tomodulus(key2DInverse[i, j]);
                            }
                            //Console.Write(key2DInverse[i, j] + " ");

                            key2DInverse[i, j] = key2DInverse[i, j] % 26;
                            //Console.Write(i + "i " + j + "j " + key2DInverse[i, j] + "element ");

                        }
                    }



                    //calculating the plain text 
                    int[,] c = new int[keysize, cipherLength];
                    for (int i = 0; i < keysize; i++)
                    {
                        for (int j = 0; j < cipherLength; j++)
                        {
                            c[i, j] = 0;
                            for (int k = 0; k < keysize; k++)
                            {
                                c[i, j] += key2DInverse[i, k] * cipherText2D[k, j];
                            }
                        }

                    }

                    //Printing the plain text

                    for (int i = 0; i < cipherLength; i++)
                    {
                        for (int j = 0; j < keysize; j++)
                        {
                            //Console.Write(i.ToString()+ "  "+ j.ToString()+" ");

                            c[j, i] = c[j, i] % 26;
                            //Console.WriteLine(c[j, i]);
                            encrypted.Add(c[j, i]);
                        }


                    }

                }
            }
            else if (keysize == 3)
            {
                det = 0;
                //Calculating Determinant 
                det += key2D[0, 0] * ((key2D[1, 1] * key2D[2, 2]) - (key2D[1, 2] * key2D[2, 1]));
                det -= key2D[0, 1] * ((key2D[1, 0] * key2D[2, 2]) - (key2D[1, 2] * key2D[2, 0]));
                det += key2D[0, 2] * ((key2D[1, 0] * key2D[2, 1]) - (key2D[1, 1] * key2D[2, 0]));

                //Console.WriteLine("det value " + det);
                //calculating b value 
                if (det < 0)
                {
                    det = Tomodulus(det);
                }
                //Console.WriteLine("det value " + det);


                //checking the gcd 
                int r;
                r = GCD(det, 26);
                if (r != 1)
                {
                    throw new InvalidAnlysisException();
                }

                //Calculating b value 
                double b = 1;
                for (int i = 0; i < 26; i++)
                {
                    if (b * det % 26 == 1)
                    {
                        break;
                    }
                    else
                    {
                        b++;
                    }
                }

                //Console.WriteLine("b value " + b);
                //Calculate inverse 
                key2DtoInverse[0, 0] = Convert.ToInt32(b) * Convert.ToInt32(Math.Pow(-1, 0)) * (key2D[1, 1] * key2D[2, 2] - key2D[1, 2] * key2D[2, 1]) % 26;
                key2DtoInverse[0, 1] = Convert.ToInt32(b) * Convert.ToInt32(Math.Pow(-1, 1)) * (key2D[1, 0] * key2D[2, 2] - key2D[1, 2] * key2D[2, 0]) % 26;
                key2DtoInverse[0, 2] = Convert.ToInt32(b) * Convert.ToInt32(Math.Pow(-1, 2)) * (key2D[1, 0] * key2D[2, 1] - key2D[1, 1] * key2D[2, 0]) % 26;

                key2DtoInverse[1, 0] = Convert.ToInt32(b) * Convert.ToInt32(Math.Pow(-1, 1)) * (key2D[0, 1] * key2D[2, 2] - key2D[2, 0] * key2D[0, 2]) % 26;
                key2DtoInverse[1, 1] = Convert.ToInt32(b) * Convert.ToInt32(Math.Pow(-1, 2)) * (key2D[0, 0] * key2D[2, 2] - key2D[2, 0] * key2D[0, 2]) % 26;
                key2DtoInverse[1, 2] = Convert.ToInt32(b) * Convert.ToInt32(Math.Pow(-1, 3)) * (key2D[0, 0] * key2D[2, 1] - key2D[0, 1] * key2D[2, 0]) % 26;

                key2DtoInverse[2, 0] = Convert.ToInt32(b) * Convert.ToInt32(Math.Pow(-1, 2)) * (key2D[0, 1] * key2D[1, 2] - key2D[0, 2] * key2D[1, 1]) % 26;
                key2DtoInverse[2, 1] = Convert.ToInt32(b) * Convert.ToInt32(Math.Pow(-1, 3)) * (key2D[0, 0] * key2D[1, 2] - key2D[0, 2] * key2D[1, 0]) % 26;
                key2DtoInverse[2, 2] = Convert.ToInt32(b) * Convert.ToInt32(Math.Pow(-1, 4)) * (key2D[0, 0] * key2D[1, 1] - key2D[0, 1] * key2D[1, 0]) % 26;


                /* Console.WriteLine("before transpose");
                 for (int i=0; i<keysize; i++)
                 {
                     for (int j=0; j<keysize;j++)
                     {
                         if(key2DtoInverse[i,j]<0)
                         {
                             key2DtoInverse[i, j] = Tomodulus(key2DtoInverse[i, j]);
                         }
                         Console.WriteLine(key2DtoInverse[i, j]+" ");
                     }
                     Console.WriteLine();
                 }*/

                //Transpose the key matrix 
                int[,] key2DinverseTranspose = new int[keysize, keysize];
                key2DinverseTranspose = transpose(key2DtoInverse, keysize, keysize);


                for (int i = 0; i < keysize; i++)
                {
                    for (int j = 0; j < keysize; j++)
                    {
                        if (key2DtoInverse[i, j] < 0)
                        {
                            key2DinverseTranspose[i, j] = Tomodulus(key2DinverseTranspose[i, j]);
                        }
                        // Console.WriteLine(key2DinverseTranspose[i, j] + " ");
                    }
                    //Console.WriteLine();
                }

                //Multiplying 
                //calculating the plain text 
                int[,] cipher = new int[keysize, cipherLength];
                for (int i = 0; i < keysize; i++)
                {
                    for (int j = 0; j < cipherLength; j++)
                    {
                        cipher[i, j] = 0;
                        for (int k = 0; k < keysize; k++)
                        {
                            cipher[i, j] += key2DinverseTranspose[i, k] * cipherText2D[k, j];
                        }
                    }

                }

                //Printing the plain text
                for (int i = 0; i < cipherLength; i++)
                {
                    for (int j = 0; j < keysize; j++)
                    {
                        //Console.Write(i.ToString()+ "  "+ j.ToString()+" ");
                        cipher[j, i] = cipher[j, i] % 26;
                        if (cipher[j, i] < 0)
                        {
                            cipher[j, i] = Tomodulus(cipher[j, i]);
                        }
                        encrypted.Add(cipher[j, i]);
                        //  Console.WriteLine(cipher[j, i]);
                    }

                }
            }
            return encrypted;
            throw new NotImplementedException();
        }


        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            int keysize = Convert.ToInt32(Math.Sqrt(key.Count));
            int plainLength = plainText.Count / keysize;
            int[,] plainText2D = new int[keysize, plainLength];
            int[,] key2D = new int[keysize, keysize];

            int x = 0;
            for (int i = 0; i < keysize; i++)
            {
                for (int j = 0; j < keysize; j++)
                {
                    key2D[i, j] = key[x];
                    x++;
                }

            }

            x = 0;
            for (int i = 0; i < plainLength; i++)
            {
                for (int j = 0; j < keysize; j++)
                {
                    plainText2D[j, i] = plainText[x];
                    x++;
                }
            }

            int[,] cipherText2D = new int[keysize, plainLength];

            int[,] c = new int[keysize, plainLength];
            for (int i = 0; i < keysize; i++)
            {
                for (int j = 0; j < plainLength; j++)
                {
                    c[i, j] = 0;
                    for (int k = 0; k < keysize; k++)
                    {
                        c[i, j] += key2D[i, k] * plainText2D[k, j];
                    }
                }

            }
            List<int> encrypted = new List<int>();
            for (int i = 0; i < plainLength; i++)
            {
                for (int j = 0; j < keysize; j++)
                {
                    //Console.Write(i.ToString()+ "  "+ j.ToString()+" ");
                    c[j, i] = c[j, i] % 26;
                    encrypted.Add(c[j, i]);
                    //Console.WriteLine((freqInfo[c[j, i]]));
                }

            }
            return (encrypted);
            //throw new NotImplementedException();
        }

        public List<int> inv(List<int> key)
        {
            InvalidAnlysisException exp = new InvalidAnlysisException();//threw Exception.
            for (int i = 0; i < key.Count; i++)
            {
                if (key[i] >= 26)
                {
                    if (key[i] < 0)
                    {
                        throw exp;
                    }
                }
            }
            long determenant = -2, idx = -1;
            //get_determenant
            if (key.Count % 3 == 0)
            {
                determenant = ((key[0] * ((key[4] * key[8])
               - (key[5] * key[7])))
               - (key[1] * ((key[3] * key[8]) - (key[5] * key[6])))
               + (key[2] * ((key[3] * key[7]) - (key[4] * key[6]))))
               % 26;
                if (determenant < 0)
                    determenant += 26;
            }
            else if (key.Count % 2 == 0)//key even?
            {
                determenant = ((key[0] * key[3]) - (key[1] * key[2]));
                determenant %= 26;
                if (determenant < 0)
                    determenant += 26;
            }
            if (determenant % 13 == 0 || determenant % 2 == 0 || determenant % 26 == 0 || determenant == 0)//conditions
                throw exp;

            bool getnum = false;
            for (long i = 1; i < 26; i++)
            {
                if ((determenant * i) % 26 == 1)
                {
                    idx = i;
                    getnum = true;
                    break;
                }
            }
            if (!getnum)
                throw exp;

            if (key.Count % 3 == 0)
            {
                long[,] result = new long[3, 3];
                long[,] list = new long[3, 3];
                int i = 0, j = 0;
                for (int ky = 0; ky < key.Count; ky++)
                {
                    list[i, j++] = key[ky];
                    if (j == 3) { i++; j = 0; }
                }

                for (int kw = 0; kw < 3; kw++)
                {
                    for (int lw = 0; lw < 3; lw++)
                    {
                        List<long> vec = new List<long>();
                        for (int iw = 0; iw < 3; iw++)
                        {
                            for (int jw = 0; jw < 3; jw++)
                            {
                                if (iw != kw && jw != lw)
                                {
                                    vec.Add(list[iw, jw]);
                                }
                            }
                        }
                        result[kw, lw] = idx;
                        result[kw, lw] *= (long)Math.Pow(-1, (kw + lw));
                        result[kw, lw] *= (long)((vec[0] * vec[3]) - (vec[1] * vec[2]));
                        result[kw, lw] %= 26;
                        if (result[kw, lw] < 0)
                        {
                            result[kw, lw] += 26;
                        }
                    }
                }
                key.Clear();

                for (i = 0; i < 3; i++)
                {
                    for (j = 0; j < 3; j++)
                    {
                        key.Add((int)result[j, i]);
                    }
                }
            }
            else if (key.Count % 2 == 0)
            {
                long[,] answer_vec = new long[2, 2];
                int i = 0, j = 0;
                int tmp = key[0];
                key[0] = key[3];
                key[3] = tmp;
                for (int k = 0; k < key.Count; k++)
                {
                    answer_vec[i, j] = idx;
                    answer_vec[i, j] *= (long)Math.Pow(-1, (i + j)) * key[k];
                    answer_vec[i, j] %= 26;

                    if (answer_vec[i, j] < 0)
                    {
                        answer_vec[i, j] += 26;
                    }
                    j++;
                    if (j == 2)
                    { j = 0; i++; }
                }

                key.Clear();
                for (i = 0; i < 2; i++)
                    for (j = 0; j < 2; j++)
                        key.Add((int)answer_vec[i, j]);

            }
            return key;
        }
        public List<int> Analyse3By3Key(List<int> plainText, List<int> cipherText)
        {

            plainText = inv(plainText);

            int[,] cipher = new int[3, 3], result = new int[3, 3], plain = new int[3, 3];
            int fnumber = 0;
            int snumber = 0;
            for (int i = 0; i < 9; i++)
            {
                plain[fnumber, snumber] = plainText[i];
                cipher[fnumber, snumber] = cipherText[i];
                snumber++;
                if (snumber == 3) { snumber = 0; fnumber++; }
            }

            for (int iw = 0; iw < 3; iw++)
                for (int jw = 0; jw < 3; jw++)
                    for (int kw = 0; kw < 3; kw++)
                        result[jw, iw] += (plain[iw, kw] * cipher[kw, jw]);

            List<int> ky = new List<int>();
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    result[i, j] %= 26;
                    ky.Add(result[i, j]);
                }
            }
            return ky;
           // throw new NotImplementedException();
        }

    }
}
