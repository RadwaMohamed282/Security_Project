using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();

            List<int> Key = new List<int>();

            int n = plainText.Length;

            for (int i = 2; i < n; i++)
            {
                Key = new List<int>();
                int iterator = 0;
                int cols = i;
                int rows = n / cols;

                if (rows * cols < n)
                {
                    rows += 1;
                }

                List<List<char>> Plainmatrix = new List<List<char>>();
                List<List<char>> Ciphermatrix = new List<List<char>>();
                for (int zeft = 0; zeft < rows; zeft++)
                {
                    Ciphermatrix.Add(new List<char>());
                    Plainmatrix.Add(new List<char>());
                }


                for (int c = 0; c < cols; c++)
                {
                    for (int r = 0; r < rows; r++)
                    {
                        if (c < cols - ((rows * cols) - n))
                        {
                            Ciphermatrix[r].Add(cipherText[iterator]);

                            iterator++;
                        }
                        else
                        {
                            if (r == rows - 1)
                            {
                                Ciphermatrix[r].Add('x');

                            }
                            else
                            {

                                Ciphermatrix[r].Add(cipherText[iterator]);

                                iterator++;
                            }
                        }
                    }
                }

                iterator = 0;
                for (int r = 0; r < rows; r++)
                {
                    for (int c = 0; c < cols; c++)
                    {
                        if (c < cols - ((rows * cols) - n))
                        {
                            Plainmatrix[r].Add(plainText[iterator]);

                            iterator++;
                        }
                        else
                        {
                            if (r == rows - 1)
                            {
                                Plainmatrix[r].Add('x');

                            }
                            else
                            {

                                Plainmatrix[r].Add(plainText[iterator]);

                                iterator++;
                            }
                        }
                    }
                }

                for (int c = 0; c < cols; c++)//maska col of plain
                {
                    for (int x = 0; x < cols; x++)//bdwr f kol l col fl cipher
                    {
                        for (int r = 0; r < rows; r++)
                        {
                            if (Plainmatrix[r][c] == Ciphermatrix[r][x])
                            {
                                if (r == rows - 1)
                                {
                                    Key.Add(x + 1);
                                }
                                continue;

                            }
                            else
                            {
                                break;
                            }




                        }


                    }
                }
                if (Key.Count == cols)
                {

                    break;
                }


            }
            return Key;
            //throw new NotImplementedException();
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            string PT = "";
            double CT_length = cipherText.Length;
            double no_rows = (CT_length / (key.Count()));

            // if no. of rows s fraction it must be round to the next whole no.
            int Rows = (int)Math.Ceiling(no_rows);

            //The Matrix 2d
            char[,] Array_2d = new char[Rows, key.Count()];

            //Map the key values with its indicies 
            Dictionary<int, int> map_of_key = new Dictionary<int, int>();
            for (int i = 0; i < key.Count(); i++)
            {
                map_of_key[key[i]] = i;
            }

            // get the empty cells number to determine them in the last row
            int empty_cells = (Rows * key.Count()) - (int)CT_length;

            for (int i = 1; i <= empty_cells; i++)
            {
                Array_2d[Rows - 1, key.Count() - i] = ' ';
            }



            // k is iterartor on cipher text 
            int k = 0;

            // loop to fill the 2d matrix with the right permutations 
            for (int i = 0; i < key.Count(); i++)
            {
                for (int j = 0; j < Rows; j++)
                {
                    if (k < CT_length && Array_2d[j, i] != ' ')
                    {
                        Array_2d[j, map_of_key[i + 1]] = cipherText[k];
                        k++;
                    }

                }
            }
            //Reading the matrix row wise to get Plain text "PT"
            for (int i = 0; i < Rows; i++)
            {
                for (int j = 0; j < key.Count(); j++)
                {
                    PT += Array_2d[i, j];
                }
            }

            // Console.WriteLine(PT);
            return PT;
            //throw new NotImplementedException();
        }

        public string Encrypt(string plainText, List<int> key)
        {

            plainText = plainText.ToUpper();
            int x = plainText.Length / key.Count, z = 0;
            if (plainText.Length % key.Count != 0)
                x++;
            char[,] arr = new char[x, key.Count];
            for (int i = 0; i < x; i++)
            {
                for (int j = 0; j < key.Count; j++)
                {
                    if (z == plainText.Length)
                    {
                        arr[i, j] = 'X';
                    }
                    else
                    {
                        arr[i, j] = plainText[z];
                        z++;
                    }
                }

            }
            string re = "";
            for (int j = 1; j <= key.Count; j++)
            {
                for (int i = 0; i < key.Count; i++)
                {
                    if (key[i] == j)
                    {
                        for (int h = 0; h < x; h++)
                        {
                            re += arr[h, i];
                        }
                    }
                }
            }
            return re;
            //throw new NotImplementedException();
        }
    }
}
