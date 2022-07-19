using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographic_Technique<string, string>
    {
        public string Decrypt(string cipherText, string key)
        {
            string ex = "ABCDEFGHIKLMNOPQRSTUVWXYZ";
            Dictionary<char, long> visted = new Dictionary<char, long>();
            cipherText = cipherText.ToUpper();
            key = key.ToUpper();
            char[,] array = new char[5, 5];
            int row = 0, column = 0;
            for (int i = 0; i < key.Length; i++)
            {
                if (!visted.ContainsKey(key[i]))
                {
                    array[row, column] = key[i];
                    visted[key[i]] = 1;
                    if (key[i] == 'I')
                        visted['J'] = 1;
                    else if (key[i] == 'J')
                        visted['I'] = 1;
                    column++;
                }
                if (column == 5) { row++; column = 0; }
                if (row == 5) break;
            }
            for (int i = 0; i < ex.Length; i++)
            {
                if (!visted.ContainsKey(ex[i]))
                {
                    array[row, column] = ex[i];
                    visted[ex[i]] = 1;
                    if (ex[i] == 'I')
                        visted['J'] = 1;
                    else if (ex[i] == 'J')
                        visted['I'] = 1;
                    column++;
                }
                if (column == 5) { row++; column = 0; }
                if (row == 5) break;
            }

            string re = "";
            for (int i = 0; i < cipherText.Length; i += 2)
            {
                int r1 = 0, c1 = 0, r2 = 0, c2 = 0;

                char h1 = cipherText[i], h2 = cipherText[i + 1], h3, h4;
                if (h1 == 'I') h3 = 'J';
                else if (h1 == 'J') h3 = 'I';
                else h3 = h1;
                if (h2 == 'I') h4 = 'J';
                else if (h2 == 'J') h4 = 'I';
                else h4 = h2;
                for (int j = 0; j < 5; j++)
                {
                    for (int k = 0; k < 5; k++)
                    {
                        if (array[j, k] == h1 || array[j, k] == h3)
                        {
                            r1 = j;
                            c1 = k;
                        }
                        if (array[j, k] == h2 || array[j, k] == h4)
                        {
                            r2 = j;
                            c2 = k;
                        }

                    }
                }
                if (r1 == r2)
                {
                    if (c1 - 1 < 0)
                    {
                        re += array[r1, 4];
                    }
                    else
                    {
                        re += array[r1, c1 - 1];
                    }
                    if (c2 - 1 < 0)
                    {
                        re += array[r2, 4];
                    }
                    else
                    {
                        re += array[r2, c2 - 1];
                    }
                }
                else if (c1 == c2)
                {
                    if (r1 - 1 < 0)
                    {
                        re += array[4, c1];
                    }
                    else
                    {
                        re += array[r1 - 1, c1];
                    }
                    if (r2 - 1 < 0)
                    {
                        re += array[4, c1];
                    }
                    else
                    {
                        re += array[r2 - 1, c1];
                    }
                }
                else
                {
                    re += array[r1, c2];
                    re += array[r2, c1];
                }
            }
            string re_f = "";
            for (int i = 1; i < re.Length; i += 2)
            {
                if (i == re.Length - 1)
                {
                    re_f += re[i - 1];
                    if (re[i] != 'X') re_f += re[i];
                    break;
                }
                if (re[i] == 'X')
                {
                    if (re[i - 1] != re[i + 1])
                    {
                        re_f += re[i - 1];
                        re_f += re[i];
                    }
                    else re_f += re[i - 1];
                }
                else { re_f += re[i - 1]; re_f += re[i]; }
            }
            return re_f;
            //throw new NotImplementedException();
        }

        public string Encrypt(string plainText, string key)
        {
            string ex = "ABCDEFGHIKLMNOPQRSTUVWXYZ";
            Dictionary<char, long> visted = new Dictionary<char, long>();
            plainText = plainText.ToUpper();
            key = key.ToUpper();
            char[,] array = new char[5, 5];
            int row = 0, column = 0;
            for (int i = 0; i < key.Length; i++)
            {
                if (!visted.ContainsKey(key[i]))
                {
                    array[row, column] = key[i];
                    visted[key[i]] = 1;
                    if (key[i] == 'I')
                        visted['J'] = 1;
                    else if (key[i] == 'J')
                        visted['I'] = 1;
                    column++;
                }
                if (column == 5) { row++; column = 0; }
                if (row == 5) break;
            }
            for (int i = 0; i < ex.Length; i++)
            {
                if (!visted.ContainsKey(ex[i]))
                {
                    array[row, column] = ex[i];
                    visted[ex[i]] = 1;
                    if (ex[i] == 'I')
                        visted['J'] = 1;
                    else if (ex[i] == 'J')
                        visted['I'] = 1;
                    column++;
                }
                if (column == 5) { row++; column = 0; }
                if (row == 5) break;
            }
            List<char> lis = new List<char>();

            for (int i = 0; i < plainText.Length; i++)
            {
                if (i + 1 < plainText.Length)
                {
                    if (plainText[i] == plainText[i + 1])
                    {
                        lis.Add(plainText[i]);
                        lis.Add('X');
                    }
                    else
                    {
                        lis.Add(plainText[i]);
                        lis.Add(plainText[i + 1]);
                        i++;
                    }
                }
                else
                {
                    lis.Add(plainText[i]);
                    lis.Add('X');
                }
            }
            string re = "";
            for (int i = 0; i < lis.Count; i += 2)
            {
                int r1 = 0, c1 = 0, r2 = 0, c2 = 0;

                char h1 = lis[i], h2 = lis[i + 1], h3, h4;
                if (h1 == 'I') h3 = 'J';
                else if (h1 == 'J') h3 = 'I';
                else h3 = h1;
                if (h2 == 'I') h4 = 'J';
                else if (h2 == 'J') h4 = 'I';
                else h4 = h2;
                for (int j = 0; j < 5; j++)
                {
                    for (int k = 0; k < 5; k++)
                    {
                        if (array[j, k] == h1 || array[j, k] == h3)
                        {
                            r1 = j;
                            c1 = k;
                        }
                        if (array[j, k] == h2 || array[j, k] == h4)
                        {
                            r2 = j;
                            c2 = k;
                        }

                    }
                }
                if (r1 == r2)
                {
                    if (c1 + 1 == 5)
                    {
                        re += array[r1, 0];
                    }
                    else
                    {
                        re += array[r1, c1 + 1];
                    }
                    if (c2 + 1 == 5)
                    {
                        re += array[r2, 0];
                    }
                    else
                    {
                        re += array[r2, c2 + 1];
                    }
                }
                else if (c1 == c2)
                {
                    if (r1 + 1 == 5)
                    {
                        re += array[0, c1];
                    }
                    else
                    {
                        re += array[r1 + 1, c1];
                    }
                    if (r2 + 1 == 5)
                    {
                        re += array[0, c1];
                    }
                    else
                    {
                        re += array[r2 + 1, c1];
                    }
                }
                else
                {
                    re += array[r1, c2];
                    re += array[r2, c1];
                }
            }

            return re;
            //throw new NotImplementedException();
        }
    }
}
