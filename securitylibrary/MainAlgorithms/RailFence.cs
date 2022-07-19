using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        int key;
        public int Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            for (int i = 0; i < plainText.Length; i++ )
            {
                if(plainText.Length % 2 == 0)
                {
                    if (plainText[plainText.Length - 1] == cipherText[cipherText.Length - 1] && plainText[plainText.Length - 2] == cipherText[i])
                    {
                        key = i;
                        break;
                    }
                }
                else
                {
                    if (plainText[plainText.Length - 1] == cipherText[i] && plainText[plainText.Length - 2] == cipherText[cipherText.Length - 1])
                    {
                        key = i;
                        break;
                    }
                }

            }
                return plainText.Length / key;
                //throw new NotImplementedException();
        }

        public string Decrypt(string cipherText, int key)
        {
            int index = 0;
            string plaintext = "";
            decimal value = cipherText.Length;
            int halfciphertext = (int)Math.Ceiling(value / key);
            char[,] array = new char[key, halfciphertext];

            for (int i = 0; i < key; i++)
            {
                for (int j = 0; j < halfciphertext; j++)
                {
                    array[i, j] = '#';
                }
            }
            for (int i = 0; i < key; i++)
            {
                for (int j = 0; j < halfciphertext; j++)
                {
                    array[i, j] = cipherText[index];
                    index++;
                    if (index == cipherText.Length)
                    {
                        break;
                    }
                }

            }

            int count = 0;
            for (int i = 0; i < halfciphertext; i++)
            {
                for (int j = 0; j < key; j++)
                {
                    if(count == cipherText.Length)
                    {
                        break;
                    }
                    if (array[j, i] == '#')
                    {
                        continue;
                    }
                    plaintext += array[j, i];
                    count++;
                }

            }

            return plaintext;

            //throw new NotImplementedException();
        }

        public string Encrypt(string plainText, int key)
        {
            int index = 0;
            string ciphertext = "";
            decimal value = plainText.Length;
            int halfplaintext = (int)Math.Ceiling(value / key);
            char[,] array = new char[key, halfplaintext];

            for(int i = 0 ; i < key; i++)
            {
                for(int j=0; j<halfplaintext; j++)
                {
                    array[i, j] = '#';
                }
            }
            for (int i = 0; i < halfplaintext; i++ )
            {
                for(int j = 0; j<key; j++)
                {
                    array[j, i] = plainText[index];
                    index++;
                    if(index == plainText.Length)
                    {
                        break;
                    }
                }

            }
            int count = 0;
            for (int k = 0; k < key; k++)
            {
                for (int m = 0; m < halfplaintext; m++)
                {
                    if (count == plainText.Length)
                    {
                        break;
                    }
                    if(array[k,m] == '#')
                    {
                        continue;
                    }
                    ciphertext+=(array[k, m]);
                    count++;
                }
            }
            return ciphertext;

               //throw new NotImplementedException();
        }
    }
}
