using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            int value;
            string keystream = "";
            string key = "";
            List<int> cipherindex = new List<int>();
            List<int> plainindex = new List<int>();
            List<int> Keyindex = new List<int>();

            for (int i = 0; i < cipherText.Length; i++)
            {
                cipherindex.Add(char.ToUpper(cipherText[i]) - 65);
                plainindex.Add(char.ToUpper(plainText[i]) - 65);

                value = cipherindex[i] - plainindex[i];
                if(value < 0)
                {
                    value += 26;
                }
                keystream += char.ConvertFromUtf32(value + 65);
            }
            keystream = keystream.ToLower();
            for (int i = 0; i < keystream.Length; i++ )
            {
                if (keystream[i] == plainText[0])
                {
                    break;
                }
                else
                    key += keystream[i];
            }

            return key;

                //throw new NotImplementedException();
        }

        public string Decrypt(string cipherText, string key)
        {
            String plaintext = "";
            int value;
            List<int> cipherindex = new List<int>();
            List<int> keyindex = new List<int>();
            for (int i = 0; i < cipherText.Length; i++)
            {
                cipherindex.Add(char.ToUpper(cipherText[i]) - 65);
            }
            for (int j = 0; j < key.Length; j++)
            {
                keyindex.Add(char.ToUpper(key[j]) - 65);
            }
            for (int k = 0; k < cipherText.Length; k++ )
            {
                value = cipherindex[k] - keyindex[k];
                if(value<0)
                {
                    value += 26;
                }
                keyindex.Add(value);
                plaintext += char.ConvertFromUtf32(value + 65);
            }
            plaintext = plaintext.ToLower();
            return plaintext;
              //  throw new NotImplementedException();
        }

        public string Encrypt(string plainText, string key)
        {
            plainText = plainText.ToLower();
            key = key.ToLower();
            string keyStream = key + plainText;
            keyStream = keyStream.Remove(plainText.Length, key.Length);
            List<char> CipherText = new List<char>();
            for (int i = 0; i < plainText.Length; i++)
            {
                int iPlain = plainText[i] - 97;
                int iKey = keyStream[i] - 97;
                CipherText.Add((char)(97 + ((iPlain + iKey) % 26)));
            }
            return new string(CipherText.ToArray());
            //throw new NotImplementedException();
        }
    }
}
