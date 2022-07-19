using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public string Encrypt(string plainText, int key)
        {
            String ciphertext = "";
            int keyindex = 0;
            foreach(char c in plainText)
            {
                keyindex = char.ToUpper(c) - 65;
                keyindex += key;
                if(keyindex >= 26)
                {
                    keyindex = keyindex % 26;
                }
                ciphertext += char.ConvertFromUtf32(keyindex + 65);
                keyindex = 0;
            }
            return ciphertext;
            
        }

        public string Decrypt(string cipherText, int key)
        {
            cipherText = cipherText.ToLower();
            int count = 26 - key;
            int i = 0;
            List<char> Alphabets = new List<char>();
            List<char> cipherAlphabet1 = new List<char>();
            List<char> cipherAlphabet2 = new List<char>();
            List<char> output = new List<char>();
            for (char c = 'a'; c <= 'z'; c++)
            {
                Alphabets.Add(c);
                i++;
                if (i > count)
                {

                    cipherAlphabet1.Add(c);
                }
                else
                {
                    cipherAlphabet2.Add(c);
                }
            }
            List<char> cipherAlphabet = new List<char>();
            cipherAlphabet = cipherAlphabet1.Concat(cipherAlphabet2).ToList();
            //////////////////////////////
            int index;
            foreach (char c in cipherText)
            {

                index = Alphabets.IndexOf(c);
                output.Add(cipherAlphabet[index]);
            }
            return new string(output.ToArray());
            //throw new NotImplementedException();
        }

        public int Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();

            int indexCipher_char = (int)cipherText[0];
            int indexplain_char = (int)plainText[0];
            int key = 0;

            if (indexCipher_char > indexplain_char)
            {
                key = indexCipher_char - indexplain_char;
            }
            else if (indexplain_char > indexCipher_char)
            {
                key = (26 - indexplain_char) + indexCipher_char;
            }

            return key;
            //throw new NotImplementedException();
        }
    }
}
