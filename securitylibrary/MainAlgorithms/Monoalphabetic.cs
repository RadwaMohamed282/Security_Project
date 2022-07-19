using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            string key = "";
            int plainindex, cipherindex, exist = 0;
            List<int> distenct = new List<int>();
            int[] array = new int[26];
            for(int k =0; k<array.Length; k++)
            {
                distenct.Add(k);
                array[k] = -1;
            }
            for (int i = 0; i < plainText.Length; i++)
            {
                plainindex = char.ToUpper(plainText[i]) - 65;
                cipherindex = char.ToUpper(cipherText[i]) -65;
                array[plainindex] = cipherindex;
                distenct.Remove(cipherindex);
            }

            for (int j = 0; j < array.Length; j++)
            {
                if (array[j] == -1)
                {
                    array[j] = distenct[exist];
                    exist += 1;
                }
                key += char.ConvertFromUtf32(array[j] + 65);
            }
            key = key.ToLower();
            return key;
                //throw new NotImplementedException();
        }

        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            string PT = "";
            int index;

            // get the index of each charcter of cipher from the key 
            for (int i = 0; i < cipherText.Length; i++)
            {
                index = key.IndexOf(cipherText[i]);
                //get the mapping charcter in alphapetic using ascii
                char letter = (char)(index + 97);
                Console.WriteLine((int)cipherText[i]);
                Console.WriteLine(cipherText[i]);
                PT += letter;

            }

            return PT;
            //throw new NotImplementedException();
        }

        public string Encrypt(string plainText, string key)
        {

            String encrypted = "";
            for (int i = 0; i < plainText.Length; i++)
            {
                char x = plainText[i];
                int index;
                if (Char.IsUpper(x))
                {
                    index = x - 65;
                }
                else
                {
                    index = x - 97;
                }

                encrypted += key[index];
            }
            Console.Write(encrypted.ToUpper());
            return encrypted.ToLower();
            //throw new NotImplementedException();
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            int SIZE = 26;
            String str = cipher.ToLower();
            int str_length = str.Length;
            //array with size of the letters
            int[] freq = new int[SIZE];
            char[] freqInfo = new char[] { 'E', 'T', 'A', 'O', 'I', 'N', 'S', 'R', 'H', 'L', 'D', 'C', 'U', 'M', 'F', 'P', 'G', 'W', 'Y', 'B', 'V', 'K', 'X', 'J', 'Q', 'Z' };

            //each char exist assign counter to it and count
            for (int i = 0; i < str_length; i++)
                freq[str[i] - 'a']++;

            //Add them in Dictionary 
            Dictionary<char, int> alphFreq = new Dictionary<char, int>();
            for (int i = 0; i < str_length; i++)
            {
                if (!alphFreq.ContainsKey(str[i]))
                {
                    alphFreq.Add(str[i], freq[str[i] - 'a']);
                    freq[str[i] - 'a'] = 0;

                }
            }


            //Sorted in descending order
            Dictionary<char, char> encodedalphaFreq = new Dictionary<char, char>();
            int index = 0;
            foreach (var item in alphFreq.OrderByDescending(i => i.Value))
            {
                encodedalphaFreq.Add(item.Key, freqInfo[index]);
                index++;
            }
            StringBuilder returnedString = new StringBuilder();
            for (int i = 0; i < str_length; i++)
            {
                returnedString.Append(encodedalphaFreq[str[i]]);
            }
            return returnedString.ToString();


            //Sort the Dictionary 


            //Create a new Dictionary char and char 

            //identify which character in the string and print it from the Dictionary 


            //The array contains a counter for each letter 


            //Assign for each letter grom freq array a letter from frequency information

           // throw new NotImplementedException();
        }
    }
}
