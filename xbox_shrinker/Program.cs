using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Xml;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace xbox_shrinker
{
    class Program
    {
        static UInt32[] b_seeds =
        {
            0x52F690D5,
            0x534D7DDE,
            0x5B71A70F,
            0x66793320,
            0x9B7E5ED5,
            0xA465265E,
            0xA53F1D11,
            0xB154430F
        };

        static void Main(string[] args)
        {
            if (!File.Exists("ss.xml"))
            {
                Console.WriteLine("ss.xml missing");
                return;
            }

            XmlDocument ssRanges = new XmlDocument();
            ssRanges.Load("ss.xml");

            byte[] junk = JunkBlock();



            foreach (string arg in args)
            {
                string fileName = arg;


                string romName = Path.GetFileName(arg.Replace(".dec", ""));

                XmlNode rom_xml = ssRanges.DocumentElement.SelectSingleNode(string.Format("rom[@name=\"{0}\"]", romName));

                MD5 hash = MD5.Create();

                string rom_md5 = rom_xml.Attributes["md5"].Value;

                if(rom_xml == null)
                {
                    Console.WriteLine("entry not found in ss.xml");
                    return;
                }

                UInt32 seed = 0;

                if (rom_xml.Attributes["seed"].Value == string.Empty)
                {
                    seed = bruteForceSeed(fileName);

                    if (seed != 0)
                    {
                        rom_xml.Attributes["seed"].Value = string.Format("{0:x8}", seed);
                        ssRanges.Save("ss.xml");
                    }
                }
                else
                {
                    seed = Convert.ToUInt32(rom_xml.Attributes["seed"].Value, 16);
                }

                bool decrypted = mode(fileName, junk);

                string fileNameOut = string.Empty;
                
                if(decrypted)
                {
                    fileNameOut = fileName.Replace(".iso.dec", ".iso");
                }
                else
                {
                    fileNameOut = fileName + ".dec";
                }

                if (decrypted)
                {
                    Console.WriteLine("starting encryption process");
                }
                else
                {
                    Console.WriteLine("starting decryption process");
                }

                using (BinaryReader br = new BinaryReader(new FileStream(fileName, FileMode.Open)))
                {
                    using (BinaryWriter bw = new BinaryWriter(new FileStream(fileNameOut, FileMode.OpenOrCreate)))
                    {
                        UInt32[,] security_sectors = readSS(rom_xml.Attributes["ssrange"].Value);

                        uint a_t = 0;
                        uint b_t = 0;
                        uint c_t = 0;

                        Seed(seed, ref a_t, ref b_t, ref c_t);

                        byte[] randomSector = new byte[2048];
                        BinaryWriter rs = new BinaryWriter(new MemoryStream(randomSector));

                        for (int j = 0; j < 0x800; j += 2)
                        {
                            UInt16 sample = (UInt16)(Value(ref a_t, ref b_t, ref c_t) >> 8);
                            rs.Write(sample);
                        }

                        while (br.BaseStream.Position != br.BaseStream.Length)
                        {
                            Int64 sector_n = br.BaseStream.Position / 2048;

                            byte[] tempBuffer = br.ReadBytes(2048);

                            bool equal = (decrypted) ? CompareArrays(tempBuffer, junk) : CompareArrays(tempBuffer, randomSector);

                            if (equal)
                            {
                                if (decrypted)
                                {
                                    hash.TransformBlock(randomSector, 0, 2048, null, 0);
                                    bw.Write(randomSector);
                                }
                                else
                                {
                                    bw.Write(junk);
                                }

                                rs.BaseStream.Position = 0;
                                for (int j = 0; j < 0x800; j += 2)
                                {
                                    UInt16 sample = (UInt16)(Value(ref a_t, ref b_t, ref c_t) >> 8);
                                    rs.Write(sample);
                                }
                            }
                            else
                            {
                                bool sec = checkSecRange(sector_n, security_sectors);

                                if (sec)
                                {
                                    hash.TransformBlock(tempBuffer, 0, 2048, null, 0);

                                    bw.Write(tempBuffer);

                                    rs.BaseStream.Position = 0;
                                    for (int j = 0; j < 0x800; j += 2)
                                    {
                                        UInt16 sample = (UInt16)(Value(ref a_t, ref b_t, ref c_t) >> 8);
                                        rs.Write(sample);
                                    }
                                }
                                else
                                {
                                    hash.TransformBlock(tempBuffer, 0, 2048, null, 0);
                                    bw.Write(tempBuffer);
                                }
                            }
                        }
                    }
                }

                hash.TransformFinalBlock(new byte[0], 0, 0);

                string file_md5 = BitConverter.ToString(hash.Hash).Replace("-", "").ToLower();

                if (decrypted)
                {
                    if (rom_md5 == file_md5)
                    {
                        Console.WriteLine("md5 matched: {0}", file_md5);
                    }
                }
                
            }

            Console.WriteLine("press any key to quit");
            Console.ReadKey(false);
        }

        private static bool checkSecRange(long sector_n, uint[,] security_sectors)
        {
            for (int i = 0; i < 16; i++)
            {
                if (security_sectors[i, 0] <= sector_n && sector_n <= security_sectors[i, 1]) return true;
            }

            return false;
        }

        private static byte[] newRandomSector(ref uint a_t, ref uint b_t, ref uint c_t)
        {
            throw new NotImplementedException();
        }

        private static uint[,] readSS(string ssRange)
        {
            uint[,] temp = new uint[16, 2];

            string[] ss = Regex.Split(ssRange, ",");

            for (int i = 0; i < 16; i++)
            {
                temp[i, 0] = Convert.ToUInt32(Regex.Split(ss[i], ":")[0]);
                temp[i, 1] = Convert.ToUInt32(Regex.Split(ss[i], ":")[1]);
            }

            return temp;
        }

        private static uint bruteForceSeed(string testFile)
        {
            BinaryReader br = new BinaryReader(new FileStream(testFile, FileMode.Open));
            br.BaseStream.Position = 0x18300000;
            byte[] sector = br.ReadBytes(2048);
            br.Close();

            string hash = BitConverter.ToString(MD5.Create().ComputeHash(sector)).Replace("-", "").ToLower();
            string filename = Path.GetFileName(testFile);

            Console.WriteLine(string.Format("ISO file: {0}", filename));
            Console.WriteLine(string.Format("1st random sector md5 hash: {0}", hash));

            var t1 = DateTime.Now;

            UInt32 seed = 0;

            Parallel.For(0x00000000, 0xffffffff, (i, state) =>
            {
                uint a_t = 0;
                uint b_t = 0;
                uint c_t = 0;

                Seed((uint)i, ref a_t, ref b_t, ref c_t);
                bool found = true;

                for (int j = 0; j < 0x800; j += 2)
                {
                    UInt16 sampleGenerated = (UInt16)(Value(ref a_t, ref b_t, ref c_t) >> 8);
                    byte low = (byte)(sampleGenerated & 0xff);
                    byte high = (byte)((sampleGenerated >> 8) & 0xff);

                    if ((sector[0 + j] != low) && (sector[1 + j] != high))
                    {
                        found = false;
                        break;
                    }
                }

                if (found)
                {
                    Console.WriteLine("Seed found: 0x{0:x8}", i);
                    Console.WriteLine("Time elapsed: {0}", DateTime.Now - t1);

                    //File.AppendAllLines(Path.Combine(Directory.GetCurrentDirectory(), "xbox_rnd_seeds.txt"), new string[] { string.Format("{0:x8},{1},{2}", i, hash.ToLower(), filename) });

                    seed = (UInt32)i;

                    state.Stop();
                }
            });

            return seed;
        }

        private static void Seed(uint seed, ref uint a_t, ref uint b_t, ref uint c_t)
        {
            a_t = 0;
            b_t = b_seeds[seed & 7];
            c_t = seed;
            a_t = Value(ref a_t, ref b_t, ref c_t);
        }

        private static uint Value(ref uint a_t, ref uint b_t, ref uint c_t)
        {
            UInt64 result;
            result = c_t;
            result += 1;
            result *= b_t;
            result %= 0xFFFFFFFB;
            c_t = (UInt32)(result & 0xFFFFFFFF);
            return c_t ^ a_t;
        }
        private static bool mode(string fileName, byte[] junk)
        {
            byte[] buffer = new byte[2048];
            using (BinaryReader br = new BinaryReader(new FileStream(fileName, FileMode.Open)))
            {
                br.BaseStream.Position = 0x18300000;
                buffer = br.ReadBytes(2048);
            }

            return CompareArrays(junk, buffer);
        }

        private static bool CompareArrays(byte[] buffer, byte[] randomSector)
        {
            for (int i = 0; i < 2048; i++)
            {
                if (buffer[i] != randomSector[i]) return false;
            }
            return true;
        }

        private static byte[] JunkBlock()
        {
            byte[] junkBuffer = new byte[2048];

            byte[] junkChain = Encoding.ASCII.GetBytes("JUNK");

            for (int i = 0; i < 512; i++)
            {
                junkChain.CopyTo(junkBuffer, i * 4);
            }

            return junkBuffer;
        }
    }
}
