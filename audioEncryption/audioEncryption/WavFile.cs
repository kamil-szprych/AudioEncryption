using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace AudioEncryption
{
    enum WavFileState : byte { Empty, Loaded, Encrypted, Decrypted };

    class WavFile
    {
        //Auxiliary variables used in program, not contained in wav file:
        public string FileName { get; private set; }
        //public int NumberOfMetadataProperties { get; } = 14;
        public WavFileState Status { get; private set; } = WavFileState.Empty;

        //Wav file raw audio data, accesed by property:
        private byte[] data;

        //Wav file metadata properties:
        public byte[] ChunkID { get; set; }
        public int ChunkSize { get; set; }
        public byte[] Format { get; set; }
        public byte[] Subchunk1ID { get; set; }
        public int Subchunk1Size { get; set; }
        public short AudioFormat { get; set; }
        public short NumChannels { get; set; }
        public int SampleRate { get; set; }
        public int ByteRate { get; set; }
        public short BlockAlign { get; set; }
        public short BitsPerSample { get; set; }
        public byte[] Subchunk2ID { get; set; }
        public int Subchunk2Size { get; set; }
        public byte[] Data
        {
            get
            {
                return data;
            }
            set
            {
                data = value;
            }
        }

        

        public object[] GetObjectArray()
        {
            return new object[] {ChunkID, ChunkSize, Format, Subchunk1ID, Subchunk1Size,
                AudioFormat, NumChannels, SampleRate, ByteRate, BlockAlign,
            BitsPerSample, Subchunk2ID, Subchunk2Size, Data};
        }

        /// <summary>
        /// Loads data from wav file and sets all Properties. Returns true if successful and false if failed.
        /// </summary>
        /// <param name="wavFilePath"></param>
        /// <returns>true - successfully loaded data, false - failed to load file</returns>
        public bool LoadDataFromFile(string wavFilePath)
        {
            if (File.Exists(wavFilePath))
            {
                using (var reader = new BinaryReader(File.OpenRead(wavFilePath)))
                {
                    ChunkID = reader.ReadBytes(4);
                    ChunkSize = reader.ReadInt32();
                    Format = reader.ReadBytes(4);
                    Subchunk1ID = reader.ReadBytes(4);
                    Subchunk1Size = reader.ReadInt32();
                    AudioFormat = reader.ReadInt16();
                    NumChannels = reader.ReadInt16();
                    SampleRate = reader.ReadInt32();
                    ByteRate = reader.ReadInt32();
                    BlockAlign = reader.ReadInt16();
                    BitsPerSample = reader.ReadInt16();
                    Subchunk2ID = reader.ReadBytes(4);
                    Subchunk2Size = reader.ReadInt32();
                    Data = reader.ReadBytes((int)reader.BaseStream.Length - 44);
                }
                FileName = Path.GetFileName(wavFilePath);
                Status = WavFileState.Loaded;
                return true;
            }
            else
            {
                return false;
            }
        }

        /// <summary>
        /// Saves this file to wav file.
        /// </summary>
        /// <param name="fileName">File name or path with file name to save to. Creates new file if doesnt exist.</param>
        public void SaveToWavFile(string fileName)
        {
            using (var writer = new BinaryWriter(File.Open(fileName, FileMode.OpenOrCreate)))
            {
                writer.Write(ChunkID);
                writer.Write(ChunkSize);
                writer.Write(Format);
                writer.Write(Subchunk1ID);
                writer.Write(Subchunk1Size);
                writer.Write(AudioFormat);
                writer.Write(NumChannels);
                writer.Write(SampleRate);
                writer.Write(ByteRate);
                writer.Write(BlockAlign);
                writer.Write(BitsPerSample);
                writer.Write(Subchunk2ID);
                writer.Write(Subchunk2Size);
                writer.Write(Data);
            }
        }

        /// <summary>
        /// Returns multiline string with wav file metadata.
        /// </summary>
        /// <returns></returns>
        public string GetMetadataString()
        {
            var sw = new System.IO.StringWriter();

            sw.WriteLine("Nazwa pliku: " + FileName);
            sw.WriteLine("Czas trwania: " + Subchunk2Size / ByteRate + "s");
            sw.WriteLine();
            sw.WriteLine("---- METADATA ----");
            sw.WriteLine("Chunkid: " + System.Text.Encoding.UTF8.GetString(ChunkID));
            sw.WriteLine("Rozmiar: " + ChunkSize.ToString());
            sw.WriteLine("Format: " + System.Text.Encoding.UTF8.GetString(Format));
            sw.WriteLine("Subchunk1 ID: " + System.Text.Encoding.UTF8.GetString(Subchunk1ID));
            sw.WriteLine("Subchunk1 rozmiar: " + Subchunk1Size.ToString());
            sw.WriteLine("Audio format: " + AudioFormat.ToString());
            sw.WriteLine("Kanaly: " + NumChannels.ToString());
            sw.WriteLine("Sample rate: " + SampleRate.ToString());
            sw.WriteLine("Byte rate: " + ByteRate.ToString());
            sw.WriteLine("Block align: " + BlockAlign.ToString());
            sw.WriteLine("Bits per sample: " + BitsPerSample.ToString());
            sw.WriteLine("Subchunk2 ID: " + System.Text.Encoding.UTF8.GetString(Subchunk2ID));
            sw.WriteLine("Subchunk2 rozmiar: " + Subchunk2Size.ToString());

            return sw.ToString();
        }

        /// <summary>
        /// Encrypts wav data using public key set in RsaManager static class. Returns true if successful otherwise false.
        /// </summary>
        /// <returns></returns>
        public bool Encrypt()
        {
            if (Status == WavFileState.Encrypted || Status == WavFileState.Empty)
                return false;

            using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
            {
                var encryptor = aes.CreateEncryptor();
                Data = encryptor.TransformFinalBlock(Data, 0, Data.Length);

                byte[] mergedKeyAndIV = new byte[aes.Key.Length + aes.IV.Length];
                Array.Copy(aes.Key, mergedKeyAndIV, aes.Key.Length);
                Array.Copy(aes.IV, 0, mergedKeyAndIV, aes.Key.Length, aes.IV.Length);

                var encryptedKeyAndIV = RsaManager.Encrypt(mergedKeyAndIV);

                if (encryptedKeyAndIV == null)
                    return false;

                var oldLength = data.Length;
                Array.Resize(ref data, oldLength + encryptedKeyAndIV.Length);
                Array.Copy(encryptedKeyAndIV, 0, data, oldLength, encryptedKeyAndIV.Length);
            }
            Status = WavFileState.Encrypted;
            return true;
        }

        /// <summary>
        /// Decrypts wav data using private key set in RsaManager static class. Returns true if successful otherwise false.
        /// </summary>
        /// <returns></returns>
        public bool Decrypt()
        {
            if (Status == WavFileState.Decrypted || Status == WavFileState.Empty)
                return false;

            using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
            {
                var encryptedKeyAndIV = data.Skip(data.Length - 256).ToArray();
                var mergedKeyAndIV = RsaManager.Decrypt(encryptedKeyAndIV);

                if (mergedKeyAndIV == null)
                    return false;

                aes.Key = mergedKeyAndIV.Take(32).ToArray();
                aes.IV = mergedKeyAndIV.Skip(32).ToArray();

                var decryptor = aes.CreateDecryptor();

                data = data.Take(data.Length - 256).ToArray();
                data = decryptor.TransformFinalBlock(data, 0, data.Length);
            }
            Status = WavFileState.Decrypted;
            return true;
        }
    }
}
