using Org.BouncyCastle.Crypto.Internal.Modes;
using Org.BouncyCastle.Crypto.Internal.Parameters;
using System;

namespace Org.BouncyCastle.Crypto.Internal.Macs
{

    internal class AeadCipherMac : IMac
    {
        private readonly IAeadBlockCipher aeadCipher;
        private readonly int macLenInBits;

        public AeadCipherMac(IAeadBlockCipher aeadCipher, int macLenInBits)
        {
            this.aeadCipher = aeadCipher;
            this.macLenInBits = macLenInBits;
        }

        public void Init(ICipherParameters parameters)
        {
            if (parameters is ParametersWithIV)
            {
                ParametersWithIV p = (ParametersWithIV)parameters;

                aeadCipher.Init(true, new AeadParameters((KeyParameter)p.Parameters, macLenInBits, p.GetIV()));
            }
            else
            {
                throw new ArgumentException("AEAD cipher based MAC needs nonce/IV");
            }
        }

        public string AlgorithmName
        {
            get
            {
                return aeadCipher.AlgorithmName + "MAC";
            }
        }

        public int GetMacSize()
        {
            return (macLenInBits + 7) / 8;
        }

        public void Update(byte input)
        {
            aeadCipher.ProcessAadByte(input);
        }

        public void BlockUpdate(byte[] input, int inOff, int len)
        {
            aeadCipher.ProcessAadBytes(input, inOff, len);
        }

        public int DoFinal(byte[] output, int outOff)
        {
            try
            {
                return aeadCipher.DoFinal(output, outOff);
            }
            catch (InvalidCipherTextException e)
            {
                throw new InvalidOperationException("unable to create MAC tag:" + e.Message, e);
            }
        }

        public void Reset()
        {
            aeadCipher.Reset();
        }
    }
}
