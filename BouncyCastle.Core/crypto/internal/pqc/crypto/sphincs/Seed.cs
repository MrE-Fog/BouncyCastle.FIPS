using Org.BouncyCastle.Crypto.Internal.Engines;
using Org.BouncyCastle.Crypto.Internal.Parameters;
using Org.BouncyCastle.Crypto.Utilities;

namespace Org.BouncyCastle.Crypto.Internal.Pqc.Crypto.Sphincs
{
    internal class Seed
    {

        internal static void get_seed(HashFunctions hs, byte[] seed, int seedOff, byte[] sk, Tree.leafaddr a)
        {
            byte[] buffer = new byte[SPHINCS256Config.SEED_BYTES + 8];
            ulong t;
            int i;

            for (i = 0; i < SPHINCS256Config.SEED_BYTES; i++)
            {
                buffer[i] = sk[i];
            }

            //4 bits to encode level
            t = (uint)a.level;
            //55 bits to encode subtree
            t |= a.subtree << 4;
            //5 bits to encode leaf
            t |= a.subleaf << 59;

            Pack.UInt64_To_LE(t, buffer, SPHINCS256Config.SEED_BYTES);

            hs.varlen_hash(seed, seedOff, buffer, buffer.Length);
        }



        internal static void prg(byte[] r, int rOff, long rlen, byte[] key, int keyOff)
        {
            byte[] nonce = new byte[8];

            IStreamCipher cipher = new ChaChaEngine(12);

            cipher.Init(true, new KeyParameter(key, keyOff, 32));
            cipher.Init(true, new ParametersWithIV(null, nonce));

            cipher.ProcessBytes(r, rOff, (int)rlen, r, rOff);

            //crypto_stream_chacha12(r, rlen, nonce, key);
        }
    }
}
