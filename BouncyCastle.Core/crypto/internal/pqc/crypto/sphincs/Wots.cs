namespace Org.BouncyCastle.Crypto.Internal.Pqc.Crypto.Sphincs
{
    internal class Wots
    {
        internal static readonly int HASH_BYTES = 32; // Has to be log(HORST_T)*HORST_K/8

        internal static readonly int WOTS_LOGW = 4;

        internal static readonly int WOTS_W = (1 << WOTS_LOGW);
        internal static readonly int WOTS_L1 = ((256 + WOTS_LOGW - 1) / WOTS_LOGW);
        //#define WOTS_L 133  // for WOTS_W == 4
        //#define WOTS_L 90  // for WOTS_W == 8
        internal static readonly int WOTS_L = 67;  // for WOTS_W == 16
        internal static readonly int WOTS_LOG_L = 7; // for WOTS_W == 16
        internal static readonly int WOTS_SIGBYTES = (WOTS_L * HASH_BYTES);

        internal static void expand_seed(byte[] outseeds, int outOff, byte[] inseed, int inOff)
        {
            clear(outseeds, outOff, WOTS_L * HASH_BYTES);

            Seed.prg(outseeds, outOff, WOTS_L * HASH_BYTES, inseed, inOff);
        }

        private static void clear(byte[] bytes, int offSet, int length)
        {
            for (int i = 0; i != length; i++)
            {
                bytes[i + offSet] = 0;
            }
        }

        internal static void gen_chain(HashFunctions hs, byte[] output, int outOff, byte[] seed, int seedOff, byte[] masks, int masksOff, int chainlen)
        {
            int i, j;
            for (j = 0; j < HASH_BYTES; j++)
            output[j + outOff] = seed[j + seedOff];

        for (i = 0; i<chainlen && i<WOTS_W; i++)
            hs.hash_n_n_mask(output, outOff, output, outOff, masks, masksOff + (i* HASH_BYTES));
    }


    internal void wots_pkgen(HashFunctions hs, byte[] pk, int pkOff, byte[] sk, int skOff, byte[] masks, int masksOff)
    {
        int i;
        expand_seed(pk, pkOff, sk, skOff);
        for (i = 0; i < WOTS_L; i++)
            gen_chain(hs, pk, pkOff + i * HASH_BYTES, pk, pkOff + i * HASH_BYTES, masks, masksOff, WOTS_W - 1);
    }


    internal void wots_sign(HashFunctions hs, byte[] sig, int sigOff, byte[] msg, byte[] sk, byte[] masks)
    {
        int[] basew = new int[WOTS_L];
            int i;
            uint c = 0;

        for (i = 0; i < WOTS_L1; i += 2)
        {
            basew[i] = msg[i / 2] & 0xf;
            basew[i + 1] = (msg[i / 2] & 0xff) >> 4;
            c += (uint)(WOTS_W - 1 - basew[i]);
            c += (uint)(WOTS_W - 1 - basew[i + 1]);
        }

        for (; i < WOTS_L; i++)
        {
            basew[i] = (int)(c & 0xf);
            c >>= 4;
        }

        expand_seed(sig, sigOff, sk, 0);

        for (i = 0; i < WOTS_L; i++)
            gen_chain(hs, sig, sigOff + i * HASH_BYTES, sig, sigOff + i * HASH_BYTES, masks, 0, basew[i]);
    }

    internal void wots_verify(HashFunctions hs, byte[] pk, byte[] sig, int sigOff, byte[] msg, byte[] masks)
    {
        int[] basew = new int[WOTS_L];
        int i, c = 0;

        for (i = 0; i < WOTS_L1; i += 2)
        {
            basew[i] = msg[i / 2] & 0xf;
            basew[i + 1] = (msg[i / 2] & 0xff) >> 4;
            c += WOTS_W - 1 - basew[i];
            c += WOTS_W - 1 - basew[i + 1];
        }

        for (; i < WOTS_L; i++)
        {
            basew[i] = c & 0xf;
            c >>= 4;
        }

        for (i = 0; i < WOTS_L; i++)
            gen_chain(hs, pk, i * HASH_BYTES, sig, sigOff + i * HASH_BYTES, masks, (basew[i] * HASH_BYTES), WOTS_W - 1 - basew[i]);
    }
}
}
