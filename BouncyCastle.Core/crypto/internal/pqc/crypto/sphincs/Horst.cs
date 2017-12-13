using System;

namespace Org.BouncyCastle.Crypto.Internal.Pqc.Crypto.Sphincs
{
    class Horst
    {
        internal static readonly int HASH_BYTES = 32; // Has to be log(HORST_T)*HORST_K/8
        internal static readonly int HORST_LOGT = 16;
        internal static readonly int HORST_T = (1 << HORST_LOGT);
        internal static readonly int HORST_K = 32;
        internal static readonly int HORST_SKBYTES = 32;
        internal static readonly int HORST_SIGBYTES = (64 * HASH_BYTES + (((HORST_LOGT - 6) * HASH_BYTES) + HORST_SKBYTES) * HORST_K);

        internal static readonly int N_MASKS = (2 * (HORST_LOGT)); /* has to be the max of  (2*(SUBTREE_HEIGHT+WOTS_LOGL)) and (WOTS_W-1) and 2*HORST_LOGT */

        static void expand_seed(byte[] outseeds, byte[] inseed)
        {
            Seed.prg(outseeds, 0, HORST_T * HORST_SKBYTES, inseed, 0);
        }

        internal static int horst_sign(HashFunctions hs,
                              byte[] sig, int sigOff, byte[] pk, 
                       byte[] seed,
                       byte[] masks,
                       byte[] m_hash)
        {
            byte[] sk = new byte[HORST_T * HORST_SKBYTES];
            uint idx;
            int i, j, k;
            int sigpos = sigOff;

            byte[] tree = new byte[(2 * HORST_T - 1) * HASH_BYTES]; /* replace by something more memory-efficient? */

            expand_seed(sk, seed);

            // Build the whole tree and save it

            // Generate pk leaves
            for (i = 0; i < HORST_T; i++)
                hs.hash_n_n(tree, (HORST_T - 1 + i) * HASH_BYTES, sk, i * HORST_SKBYTES);

            long offset_in, offset_out;
            for (i = 0; i < HORST_LOGT; i++)
            {
                offset_in = (1 << (HORST_LOGT - i)) - 1;
                offset_out = (1 << (HORST_LOGT - i - 1)) - 1;
                for (j = 0; j < (1 << (HORST_LOGT - i - 1)); j++)
                    hs.hash_2n_n_mask(tree, (int)((offset_out + j) * HASH_BYTES), tree, (int)((offset_in + 2 * j) * HASH_BYTES), masks, 2 * i * HASH_BYTES);
            }

            // First write 64 hashes from level 10 to the signature
            for (j = 63 * HASH_BYTES; j < 127 * HASH_BYTES; j++)
                sig[sigpos++] = tree[j];

            // Signature consists of HORST_K parts; each part of secret key and HORST_LOGT-4 auth-path hashes
            for (i = 0; i < HORST_K; i++)
            {
                idx = (uint)((m_hash[2 * i] & 0xff) + ((m_hash[2 * i + 1] & 0xff) << 8));

                for (k = 0; k < HORST_SKBYTES; k++)
                    sig[sigpos++] = sk[idx * HORST_SKBYTES + k];

                idx += (uint)(HORST_T - 1);
                for (j = 0; j < HORST_LOGT - 6; j++)
                {
                    idx = ((idx & 1) != 0) ? idx + 1 : idx - 1; // neighbor node
                    for (k = 0; k < HASH_BYTES; k++)
                        sig[sigpos++] = tree[idx * HASH_BYTES + k];
                    idx = (idx - 1) / 2; // parent node
                }
            }

            for (i = 0; i < HASH_BYTES; i++)
                pk[i] = tree[i];

            return HORST_SIGBYTES;
        }

        internal static int horst_verify(HashFunctions hs, byte[] pk, byte[] sig, int sigOff, byte[] masks, byte[] m_hash)
        {
            byte[] buffer = new byte[32 * HASH_BYTES];

            uint idx;
            int i, j, k;

            int sigOffset = sigOff + 64 * HASH_BYTES;

            for (i = 0; i < HORST_K; i++)
            {
                idx = (uint)((m_hash[2 * i] & 0xff) + ((m_hash[2 * i + 1] & 0xff) << 8));

                if ((idx & 1) == 0)
                {
                    hs.hash_n_n(buffer, 0, sig, sigOffset);
                    for (k = 0; k < HASH_BYTES; k++)
                        buffer[HASH_BYTES + k] = sig[sigOffset + HORST_SKBYTES + k];
                }
                else
                {
                    hs.hash_n_n(buffer, HASH_BYTES, sig, sigOffset);
                    for (k = 0; k < HASH_BYTES; k++)
                        buffer[k] = sig[sigOffset + HORST_SKBYTES + k];
                }
                sigOffset += HORST_SKBYTES + HASH_BYTES;

                for (j = 1; j < HORST_LOGT - 6; j++)
                {
                    idx = idx >> 1; // parent node

                    if ((idx & 1) == 0)
                    {
                        hs.hash_2n_n_mask(buffer, 0, buffer, 0, masks, 2 * (j - 1) * HASH_BYTES);
                        for (k = 0; k < HASH_BYTES; k++)
                            buffer[HASH_BYTES + k] = sig[sigOffset + k];
                    }
                    else
                    {

                        hs.hash_2n_n_mask(buffer, HASH_BYTES, buffer, 0, masks, 2 * (j - 1) * HASH_BYTES);
                        for (k = 0; k < HASH_BYTES; k++)
                            buffer[k] = sig[sigOffset + k];
                    }
                    sigOffset += HASH_BYTES;
                }

                idx = idx >> 1; // parent node
                hs.hash_2n_n_mask(buffer, 0, buffer, 0, masks, 2 * (HORST_LOGT - 7) * HASH_BYTES);

                for (k = 0; k < HASH_BYTES; k++)
                    if (sig[sigOff + idx * HASH_BYTES + k] != buffer[k])
                    {
                        for (k = 0; k < HASH_BYTES; k++)
                            pk[k] = 0;
                        return -1;
                    }
            }

            // Compute root from level10
            for (j = 0; j < 32; j++)
                hs.hash_2n_n_mask(buffer, j * HASH_BYTES, sig, sigOff + 2 * j * HASH_BYTES, masks, 2 * (HORST_LOGT - 6) * HASH_BYTES);
            // Hash from level 11 to 12
            for (j = 0; j < 16; j++)
                hs.hash_2n_n_mask(buffer, j * HASH_BYTES, buffer, 2 * j * HASH_BYTES, masks, 2 * (HORST_LOGT - 5) * HASH_BYTES);
            // Hash from level 12 to 13
            for (j = 0; j < 8; j++)
                hs.hash_2n_n_mask(buffer, j * HASH_BYTES, buffer, 2 * j * HASH_BYTES, masks, 2 * (HORST_LOGT - 4) * HASH_BYTES);
            // Hash from level 13 to 14
            for (j = 0; j < 4; j++)
                hs.hash_2n_n_mask(buffer, j * HASH_BYTES, buffer, 2 * j * HASH_BYTES, masks, 2 * (HORST_LOGT - 3) * HASH_BYTES);
            // Hash from level 14 to 15
            for (j = 0; j < 2; j++)
                hs.hash_2n_n_mask(buffer, j * HASH_BYTES, buffer, 2 * j * HASH_BYTES, masks, 2 * (HORST_LOGT - 2) * HASH_BYTES);
            // Hash from level 15 to 16

            hs.hash_2n_n_mask(pk, 0, buffer, 0, masks, 2 * (HORST_LOGT - 1) * HASH_BYTES);

            return 0;
        }
    }
}

