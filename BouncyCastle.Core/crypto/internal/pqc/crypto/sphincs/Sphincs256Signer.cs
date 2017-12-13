using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using System;

namespace Org.BouncyCastle.Crypto.Internal.Pqc.Crypto.Sphincs
{
    /**
     * SPHINCS-256 signer.
     * <p>
     * This implementation is heavily based on the reference implementation in SUPERCOP, the main difference being the digests used
     * for message hashing and tree construction are now configurable (within limits...)
     * </p>
     */
    internal class Sphincs256Signer: IMessageSigner
{
        internal static readonly int CRYPTO_BYTES = (SPHINCS256Config.MESSAGE_HASH_SEED_BYTES + (SPHINCS256Config.TOTALTREE_HEIGHT + 7) / 8 + Horst.HORST_SIGBYTES + (SPHINCS256Config.TOTALTREE_HEIGHT / SPHINCS256Config.SUBTREE_HEIGHT) * Wots.WOTS_SIGBYTES + SPHINCS256Config.TOTALTREE_HEIGHT * SPHINCS256Config.HASH_BYTES);

        private readonly HashFunctions hashFunctions;

    private byte[] keyData;

    /**
     * Base constructor.
     *
     * @param nDigest  the "n-digest" must produce 32 bytes of output - used for tree construction.
     * @param twoNDigest the "2n-digest" must produce 64 bytes of output - used for initial message/key/seed hashing.
     */
    public Sphincs256Signer(IDigest nDigest, IDigest twoNDigest)
    {
        if (nDigest.GetDigestSize() != 32)
        {
            throw new ArgumentException("n-digest needs to produce 32 bytes of output");
        }
        if (twoNDigest.GetDigestSize() != 64)
        {
            throw new ArgumentException("2n-digest needs to produce 64 bytes of output");
        }

        this.hashFunctions = new HashFunctions(nDigest, twoNDigest);
    }

    public void Init(bool forSigning, ICipherParameters param)
    {
         if (forSigning)
         {
             keyData = ((SphincsPrivateKeyParameters)param).GetKeyData();
         }
         else
         {
             keyData = ((SphincsPublicKeyParameters)param).GetKeyData();
         }
    }

    public byte[] GenerateSignature(byte[] message)
    {
        return crypto_sign(hashFunctions, message, keyData);
    }

    public bool VerifySignature(byte[] message, byte[] signature)
    {
        return verify(hashFunctions, message, signature, keyData);
    }

    static void validate_authpath(HashFunctions hs, byte[] root, byte[] leaf, uint leafidx, byte[] authpath, int auOff, byte[] masks, int height)
    {
        int i, j;
        byte[] buffer = new byte[2 * SPHINCS256Config.HASH_BYTES];

        if ((leafidx & 1) != 0)
        {
            for (j = 0; j < SPHINCS256Config.HASH_BYTES; j++)
            {
                buffer[SPHINCS256Config.HASH_BYTES + j] = leaf[j];
            }
            for (j = 0; j < SPHINCS256Config.HASH_BYTES; j++)
            {
                buffer[j] = authpath[auOff + j];
            }
        }
        else
        {
            for (j = 0; j < SPHINCS256Config.HASH_BYTES; j++)
            {
                buffer[j] = leaf[j];
            }
            for (j = 0; j < SPHINCS256Config.HASH_BYTES; j++)
            {
                buffer[SPHINCS256Config.HASH_BYTES + j] = authpath[auOff + j];
            }
        }
        int authOff = auOff + SPHINCS256Config.HASH_BYTES;

        for (i = 0; i < height - 1; i++)
        {
            leafidx >>= 1;
            if ((leafidx & 1) != 0)
            {
                hs.hash_2n_n_mask(buffer, SPHINCS256Config.HASH_BYTES, buffer, 0, masks, 2 * (Wots.WOTS_LOG_L + i) * SPHINCS256Config.HASH_BYTES);
                for (j = 0; j < SPHINCS256Config.HASH_BYTES; j++)
                {
                    buffer[j] = authpath[authOff + j];
                }
            }
            else
            {
                hs.hash_2n_n_mask(buffer, 0, buffer, 0, masks, 2 * (Wots.WOTS_LOG_L + i) * SPHINCS256Config.HASH_BYTES);
                for (j = 0; j < SPHINCS256Config.HASH_BYTES; j++)
                {
                    buffer[j + SPHINCS256Config.HASH_BYTES] = authpath[authOff + j];
                }
            }
            authOff += SPHINCS256Config.HASH_BYTES;
        }
        hs.hash_2n_n_mask(root, 0, buffer, 0, masks, 2 * (Wots.WOTS_LOG_L + height - 1) * SPHINCS256Config.HASH_BYTES);
    }


    static void compute_authpath_wots(HashFunctions hs, byte[] root, byte[] authpath, int authOff, Tree.leafaddr a, byte[] sk, byte[] masks, int height)
    {
            int i, j;
            uint idx;
        Tree.leafaddr ta = new Tree.leafaddr(a);

        byte[] tree = new byte[2 * (1 << SPHINCS256Config.SUBTREE_HEIGHT) * SPHINCS256Config.HASH_BYTES];
        byte[] seed = new byte[(1 << SPHINCS256Config.SUBTREE_HEIGHT) * SPHINCS256Config.SEED_BYTES];
        byte[] pk = new byte[(1 << SPHINCS256Config.SUBTREE_HEIGHT) * Wots.WOTS_L * SPHINCS256Config.HASH_BYTES];

        // level 0
        for (ta.subleaf = 0; ta.subleaf < (1UL << SPHINCS256Config.SUBTREE_HEIGHT); ta.subleaf++)
        {
            Seed.get_seed(hs, seed, (int)(ta.subleaf * (ulong)SPHINCS256Config.SEED_BYTES), sk, ta);
        }

        Wots w = new Wots();

        for (ta.subleaf = 0; ta.subleaf < (1UL << SPHINCS256Config.SUBTREE_HEIGHT); ta.subleaf++)
        {
            w.wots_pkgen(hs, pk, (int)(ta.subleaf * (ulong)Wots.WOTS_L * (ulong)SPHINCS256Config.HASH_BYTES), seed, (int)(ta.subleaf * (ulong)SPHINCS256Config.SEED_BYTES), masks, 0);
        }

        for (ta.subleaf = 0; ta.subleaf < (1UL << SPHINCS256Config.SUBTREE_HEIGHT); ta.subleaf++)
        {
            Tree.l_tree(hs, tree, (int)((1UL << SPHINCS256Config.SUBTREE_HEIGHT) * (ulong)SPHINCS256Config.HASH_BYTES + ta.subleaf * (ulong)SPHINCS256Config.HASH_BYTES),
                pk, (int)(ta.subleaf * (ulong)Wots.WOTS_L * (ulong)SPHINCS256Config.HASH_BYTES), masks, 0);
        }

        int level = 0;

        // tree
        for (i = (1 << SPHINCS256Config.SUBTREE_HEIGHT); i > 0; i >>= 1)
        {
            for (j = 0; j < i; j += 2)
            {
                hs.hash_2n_n_mask(tree, (i >> 1) * SPHINCS256Config.HASH_BYTES + (j >> 1) * SPHINCS256Config.HASH_BYTES,
                    tree, i * SPHINCS256Config.HASH_BYTES + j * SPHINCS256Config.HASH_BYTES,
                    masks, 2 * (Wots.WOTS_LOG_L + level) * SPHINCS256Config.HASH_BYTES);
            }

            level++;
        }


        idx = (uint)a.subleaf;

        // copy authpath
        for (i = 0; i < height; i++)
        {
            Array.Copy(tree, ((1 << SPHINCS256Config.SUBTREE_HEIGHT) >> i) * SPHINCS256Config.HASH_BYTES + ((idx >> i) ^ 1) * SPHINCS256Config.HASH_BYTES, authpath, authOff + i * SPHINCS256Config.HASH_BYTES, SPHINCS256Config.HASH_BYTES);
        }

        // copy root
        Array.Copy(tree, SPHINCS256Config.HASH_BYTES, root, 0,  SPHINCS256Config.HASH_BYTES);
    }

    byte[] crypto_sign(HashFunctions hs, byte[] m, byte[] sk)
    {
        byte[] sm = new byte[CRYPTO_BYTES];
        int i;
        ulong leafidx;
        byte[] R = new byte[SPHINCS256Config.MESSAGE_HASH_SEED_BYTES];
        byte[] m_h = new byte[SPHINCS256Config.MSGHASH_BYTES];
        ulong[] rnd = new ulong[8];

        byte[] root = new byte[SPHINCS256Config.HASH_BYTES];
        byte[] seed = new byte[SPHINCS256Config.SEED_BYTES];
        byte[] masks = new byte[Horst.N_MASKS * SPHINCS256Config.HASH_BYTES];
        int pk;
        byte[] tsk = new byte[SPHINCS256Config.CRYPTO_SECRETKEYBYTES];

        for (i = 0; i < SPHINCS256Config.CRYPTO_SECRETKEYBYTES; i++)
        {
            tsk[i] = sk[i];
        }
       
        // create leafidx deterministically
        {
            // shift scratch upwards so we can reuse msg later
            int scratch = CRYPTO_BYTES - SPHINCS256Config.SK_RAND_SEED_BYTES;

            // Copy secret random seed to scratch
            Array.Copy(tsk, SPHINCS256Config.CRYPTO_SECRETKEYBYTES - SPHINCS256Config.SK_RAND_SEED_BYTES, sm, scratch, SPHINCS256Config.SK_RAND_SEED_BYTES);

            IDigest d = hs.getMessageHash();
            byte[] bRnd = new byte[d.GetDigestSize()];

            d.BlockUpdate(sm, scratch, SPHINCS256Config.SK_RAND_SEED_BYTES);

            d.BlockUpdate(m, 0, m.Length);

            d.DoFinal(bRnd, 0);
            // wipe sk
            zerobytes(sm, scratch, SPHINCS256Config.SK_RAND_SEED_BYTES);

            for (int j = 0; j != rnd.Length; j++)
            {
                rnd[j] = Pack.LE_To_UInt64(bRnd, j * 8);
            }
            leafidx = rnd[0] & 0xfffffffffffffffUL;
       
            Array.Copy(bRnd, 16, R, 0, SPHINCS256Config.MESSAGE_HASH_SEED_BYTES);

            // prepare msg_hash
            scratch = CRYPTO_BYTES - SPHINCS256Config.MESSAGE_HASH_SEED_BYTES - SPHINCS256Config.CRYPTO_PUBLICKEYBYTES;

            // cpy R
            Array.Copy(R, 0, sm, scratch, SPHINCS256Config.MESSAGE_HASH_SEED_BYTES);

            // construct and cpy pk
            Tree.leafaddr b = new Tree.leafaddr();
            b.level = SPHINCS256Config.N_LEVELS - 1;
            b.subtree = 0;
            b.subleaf = 0;

            pk = scratch + SPHINCS256Config.MESSAGE_HASH_SEED_BYTES;

                Array.Copy(tsk, SPHINCS256Config.SEED_BYTES, sm, pk, Horst.N_MASKS * SPHINCS256Config.HASH_BYTES);

            Tree.treehash(hs, sm, pk + (Horst.N_MASKS * SPHINCS256Config.HASH_BYTES), SPHINCS256Config.SUBTREE_HEIGHT, tsk, b, sm, pk);

            d = hs.getMessageHash();

            d.BlockUpdate(sm, scratch, SPHINCS256Config.MESSAGE_HASH_SEED_BYTES + SPHINCS256Config.CRYPTO_PUBLICKEYBYTES);
            d.BlockUpdate(m, 0, m.Length);
            d.DoFinal(m_h, 0);
        }

        Tree.leafaddr a = new Tree.leafaddr();

        a.level = SPHINCS256Config.N_LEVELS; // Use unique value $d$ for HORST address.
        a.subleaf = (leafidx & (1UL << SPHINCS256Config.SUBTREE_HEIGHT) - 1);
        a.subtree = (leafidx >> SPHINCS256Config.SUBTREE_HEIGHT);

        int smlen = 0;

        for (i = 0; i < SPHINCS256Config.MESSAGE_HASH_SEED_BYTES; i++)
        {
            sm[i] = R[i];
        }

        int smOff = SPHINCS256Config.MESSAGE_HASH_SEED_BYTES;
        smlen += SPHINCS256Config.MESSAGE_HASH_SEED_BYTES;

        Array.Copy(tsk, SPHINCS256Config.SEED_BYTES, masks, 0, Horst.N_MASKS * SPHINCS256Config.HASH_BYTES);
        for (i = 0; i < (SPHINCS256Config.TOTALTREE_HEIGHT + 7) / 8; i++)
        {
            sm[smOff + i] = (byte)((leafidx >> 8 * i) & 0xff);
        }

        smOff += (SPHINCS256Config.TOTALTREE_HEIGHT + 7) / 8;
        smlen += (SPHINCS256Config.TOTALTREE_HEIGHT + 7) / 8;

        Seed.get_seed(hs, seed, 0, tsk, a);

        int horst_sigbytes = Horst.horst_sign(hs, sm, smOff, root, seed, masks, m_h);

        smOff += horst_sigbytes;
        smlen += horst_sigbytes;

        Wots w = new Wots();

        for (i = 0; i < SPHINCS256Config.N_LEVELS; i++)
        {
            a.level = i;

            Seed.get_seed(hs, seed, 0, tsk, a); //XXX: Don't use the same address as for horst_sign here!

            w.wots_sign(hs, sm, smOff, root, seed, masks);

            smOff += Wots.WOTS_SIGBYTES;
            smlen += Wots.WOTS_SIGBYTES;

            compute_authpath_wots(hs, root, sm, smOff, a, tsk, masks, SPHINCS256Config.SUBTREE_HEIGHT);
            smOff += SPHINCS256Config.SUBTREE_HEIGHT * SPHINCS256Config.HASH_BYTES;
            smlen += SPHINCS256Config.SUBTREE_HEIGHT * SPHINCS256Config.HASH_BYTES;

            a.subleaf = (a.subtree & ((1UL << SPHINCS256Config.SUBTREE_HEIGHT) - 1));
            a.subtree >>= SPHINCS256Config.SUBTREE_HEIGHT;
        }

        zerobytes(tsk, 0, SPHINCS256Config.CRYPTO_SECRETKEYBYTES);

        return sm;
    }

    private void zerobytes(byte[] tsk, int off, int cryptoSecretkeybytes)
    {
        for (int i = 0; i != cryptoSecretkeybytes; i++)
        {
            tsk[off + i] = 0;
        }
    }

    bool verify(HashFunctions hs, byte[] m, byte[] sm, byte[] pk)
    {
        int i;
        int smlen = sm.Length;
        long leafidx = 0;
        byte[] wots_pk = new byte[ Wots.WOTS_L * SPHINCS256Config.HASH_BYTES];
        byte[] pkhash = new byte[ SPHINCS256Config.HASH_BYTES];
        byte[] root = new byte[ SPHINCS256Config.HASH_BYTES];
        byte[] sig = new byte[ CRYPTO_BYTES];
        int sigp;
        byte[] tpk = new byte[ SPHINCS256Config.CRYPTO_PUBLICKEYBYTES];

        if (smlen != CRYPTO_BYTES)
        {
            throw new ArgumentException("signature wrong size");
        }

        byte[] m_h = new byte[ SPHINCS256Config.MSGHASH_BYTES];

        for (i = 0; i < SPHINCS256Config.CRYPTO_PUBLICKEYBYTES; i++)
            tpk[i] = pk[i];

        // construct message hash
        {
            byte[] R = new byte[ SPHINCS256Config.MESSAGE_HASH_SEED_BYTES];

            for (i = 0; i < SPHINCS256Config.MESSAGE_HASH_SEED_BYTES; i++)
                R[i] = sm[i];

            Array.Copy(sm, 0, sig, 0, CRYPTO_BYTES);

            IDigest mHash = hs.getMessageHash();

            // input R
            mHash.BlockUpdate(R, 0, SPHINCS256Config.MESSAGE_HASH_SEED_BYTES);

            // input pub key
            mHash.BlockUpdate(tpk, 0, SPHINCS256Config.CRYPTO_PUBLICKEYBYTES);

            // input message
            mHash.BlockUpdate(m, 0, m.Length);

            mHash.DoFinal(m_h, 0);
        }

        sigp = 0;

        sigp += SPHINCS256Config.MESSAGE_HASH_SEED_BYTES;
        smlen -= SPHINCS256Config.MESSAGE_HASH_SEED_BYTES;


        for (i = 0; i < (SPHINCS256Config.TOTALTREE_HEIGHT + 7) / 8; i++)
        {
            leafidx ^= ((long)(sig[sigp + i] & 0xff) << (8 * i));
        }


        Horst.horst_verify(hs, root, sig, sigp + (SPHINCS256Config.TOTALTREE_HEIGHT + 7) / 8,
            tpk, m_h);

        sigp += (SPHINCS256Config.TOTALTREE_HEIGHT + 7) / 8;
        smlen -= (SPHINCS256Config.TOTALTREE_HEIGHT + 7) / 8;

        sigp += Horst.HORST_SIGBYTES;
        smlen -= Horst.HORST_SIGBYTES;

        Wots w = new Wots();

        for (i = 0; i < SPHINCS256Config.N_LEVELS; i++)
        {
            w.wots_verify(hs, wots_pk, sig, sigp, root, tpk);

            sigp += Wots.WOTS_SIGBYTES;
            smlen -= Wots.WOTS_SIGBYTES;

            Tree.l_tree(hs, pkhash, 0, wots_pk, 0, tpk, 0);
            validate_authpath(hs, root, pkhash, (uint)(leafidx & 0x1f), sig, sigp, tpk, SPHINCS256Config.SUBTREE_HEIGHT);
            leafidx >>= 5;

            sigp += SPHINCS256Config.SUBTREE_HEIGHT * SPHINCS256Config.HASH_BYTES;
            smlen -= SPHINCS256Config.SUBTREE_HEIGHT * SPHINCS256Config.HASH_BYTES;
        }

        bool verified = true;
        for (i = 0; i < SPHINCS256Config.HASH_BYTES; i++)
        {
            if (root[i] != tpk[i + Horst.N_MASKS * SPHINCS256Config.HASH_BYTES])
            {
                verified = false;
            }
        }

        return verified;
    }
}
}
