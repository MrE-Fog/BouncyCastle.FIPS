

namespace Org.BouncyCastle.Crypto.Internal.Pqc.Crypto.Sphincs
{
    internal class SPHINCS256Config
    {
        internal static readonly int SUBTREE_HEIGHT = 5;
        internal static readonly int TOTALTREE_HEIGHT = 60;
        internal static readonly int N_LEVELS = (TOTALTREE_HEIGHT / SUBTREE_HEIGHT);
        internal static readonly int SEED_BYTES = 32;

        internal static readonly int SK_RAND_SEED_BYTES = 32;
        internal static readonly int MESSAGE_HASH_SEED_BYTES = 32;

        internal static readonly int HASH_BYTES = 32; // Has to be log(HORST_T)*HORST_K/8
        internal static readonly int MSGHASH_BYTES = 64;

        internal static readonly int CRYPTO_PUBLICKEYBYTES = ((Horst.N_MASKS + 1) * HASH_BYTES);
        internal static readonly int CRYPTO_SECRETKEYBYTES = (SEED_BYTES + CRYPTO_PUBLICKEYBYTES - HASH_BYTES + SK_RAND_SEED_BYTES);
    }
}
