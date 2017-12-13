using Org.BouncyCastle.Security;
using System;

namespace Org.BouncyCastle.Crypto.Internal.Pqc.Crypto.Sphincs
{
    internal class Sphincs256KeyPairGenerator : IAsymmetricCipherKeyPairGenerator
    {
        private SecureRandom random;
        private IDigest treeDigest;

        public void Init(KeyGenerationParameters param)
        {
            random = param.Random;
            treeDigest = ((Sphincs256KeyGenerationParameters)param).TreeDigest;
        }

        public AsymmetricCipherKeyPair GenerateKeyPair()
        {
            Tree.leafaddr a = new Tree.leafaddr();

            byte[] sk = new byte[SPHINCS256Config.CRYPTO_SECRETKEYBYTES];

            random.NextBytes(sk);

            byte[] pk = new byte[SPHINCS256Config.CRYPTO_PUBLICKEYBYTES];

            Array.Copy(sk, SPHINCS256Config.SEED_BYTES, pk, 0, Horst.N_MASKS * SPHINCS256Config.HASH_BYTES);

            // Initialization of top-subtree address
            a.level = SPHINCS256Config.N_LEVELS - 1;
            a.subtree = 0;
            a.subleaf = 0;

            HashFunctions hs = new HashFunctions(treeDigest);

            // Format pk: [|N_MASKS*params.HASH_BYTES| Bitmasks || root]
            // Construct top subtree
            Tree.treehash(hs, pk, (Horst.N_MASKS * SPHINCS256Config.HASH_BYTES), SPHINCS256Config.SUBTREE_HEIGHT, sk, a, pk, 0);

            return new AsymmetricCipherKeyPair(new SphincsPublicKeyParameters(pk), new SphincsPrivateKeyParameters(sk));
        }
    }
}
