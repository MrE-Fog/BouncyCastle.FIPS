
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Internal.Pqc.Crypto.Sphincs
{
    internal class HashFunctions
{
    private static readonly byte[] hashc = Strings.ToByteArray("expand 32-byte to 64-byte state!");

    private readonly IDigest dig256;
    private readonly IDigest dig512;
    private readonly Permute perm = new Permute();

    // for key pair generation where message hash not required
    internal HashFunctions(IDigest dig256): this(dig256, null)
    {
  
    }

    internal HashFunctions(IDigest dig256, IDigest dig512)
    {
        this.dig256 = dig256;
        this.dig512 = dig512;
    }

    internal int varlen_hash(byte[] output, int outOff, byte[] input, int inLen)
    {
        dig256.BlockUpdate(input, 0, inLen);

        dig256.DoFinal(output, outOff);

        return 0;
    }

    internal IDigest getMessageHash()
    {
        return dig512;
    }

    internal int hash_2n_n(byte[] output, int outOff, byte[] input, int inOff)
    {
        byte[] x = new byte[64];
        int i;
        for (i = 0; i < 32; i++)
        {
            x[i] = input[inOff + i];
            x[i + 32] = hashc[i];
        }
        perm.chacha_permute(x, x);
        for (i = 0; i < 32; i++)
        {
            x[i] = (byte)(x[i] ^ input[inOff + i + 32]);
        }
        perm.chacha_permute(x, x);
        for (i = 0; i < 32; i++)
        {
            output[outOff + i] = x[i];
        }

        return 0;
    }

    internal int hash_2n_n_mask(byte[] output, int outOff, byte[] input, int inOff, byte[] mask, int maskOff)
    {
        byte[] buf = new byte[2 * SPHINCS256Config.HASH_BYTES];
        int i;
        for (i = 0; i < 2 * SPHINCS256Config.HASH_BYTES; i++)
        {
            buf[i] = (byte)(input[inOff + i] ^ mask[maskOff + i]);
        }

        int rv = hash_2n_n(output, outOff, buf, 0);

        return rv;
    }

    internal int hash_n_n(byte[] output, int outOff, byte[] input, int inOff)
    {

        byte[] x = new byte[64];
        int i;

        for (i = 0; i < 32; i++)
        {
            x[i] = input[inOff + i];
            x[i + 32] = hashc[i];
        }
        perm.chacha_permute(x, x);
        for (i = 0; i < 32; i++)
        {
            output[outOff + i] = x[i];
        }

        return 0;
    }

    internal int hash_n_n_mask(byte[] output, int outOff, byte[] input, int inOff,  byte[] mask, int maskOff)
    {
        byte[] buf = new byte[SPHINCS256Config.HASH_BYTES];
        int i;
        for (i = 0; i < SPHINCS256Config.HASH_BYTES; i++)
        {
            buf[i] = (byte)(input[inOff + i] ^ mask[maskOff + i]);
        }
        return hash_n_n(output, outOff, buf, 0);
    }
}
}

