
using Org.BouncyCastle.Bcpg;

namespace Org.BouncyCastle.OpenPgp
{
    public interface IKeyFingerPrintCalculator
    {
        byte[] CalculateFingerprint(PublicKeyPacket publicPk);
    }
}
