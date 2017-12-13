using Org.BouncyCastle.Asn1;

namespace Org.BouncyCastle.Cms
{
    internal interface IAuthAttributesProvider
    {
        Asn1Set AuthAttributes { get;  }
    }
}