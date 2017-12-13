using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Collections;
using System;
using System.Collections;

namespace Org.BouncyCastle.OpenSsl
{ 

internal class PemUtilities
{
        private static readonly IDictionary KEYSIZES = Platform.CreateHashtable();
    private static readonly ISet Pkcs5_SCHEME_1 = new HashSet();
    private static readonly ISet Pkcs5_SCHEME_2 = new HashSet();

    static PemUtilities()
    {
        Pkcs5_SCHEME_1.Add(PkcsObjectIdentifiers.PbeWithMD2AndDesCbc);
        Pkcs5_SCHEME_1.Add(PkcsObjectIdentifiers.PbeWithMD2AndRC2Cbc);
        Pkcs5_SCHEME_1.Add(PkcsObjectIdentifiers.PbeWithMD5AndDesCbc);
        Pkcs5_SCHEME_1.Add(PkcsObjectIdentifiers.PbeWithMD5AndRC2Cbc);
        Pkcs5_SCHEME_1.Add(PkcsObjectIdentifiers.PbeWithSha1AndDesCbc);
        Pkcs5_SCHEME_1.Add(PkcsObjectIdentifiers.PbeWithSha1AndRC2Cbc);

        Pkcs5_SCHEME_2.Add(PkcsObjectIdentifiers.IdPbeS2);
        Pkcs5_SCHEME_2.Add(PkcsObjectIdentifiers.DesEde3Cbc);
        Pkcs5_SCHEME_2.Add(NistObjectIdentifiers.IdAes128Cbc);
        Pkcs5_SCHEME_2.Add(NistObjectIdentifiers.IdAes192Cbc);
        Pkcs5_SCHEME_2.Add(NistObjectIdentifiers.IdAes256Cbc);

        KEYSIZES.Add(PkcsObjectIdentifiers.DesEde3Cbc.Id, 192);
        KEYSIZES.Add(NistObjectIdentifiers.IdAes128Cbc.Id, 128);
        KEYSIZES.Add(NistObjectIdentifiers.IdAes192Cbc.Id, 192);
        KEYSIZES.Add(NistObjectIdentifiers.IdAes256Cbc.Id, 256);
    }

    static int GetKeySize(string algorithm)
    {
        if (!KEYSIZES.Contains(algorithm))
        {
            throw new InvalidOperationException("no key size for algorithm: " + algorithm);
        }
        
        return (int)KEYSIZES[algorithm];
    }

    static bool IsPkcs5Scheme1(DerObjectIdentifier algOid)
    {
        return Pkcs5_SCHEME_1.Contains(algOid);
    }

    public static bool IsPkcs5Scheme2(DerObjectIdentifier algOid)
    {
        return Pkcs5_SCHEME_2.Contains(algOid);
    }

    public static bool IsPkcs12(DerObjectIdentifier algOid)
    {
        return algOid.Id.StartsWith(PkcsObjectIdentifiers.Pkcs12PbeIds);
    }
}
}
