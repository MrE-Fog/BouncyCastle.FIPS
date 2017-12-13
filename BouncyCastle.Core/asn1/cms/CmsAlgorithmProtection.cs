using Org.BouncyCastle.Asn1.X509;
using System;

namespace Org.BouncyCastle.Asn1.Cms
{

    /**
     * From RFC 6211
     * <pre>
     * CMSAlgorithmProtection ::= SEQUENCE {
     *    digestAlgorithm         DigestAlgorithmIdentifier,
     *    signatureAlgorithm  [1] SignatureAlgorithmIdentifier OPTIONAL,
     *    macAlgorithm        [2] MessageAuthenticationCodeAlgorithm
     *                                     OPTIONAL
     * }
     * (WITH COMPONENTS { signatureAlgorithm PRESENT,
     *                    macAlgorithm ABSENT } |
     *  WITH COMPONENTS { signatureAlgorithm ABSENT,
     *                    macAlgorithm PRESENT })
     * </pre>
     */
    public class CmsAlgorithmProtection : Asn1Encodable
    {
        public static readonly int Signature = 1;
        public static readonly int Mac = 2;

        private readonly AlgorithmIdentifier digestAlgorithm;
        private readonly AlgorithmIdentifier signatureAlgorithm;
        private readonly AlgorithmIdentifier macAlgorithm;

        public CmsAlgorithmProtection(AlgorithmIdentifier digestAlgorithm, int type, AlgorithmIdentifier algorithmIdentifier)
        {
            if (digestAlgorithm == null || algorithmIdentifier == null)
            {
                throw new ArgumentException("AlgorithmIdentifiers cannot be null");
            }

            this.digestAlgorithm = digestAlgorithm;

            if (type == 1)
            {
                this.signatureAlgorithm = algorithmIdentifier;
                this.macAlgorithm = null;
            }
            else if (type == 2)
            {
                this.signatureAlgorithm = null;
                this.macAlgorithm = algorithmIdentifier;
            }
            else
            {
                throw new ArgumentException("Unknown type: " + type);
            }
        }

        private CmsAlgorithmProtection(Asn1Sequence sequence)
        {
            if (sequence.Count != 2)
            {
                throw new ArgumentException("Sequence wrong size: One of signatureAlgorithm or macAlgorithm must be present");
            }

            this.digestAlgorithm = AlgorithmIdentifier.GetInstance(sequence[0]);

            Asn1TaggedObject tagged = Asn1TaggedObject.GetInstance(sequence[1]);
            if (tagged.TagNo == 1)
            {
                this.signatureAlgorithm = AlgorithmIdentifier.GetInstance(tagged, false);
                this.macAlgorithm = null;
            }
            else if (tagged.TagNo == 2)
            {
                this.signatureAlgorithm = null;

                this.macAlgorithm = AlgorithmIdentifier.GetInstance(tagged, false);
            }
            else
            {
                throw new ArgumentException("Unknown tag found: " + tagged.TagNo);
            }
        }

        public static CmsAlgorithmProtection GetInstance(
            Object obj)
        {
            if (obj is CmsAlgorithmProtection)
            {
                return (CmsAlgorithmProtection)obj;
            }
            else if (obj != null)
            {
                return new CmsAlgorithmProtection(Asn1Sequence.GetInstance(obj));
            }

            return null;
        }


        public AlgorithmIdentifier DigestAlgorithm
        {
            get
            {
                return digestAlgorithm;
            }
        }

        public AlgorithmIdentifier MacAlgorithm
        {
            get
            {
                return macAlgorithm;
            }
        }

        public AlgorithmIdentifier SignatureAlgorithm
        {
            get
            {
                return signatureAlgorithm;
            }
        }

        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector();

            v.Add(digestAlgorithm);
            if (signatureAlgorithm != null)
            {
                v.Add(new DerTaggedObject(false, 1, signatureAlgorithm));
            }
            if (macAlgorithm != null)
            {
                v.Add(new DerTaggedObject(false, 2, macAlgorithm));
            }

            return new DerSequence(v);
        }
    }
}
