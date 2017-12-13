
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Ans1.BC
{
    public class Sphincs256KeyParams : Asn1Encodable
    {
        private readonly DerInteger version;
        private readonly AlgorithmIdentifier treeDigest;

        public Sphincs256KeyParams(AlgorithmIdentifier treeDigest)
        {
            this.version = new DerInteger(0);
            this.treeDigest = treeDigest;
        }

        private Sphincs256KeyParams(Asn1Sequence sequence)
        {
            this.version = DerInteger.GetInstance(sequence[0]);
            this.treeDigest = AlgorithmIdentifier.GetInstance(sequence[1]);
        }

        public static Sphincs256KeyParams GetInstance(object o)
        {
            if (o is Sphincs256KeyParams)
            {
                return (Sphincs256KeyParams)o;
            }
            else if (o != null)
            {
                return new Sphincs256KeyParams(Asn1Sequence.GetInstance(o));
            }

            return null;
        }

        public AlgorithmIdentifier TreeDigest
        {
            get
            {
                return treeDigest;
            }
        }

        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector();

            v.Add(version);
            v.Add(treeDigest);

            return new DerSequence(v);
        }
    }
}
