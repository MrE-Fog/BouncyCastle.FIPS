using Org.BouncyCastle.Asn1;
using System;
using System.Collections;
using System.Collections.Generic;

namespace Org.BouncyCastle.OpenSsl
{

    public class CertificateTrustBlock
    {
        private Asn1Sequence uses;
        private Asn1Sequence prohibitions;
        private String alias;

        public CertificateTrustBlock(ISet<DerObjectIdentifier> uses) : this(null, uses, null)
        {
        }

        public CertificateTrustBlock(String alias, ISet<DerObjectIdentifier> uses) : this(alias, uses, null)
        {
        }

        public CertificateTrustBlock(String alias, ISet<DerObjectIdentifier> uses, ISet<DerObjectIdentifier> prohibitions)
        {
            this.alias = alias;
            this.uses = ToSequence(uses);
            this.prohibitions = ToSequence(prohibitions);
        }

        internal CertificateTrustBlock(byte[] encoded)
        {
            Asn1Sequence seq = Asn1Sequence.GetInstance(encoded);

            for (IEnumerator en = seq.GetEnumerator(); en.MoveNext();)
            {
                Asn1Encodable obj = (Asn1Encodable)en.Current;

                if (obj is Asn1Sequence)
                {
                    this.uses = Asn1Sequence.GetInstance(obj);
                }
                else if (obj is Asn1TaggedObject)
                {
                    this.prohibitions = Asn1Sequence.GetInstance((Asn1TaggedObject)obj, false);
                }
                else if (obj is DerUtf8String)
                {
                    this.alias = DerUtf8String.GetInstance(obj).GetString();
                }
            }
        }

        public String Alias
        {
            get
            {
                return alias;
            }
        }

        public ISet<DerObjectIdentifier> GetUses()
        {
            return toSet(uses);
        }

        public ISet<DerObjectIdentifier> GetProhibitions()
        {
            return toSet(prohibitions);
        }

        private ISet<DerObjectIdentifier> toSet(Asn1Sequence seq)
        {
            if (seq != null)
            {
                ISet<DerObjectIdentifier> oids = new HashSet<DerObjectIdentifier>();

                for (IEnumerator en = seq.GetEnumerator(); en.MoveNext();)
                {
                    oids.Add(DerObjectIdentifier.GetInstance(en.Current));
                }

                return oids;
            }

            return new HashSet<DerObjectIdentifier>();
        }

        private Asn1Sequence ToSequence(ISet<DerObjectIdentifier> oids)
        {
            if (oids == null || oids.Count == 0)
            {
                return null;
            }

            Asn1EncodableVector v = new Asn1EncodableVector();

            for (IEnumerator it = oids.GetEnumerator(); it.MoveNext();)
            {
                v.Add((Asn1Encodable)it.Current);
            }

            return new DerSequence(v);
        }

        internal Asn1Sequence ToAsn1Sequence()
        {
            Asn1EncodableVector v = new Asn1EncodableVector();

            if (uses != null)
            {
                v.Add(uses);
            }
            if (prohibitions != null)
            {
                v.Add(new DerTaggedObject(false, 0, prohibitions));
            }
            if (alias != null)
            {
                v.Add(new DerUtf8String(alias));
            }

            return new DerSequence(v);
        }
    }
}
