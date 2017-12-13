
using System.IO;
using Org.BouncyCastle.Asn1;
using System.Collections;

namespace Org.BouncyCastle.Cms
{
    public class Pkcs7ProcessableObject : ICmsTypedData
    {
        private Asn1Encodable content;
        private DerObjectIdentifier contentType;

        public DerObjectIdentifier ContentType
        {
            get
            {
                return contentType;
            }
        }

        public Pkcs7ProcessableObject(DerObjectIdentifier contentType, Asn1Encodable content)
        {
            this.contentType = contentType;
            this.content = content;
        }

        public void Write(Stream output)
        {
            if (content is Asn1Sequence)
            {
                Asn1Sequence s = Asn1Sequence.GetInstance(content);

                for (IEnumerator it = s.GetEnumerator(); it.MoveNext();)
                {
                    Asn1Encodable enc = (Asn1Encodable)it.Current;
                    byte[] data = enc.ToAsn1Object().GetEncoded(Asn1Encodable.Der);

                    output.Write(data, 0, data.Length);
                }
            }
            else
            {
                byte[] encoded = content.ToAsn1Object().GetEncoded(Asn1Encodable.Der);
                int index = 1;

                while ((encoded[index] & 0xff) > 127)
                {
                    index++;
                }

                index++;

                output.Write(encoded, index, encoded.Length - index);
            }
        }

        public object GetContent()
        {
            return content;
        }
    }
}