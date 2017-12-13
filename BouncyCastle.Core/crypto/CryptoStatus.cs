using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Text;

using Org.BouncyCastle.Crypto.Fips;
using Org.BouncyCastle.Crypto.Internal;
using Org.BouncyCastle.Crypto.Internal.Digests;
using Org.BouncyCastle.Crypto.Internal.Macs;
using Org.BouncyCastle.Crypto.Internal.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Crypto
{
    public static class CryptoStatus
	{
        private static readonly byte[] MacKey = Encoding.ASCII.GetBytes("Legion of the Bouncy Castle Inc.");

        /// <summary>
        /// The initial value is a placeholder, to be replaced by an actual MAC calculated by the core-mac
        /// tool (as a post-build event).
        /// </summary>
        /// <remarks>The first few bytes are "_BCFIPS_MAC_", the rest was randomly generated.</remarks>
        private static readonly byte[] MacValue =
        {
            0x5F, 0x42, 0x43, 0x46, 0x49, 0x50, 0x53, 0x5F, 0x4D, 0x41, 0x43, 0x5F, 0xA3, 0xA0, 0x26, 0x51,
            0x64, 0xDA, 0x27, 0xB7, 0xE1, 0xC8, 0x84, 0xE8, 0xBF, 0x01, 0xFD, 0x44, 0xEF, 0xA9, 0x5E, 0x61,
            0x9D, 0xA0, 0x19, 0x72, 0x23, 0xDD, 0xA4, 0x50, 0x93, 0x37, 0xDC, 0xE6, 0x41, 0x14, 0xEC, 0xE5,
            0x5E, 0x59, 0x98, 0x8F, 0xE7, 0x9C, 0xEE, 0x7E, 0xFA, 0xEB, 0x72, 0x55, 0x88, 0x4B, 0xFC, 0x63
        };

        public static readonly string READY = "READY";

        private static readonly object LoaderLock = new object();

        private static readonly string[] Types =
        {
            Platform.GetTypeName(typeof(FipsAes)),
            Platform.GetTypeName(typeof(FipsTripleDes)),
            //Platform.GetTypeName(typeof(FipsDH)),
            Platform.GetTypeName(typeof(FipsDrbg)),
            Platform.GetTypeName(typeof(FipsDsa)),
            Platform.GetTypeName(typeof(FipsEC)),
            Platform.GetTypeName(typeof(FipsKdf)),
            Platform.GetTypeName(typeof(FipsPbkd)),
            Platform.GetTypeName(typeof(FipsRsa)),
            Platform.GetTypeName(typeof(FipsShs)),
        };

        private static volatile Loader loader;
        private static volatile Exception statusException;

        /// <summary>Check to see if the FIPS module is ready for operation.</summary>
        /// <returns><c>true</c> if the module is ready for operation with all self-tests complete.</returns>
        public static bool IsReady()
		{
            // FSM_STATE:2.0, "POWER ON INITIALIZATION", "Initialization of the module after power on or RST"
            lock (LoaderLock)
            {
                if (loader == null && statusException == null)
                {
                    try
                    {
                        loader = new Loader();
                    }
                    catch (Exception e)
                    {
                        statusException = e;

                        MoveToErrorStatus(new CryptoOperationError("Module startup failed: " + e.Message, e));
                    }

                    // FSM_STATE:3.1, "FIRMWARE INTEGRITY - HMAC-SHA512", "The module is performing the Firmware Integrity Check: HMAC-SHA512"
                    // FSM_TRANS:3.3
                    ChecksumValidate();
                    // FSM_TRANS:3.4
                }
                else if (statusException != null)
                {
                    throw new CryptoOperationError("Module in error status: " + statusException.Message, statusException);
                }
            }

            // FSM_TRANS:3.1
            return true;
        }

        /// <summary>
        /// Return true if the module is in error status, false otherwise.
        /// </summary>
        /// <returns><c>true</c>, if an error has been detected, <c>false</c> otherwise.</returns>
        public static bool IsErrorStatus()
		{
			return statusException != null;
		}

		/// <summary>
		/// Return a message indicating the current status.
		/// </summary>
		/// <returns>READY if all is well, an exception message otherwise.</returns>
		public static string GetStatusMessage()
		{
			try
			{
				CryptoStatus.IsReady();
			}
			catch (CryptoOperationError)
			{
				// ignore as loader exception will now be set.
			}

			if (statusException != null)
			{
				return statusException.Message;
			}

			return READY;
		}

		internal static void MoveToErrorStatus(string error)
		{
			MoveToErrorStatus(new CryptoOperationError(error));
		}

		internal static void MoveToErrorStatus(CryptoOperationError error)
		{
			// FSM_STATE:8.0
			// FSM_TRANS:3.2
			statusException =  error;
			throw (CryptoOperationError)statusException;
		}

        private static void ChecksumValidate()
        {
            try
            {
                byte[] hMac = CalculateAssemblyHMac();

                if (!Arrays.AreEqual(hMac, MacValue))
                {
                    MoveToErrorStatus(new CryptoOperationError("Module checksum failed: expected [" + Hex.ToHexString(MacValue) + "] got [" + Hex.ToHexString(hMac) + "]"));
                }
            }
            catch (Exception e)
            {
                statusException = e;

                MoveToErrorStatus(new CryptoOperationError("Module checksum failed: " + e.Message, e));
            }
        }

        private static void LoadType(string typeName)
        {
            try
            {
                System.Runtime.CompilerServices.RuntimeHelpers.RunClassConstructor(Type.GetType(typeName).TypeHandle);
            }
            catch (TargetInvocationException e)
            {
                statusException = e.InnerException ?? e;
                throw e;
            }
            catch (Exception e)
            {
                statusException = e;
                throw new InvalidOperationException("Unable to initialize module: " + e.Message, e);
            }
        }

        /// <summary>
        /// Return the HMAC used to verify that the code contained in the assembly is the same.
        /// </summary>
        /// <returns>the internally calculated HMAC for the assembly.</returns>
        public static byte[] GetModuleHMac()
        {
            try
            {
                return CalculateAssemblyHMac();
            }
            catch (Exception)
            {
                return new byte[MacValue.Length];
            }
        }

        private static byte[] CalculateAssemblyHMac()
        {
            Assembly assembly = Assembly.GetExecutingAssembly();
            Check(assembly.GetModules().Length == 1);

            string path = assembly.ManifestModule.FullyQualifiedName;
            byte[] data = File.ReadAllBytes(path);

            IMac mac = new HMac(new Sha512Digest());
            mac.Init(new KeyParameter(MacKey));

            int macPos;
            var ranges = AnalyzePEData(data, out macPos);
            Check(macPos >= 0);

            int pos = 0;
            foreach (var range in ranges)
            {
                if (pos < range.Start)
                {
                    mac.BlockUpdate(data, pos, range.Start - pos);
                }
                if (range.Data != null)
                {
                    mac.BlockUpdate(range.Data, 0, range.Data.Length);
                }
                int rangeEnd = range.Start + range.Length;
                if (pos < rangeEnd)
                {
                    pos = rangeEnd;
                }
            }

            if (pos < data.Length)
            {
                mac.BlockUpdate(data, pos, data.Length - pos);
            }

            return Macs.DoFinal(mac);
        }

        private static List<Range> AnalyzePEData(byte[] data, out int macPos)
        {
            var ranges = new List<Range>();

            int dosOff = 0;
            int magic = ReadUint16(data, dosOff);
            Check(magic == 0x5A4D);
            int peOff = ReadUint31(data, dosOff + 0x3C);
            Check(64 <= peOff);
            Check((peOff & 7) == 0);

            Check(ReadStringToNull(data, peOff, 4) == "PE");
            int numberOfSections = ReadUint16(data, peOff + 6);
            int optSize = ReadUint16(data, peOff + 20);

            int optOff = peOff + 24;
            int optMagic = ReadUint16(data, optOff);
            Check(optMagic == 0x010B || optMagic == 0x20B);

            int fileAlign = ReadUint31(data, optOff + 36);
            Check(512 <= fileAlign && fileAlign <= 65536);
            Check((fileAlign & (fileAlign - 1)) == 0);
            int peChecksumOff = optOff + 64;

            ranges.Add(Range.Skip(peChecksumOff, 4));

            int ddOff = optOff + (optMagic == 0x010B ? 96 : 112);
            int numDDEntries = ReadUint31(data, ddOff - 4);

            if (numDDEntries > 4)
            {
                int certTableEntryOff = ddOff + (4 * 8);

                ranges.Add(Range.Skip(certTableEntryOff, 8));

                int certTableSize = ReadUint31(data, certTableEntryOff + 4);
                if (certTableSize > 0)
                {
                    // NOTE: For 'Certificate Table', the first entry is a file pointer, not an RVA
                    int certTableOff = ReadUint31(data, certTableEntryOff);
                    ranges.Add(Range.Skip(certTableOff, certTableSize));
                }
            }

            if (numDDEntries > 14)
            {
                int cliHeaderEntryOff = ddOff + (14 * 8);

                int cliHeaderRVA = ReadUint31(data, cliHeaderEntryOff);
                int cliHeaderSize = ReadUint31(data, cliHeaderEntryOff + 4);
                Check(cliHeaderSize == 72);


                int sectionHeadersOff = optOff + optSize;

                int cliHeaderOff = LocateRVA(data, sectionHeadersOff, numberOfSections, cliHeaderRVA);
                int flagsOff = cliHeaderOff + 16;

                // The first byte (of 4) contains the COMIMAGE_FLAGS_STRONGNAMESIGNED bit (0x08); force it off
                byte newFlagByte = (byte)(data[flagsOff] & 0xF7);
                ranges.Add(Range.Replace(flagsOff, 1, new byte[] { newFlagByte }));

                // An IMAGE_DATA_DIRECTORY gives the location of the StrongNameSignature
                int snSigDataOff = flagsOff + 16;

                ranges.Add(Range.Skip(snSigDataOff, 8));

                int snSigSize = ReadUint31(data, snSigDataOff + 4);
                if (snSigSize > 0)
                {
                    int snSigRVA = ReadUint31(data, snSigDataOff);
                    int snSigOff = LocateRVA(data, sectionHeadersOff, numberOfSections, snSigRVA);
                    ranges.Add(Range.Skip(snSigOff, snSigSize));
                }
            }

            macPos = IndexOfMac(data, MacValue);
            if (macPos >= 0)
            {
                ranges.Add(Range.Skip(macPos, MacValue.Length));
            }

            ranges.Sort((x, y) => x.Start < y.Start ? -1 : x.Start > y.Start ? 1 : 0);
            return ranges;
        }

        private static void Check(bool condition)
        {
            if (!condition)
                throw new InvalidDataException();
        }

        private static int IndexOfMac(byte[] data, byte[] mac)
        {
            int result = -1;
            byte firstByte = mac[0];

            int lastPos = data.Length - mac.Length;
            for (int i = 0; i <= lastPos; ++i)
            {
                if (data[i] == firstByte)
                {
                    int j = 1;
                    for (; j < mac.Length; ++j)
                    {
                        if (data[i + j] != mac[j])
                            break;
                    }
                    if (j == mac.Length)
                    {
                        Check(result == -1);
                        result = i;
                    }
                }
            }

            return result;
        }

        private static int LocateRVA(byte[] data, int sectionHeadersOff, int numberOfSections, int rva)
        {
            for (int i = 0; i < numberOfSections; ++i)
            {
                int off = sectionHeadersOff + i * 40;
                //string name = ReadStringToNull(data, off, 8);
                int virtualAddress = ReadUint31(data, off + 12);
                if (virtualAddress <= rva)
                {
                    int virtualSize = ReadUint31(data, off + 8);
                    if ((rva - virtualAddress) < virtualSize)
                    {
                        int rawOff = ReadUint31(data, off + 20);
                        return rawOff + (rva - virtualAddress);
                    }
                }
            }

            throw new InvalidDataException();
        }

        private static string ReadStringToNull(byte[] data, int off, int len)
        {
            int i = 0;
            for (; i < len; ++i)
            {
                if (data[off + i] == 0)
                    break;
            }

            return Encoding.ASCII.GetString(data, off, i);
        }

        private static int ReadUint16(byte[] data, int off)
        {
            return Pack.LE_To_UInt16(data, off);
        }

        private static int ReadUint31(byte[] data, int off)
        {
            uint n = Pack.LE_To_UInt32(data, off);
            Check(n >> 31 == 0);
            return (int)n;
        }

        private class Range
        {
            public static Range Replace(int start, int length, byte[] data)
            {
                return new Range { Start = start, Length = length, Data = data };
            }

            public static Range Skip(int start, int length)
            {
                return Replace(start, length, null);
            }

            public int Start { get; private set; }
            public int Length { get; private set; }
            public byte[] Data { get; private set; }
        }

        internal class Loader
        {
            internal Loader()
            {
                // FSM_STATE:3.0, "POWER ON SELF-TEST", ""
                foreach (string type in Types)
                {
                    if (!IsErrorStatus())
                    {
                        LoadType(type);
                    }
                }
            }
        }
    }
}
