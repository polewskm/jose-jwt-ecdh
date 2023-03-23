using System.Security.Cryptography;
using System.Text;
using Jose;

Console.WriteLine($"Running on {Environment.OSVersion}");

const int cekSizeBits = 256;
const string algorithmType = "ECDH-ES";

var enc = Encoding.UTF8.GetBytes(algorithmType);
var apu = Array.Empty<byte>();
var apv = Array.Empty<byte>();

var algorithmId = Arrays.Concat(Arrays.IntToBytes(enc.Length), enc);
var partyUInfo = Arrays.Concat(Arrays.IntToBytes(apu.Length), apu);
var partyVInfo = Arrays.Concat(Arrays.IntToBytes(apv.Length), apv);
var suppPubInfo = Arrays.IntToBytes(cekSizeBits);

var privateParameters = new ECParameters
{
    Curve = ECCurve.NamedCurves.nistP256,
    Q = new ECPoint // public part
    {
        X = Convert.FromBase64String("3BDv2y0CqT9A28qOhJoSp9K6qNSEaGagF6TLuVtCR5g="),
        Y = Convert.FromBase64String("AkR4kvGNucKbDyHW7d5iD/C37aJML+4V+rxcyeXN0ts=")
    },
    // private part
    D = Convert.FromBase64String("Zw1DgcQ2LAex8SBaceej1yCB6IaSPFfBz05JccmImCo=")
};
#if WINDOWS
using var privateKey = new ECDiffieHellmanCng();
privateKey.ImportParameters(privateParameters);
#else
using var privateKey = ECDiffieHellman.Create(privateParameters);
#endif

var publicParameters = new ECParameters
{
    Curve = ECCurve.NamedCurves.nistP256,
    Q = new ECPoint // public part
    {
        X = Convert.FromBase64String("YZAG4YKtXl/sQW+kTERkV3CTjU4CqUeVAFcROMivNYQ="),
        Y = Convert.FromBase64String("u2iWhH749lKT6YMjkGC5eU26/wfM5PsZNSojgnQOD30=")
    }
    // omitting private part
    // D = Convert.FromBase64String("CLNiEczZu1yKLG7iOQv+74oFIoulQw4DRBIAk0RNOoQ=")
};
#if WINDOWS
using var publicKey = new ECDiffieHellmanCng();
publicKey.ImportParameters(publicParameters);
#else
using var publicKey = ECDiffieHellman.Create(publicParameters);
#endif

#if WINDOWS
var derivedKey1 = ConcatKDF.DeriveKey(
    publicKey.Key,
    privateKey.Key,
    cekSizeBits,
    algorithmId,
    partyVInfo,
    partyUInfo,
    suppPubInfo);
Console.WriteLine($"Derived Key #1 = {Convert.ToBase64String(derivedKey1)}");
#endif

// Concat KDF, as defined in Section 5.8.1 of [NIST.800-56A]
// reps = ceil( keydatalen / hashlen )
// K(i) = H(counter || Z || OtherInfo)
// DerivedKeyingMaterial = K(1) || K(2) || … || K(reps-1) || K_Last
// So knowing that:
// - jose-jwt supports a maximum keydatalen of 256
// - and hashlen=256
// then reps will always be 1
const int reps = 1;

var secretPrepend = Arrays.IntToBytes(reps);
var secretAppend = Arrays.Concat(
    algorithmId,
    partyUInfo,
    partyVInfo,
    suppPubInfo
);
var derivedKey2 = Arrays.LeftmostBits(privateKey.DeriveKeyFromHash(
    publicKey.PublicKey,
    HashAlgorithmName.SHA256,
    secretPrepend,
    secretAppend), cekSizeBits);
Console.WriteLine($"Derived Key #2 = {Convert.ToBase64String(derivedKey2)}");
