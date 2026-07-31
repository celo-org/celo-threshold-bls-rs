const threshold = require('../src/blind_threshold_bls');

// Static test inputs - DO NOT CHANGE
const STATIC_SEED = Buffer.from('0000000000000000000000000000000000000000000000000000000000000001', 'hex');
const STATIC_BLINDING_SEED = Buffer.from('0000000000000000000000000000000000000000000000000000000000000002', 'hex');
const STATIC_THRESHOLD_SEED = Buffer.from('0000000000000000000000000000000000000000000000000000000000000003', 'hex');
const STATIC_MESSAGE = Buffer.from('test message', 'utf8');

describe('Blind Threshold BLS Static Tests', () => {
  describe('Single key operations', () => {
    const keypair = threshold.keygen(STATIC_SEED);
    
    it('should generate deterministic keypair', () => {
      const expectedPrivateKey = 'c18399a683fec5c4c6b8fbc4de65ed99a08a9a0390298e0490fbf6eb2ca20610';
      const expectedPublicKey = '1a1e6a65e1483d55ffdde0951f857f379e28856ee04d5e90a38c583ba9fd98ac889378e7ed3e3b7487ff9bf9f4a96c0105c4c98c0f13b44fedaff4e8326c1be5885ee10187fa85c334373c5b5d09d9e926ba516fce640fa6fc032d6cc297a381';
      
      expect(Buffer.from(keypair.privateKey).toString('hex')).toBe(expectedPrivateKey);
      expect(Buffer.from(keypair.publicKey).toString('hex')).toBe(expectedPublicKey);
    });
    
    it('should sign and verify message', () => {
      const signature = threshold.sign(keypair.privateKey, STATIC_MESSAGE);
      
      // Verify the signature works
      threshold.verify(keypair.publicKey, STATIC_MESSAGE, signature);
      
      // Check against expected output
      const expectedSignature = 'ccf039d94f8a4c3e1855ccb3a1334aad98df360922267fe0d66acf619cefd7197c5b152faed7888fedef21f07e6b1701';
      expect(Buffer.from(signature).toString('hex')).toBe(expectedSignature);
    });
    
    it('should blind, sign, unblind and verify', () => {
      // Blind the message
      const blinded = threshold.blind(STATIC_MESSAGE, STATIC_BLINDING_SEED);
      const blindedMessage = blinded.message;
      const blindingFactor = blinded.blindingFactor;
      
      // Sign the blinded message
      const blindSignature = threshold.signBlindedMessage(keypair.privateKey, blindedMessage);
      
      // Unblind the signature
      const unblindedSignature = threshold.unblind(blindSignature, blindingFactor);
      
      // Verify the unblinded signature
      threshold.verify(keypair.publicKey, STATIC_MESSAGE, unblindedSignature);
      
      // Check against expected outputs
      const expectedBlindedMessage = 'be8f7f278c94df4beca29ba8745d781bf2b2ef75adad8b4224460d2b4aa13c4ddbcd2d021549cb382fd3b4f0be856e00';
      const expectedBlindingFactor = '36e00463ede241c77aa32fd678943ebc4f228ae0c5cae7f64586e3a955ce5310';
      const expectedBlindSignature = 'a8e5268eac8381ae40c722ab9b1528c3fc58dcab173bae7bbc7a696347920062cf4dee7c841fbdaf21769bea6125ce00';
      const expectedUnblindedSignature = 'ccf039d94f8a4c3e1855ccb3a1334aad98df360922267fe0d66acf619cefd7197c5b152faed7888fedef21f07e6b1701';
      
      expect(Buffer.from(blindedMessage).toString('hex')).toBe(expectedBlindedMessage);
      expect(Buffer.from(blindingFactor).toString('hex')).toBe(expectedBlindingFactor);
      expect(Buffer.from(blindSignature).toString('hex')).toBe(expectedBlindSignature);
      expect(Buffer.from(unblindedSignature).toString('hex')).toBe(expectedUnblindedSignature);
    });
  });
  
  describe('Threshold operations', () => {
    // Create a 3-of-5 threshold scheme
    const t = 3;
    const n = 5;
    const keys = threshold.thresholdKeygen(n, t, STATIC_THRESHOLD_SEED);
    
    it('should generate deterministic threshold keys', () => {
      const expectedPolynomial = '03000000000000005e82a2984466e3d073dcff0bab2851f1b7dd3f36c151130a6509ea4f1275f7d32d037b79989d4dc01eacf33cc67c67003995fe5d32452d935f825328a8b3b9b63d0869823b809383917e046c54eec3dbae96ecc7dcf6fecbfae6f4f6cb352b0166b8a781519daf4944679740ebf965d1469259a1c61ab25369e1e33287f890d95bdcc47f522ce585c6dce9786098ca001fdcb9896ca59265e1331a3c97f2e14ab7fd87a2fdb33bcd950239df096c34876daafec59eb8fe11eeae497e15cf9e81db50479ab466b763b73427370609bf23ab134bd3e33f3c3b1484948809d5123794f91cbf17892363157364b000696601e269315e36db70ca51d72efbc2193c476b6fb6b4e4e54abb6d56052bc39f9d2b6c6414e7b9a063af1fc89289d1036d80';
      const expectedThresholdPublicKey = "5e82a2984466e3d073dcff0bab2851f1b7dd3f36c151130a6509ea4f1275f7d32d037b79989d4dc01eacf33cc67c67003995fe5d32452d935f825328a8b3b9b63d0869823b809383917e046c54eec3dbae96ecc7dcf6fecbfae6f4f6cb352b01"
      
      expect(Buffer.from(keys.polynomial).toString('hex')).toBe(expectedPolynomial);
      expect(Buffer.from(keys.thresholdPublicKey).toString('hex')).toBe(expectedThresholdPublicKey);
      expect(keys.numShares()).toBe(n);
      expect(keys.t).toBe(t);
      expect(keys.n).toBe(n);
    });
    
    it('should generate deterministic shares', () => {
      // Check each share against expected values
      const expectedShares = [
        '00000000e8b804c0c6407b5d472877b6a74091c83b5c524cafa5c6524d2482597390c208',
        '01000000dc00bc1b36c9fbfc504cce1558282d23ab444b0a7f94db934c93e99e726b860b',
        '02000000700b48a3abbfb1749ba1c97fc8cd56048a94c9adee377041c65ad08ac2921f06',
        '03000000a5d8a85627a4aece272869c4f7a7b8c5d9fb04931cdd38bc102063b7c16b390b',
        '040000007a68de35a9f6e000f5dfac13e73fa80d99cac55dea3681a3d53d758a11912808'
      ];
      
      for (let i = 0; i < n; i++) {
        const share = keys.getShare(i);
        expect(Buffer.from(share).toString('hex')).toBe(expectedShares[i]);
      }
    });
    
    it('should create valid partial signatures that can be combined', () => {
      // Blind the message
      const blinded = threshold.blind(STATIC_MESSAGE, STATIC_BLINDING_SEED);
      const blindedMessage = blinded.message;
      
      // Generate partial signatures
      const partialSigs = [];
      const expectedPartialSigs = [
        '300000000000000007b0a0d3b48e540c4dfbe5252f634401adf237103b24e932bae6c9716a88c8cc1a094d253f0aa5ee46915b61fd617f0100000000',
        '30000000000000005dced024cfdd67a78fc11ff874512919d7922d94cbf784eb77b6a20568d65e18d5c1288bf9a89a34255ce9e6773a6f0101000000',
        '30000000000000006a21dca24177420f62004d08ef1f0547a441098a21f636835741794a30e1c158e7554215bff19ff612c09e9a9155f38002000000'
      ];
      
      for (let i = 0; i < t; i++) {
        const share = keys.getShare(i);
        const partialSig = threshold.partialSignBlindedMessage(share, blindedMessage);
        
        // Verify the partial signature
        threshold.partialVerifyBlindSignature(keys.polynomial, blindedMessage, partialSig);
        
        partialSigs.push(partialSig);
        expect(Buffer.from(partialSig).toString('hex')).toBe(expectedPartialSigs[i]);
      }
      
      // Combine the signatures
      const combinedSig = threshold.combine(t, flattenSigsArray(partialSigs));
      
      // Unblind the signature
      const unblindedSig = threshold.unblind(combinedSig, blinded.blindingFactor);
      
      // Verify the combined signature
      threshold.verify(keys.thresholdPublicKey, STATIC_MESSAGE, unblindedSig);
      
      // Check against expected outputs
      const expectedCombinedSig = "57b1542abd5c55fa2623f14948d434735ebb286dd00fe440cc48b39b4ec974f4146c03be56b7da90ab742fe83fa7b980";
      const expectedUnblindedSig = "2078af1b0b286de06d0ae63c152c04932cdc08a4a4b5ec3089149c173e11760a0f4c11ea54e92370661ea4524c95b100";
      
      expect(Buffer.from(combinedSig).toString('hex')).toBe(expectedCombinedSig);
      expect(Buffer.from(unblindedSig).toString('hex')).toBe(expectedUnblindedSig);
    });
    
    it('should handle non-blinded threshold signatures', () => {
      // Generate partial signatures
      const partialSigs = [];
      const expectedPartialSigs = [
        '30000000000000008534e56484b7d886e829580953781da776744bc63287914b0be6d43d87fc6cce210a83bafad5dc48e0906c749726f90000000000',
        '3000000000000000746b09b75cf9b5cba3d2cfe17705ad9fe8381b0454feff30502344a7727a9cb83d058f806a1d7c7282cceeb1c048b48001000000',
        '3000000000000000233044cfe58b6a0dc0e1d5c08c37f66902ffec1c0fb6e46df38e19948bc8308170570f9a3a4687f441cfa11756780a8102000000'
      ];
      
      for (let i = 0; i < t; i++) {
        const share = keys.getShare(i);
        const partialSig = threshold.partialSign(share, STATIC_MESSAGE);
        
        // Verify the partial signature
        threshold.partialVerify(keys.polynomial, STATIC_MESSAGE, partialSig);
        
        partialSigs.push(partialSig);
        expect(Buffer.from(partialSig).toString('hex')).toBe(expectedPartialSigs[i]);
      }
      
      // Combine the signatures
      const combinedSig = threshold.combine(t, flattenSigsArray(partialSigs));
      
      // Verify the combined signature
      threshold.verify(keys.thresholdPublicKey, STATIC_MESSAGE, combinedSig);
      
      // Check against expected output
      const expectedCombinedSig = '2078af1b0b286de06d0ae63c152c04932cdc08a4a4b5ec3089149c173e11760a0f4c11ea54e92370661ea4524c95b100'
      expect(Buffer.from(combinedSig).toString('hex')).toBe(expectedCombinedSig);
    });
  });
});

/**
 * Helper function to flatten an array of signatures
 */
function flattenSigsArray(sigs) {
  return Uint8Array.from(sigs.reduce((a, b) => {
    return Array.from(a).concat(Array.from(b));
  }, []));
} 